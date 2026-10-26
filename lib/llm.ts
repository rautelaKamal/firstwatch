/**
 * A small client for any OpenAI-compatible chat endpoint, built around a
 * token budget rather than around convenience.
 *
 * Free tiers are measured per minute, and the binding limit is usually tokens
 * per minute, not requests. A single request bigger than the minute's budget
 * is rejected outright. So every request is estimated before it is sent, the
 * estimate includes the output tokens it reserves, and the caller waits until
 * the last 60 seconds of spend leaves room for it.
 *
 * Plain fetch, no SDK: the Groq SDK appends its own path to the base URL,
 * which breaks LLM_BASE_URL for every other provider.
 */

export type ToolCall = { id: string; type: "function"; function: { name: string; arguments: string } };
export type ChatMessage =
  | { role: "system" | "user"; content: string }
  | { role: "assistant"; content: string; tool_calls?: ToolCall[] }
  | { role: "tool"; tool_call_id: string; content: string };
export type ToolSchema = {
  type: "function";
  function: { name: string; description: string; parameters: Record<string, unknown> };
};

export type LlmConfig = {
  baseUrl: string;
  apiKey: string;
  model: string;
  /** Tokens per minute the provider allows. */
  tpm: number;
  /** Requests per minute the provider allows. */
  rpm: number;
  /** Largest single request, input plus reserved output, that we will send. */
  maxRequestTokens: number;
  /** gpt-oss and other reasoning models: spend as little as possible on hidden reasoning. */
  reasoningEffort: string | null;
};

export const DEFAULT_BASE_URL = "https://api.groq.com/openai/v1";
export const DEFAULT_MODEL = "openai/gpt-oss-120b";

export function llmConfig(overrides: Partial<LlmConfig> = {}): LlmConfig | null {
  const apiKey = overrides.apiKey ?? process.env.LLM_API_KEY ?? process.env.GROQ_API_KEY;
  if (!apiKey) return null;
  const model = overrides.model ?? process.env.LLM_MODEL ?? DEFAULT_MODEL;
  return {
    baseUrl: (overrides.baseUrl ?? process.env.LLM_BASE_URL ?? DEFAULT_BASE_URL).replace(/\/+$/, ""),
    apiKey,
    model,
    tpm: overrides.tpm ?? Number(process.env.LLM_TPM ?? 8000),
    rpm: overrides.rpm ?? Number(process.env.LLM_RPM ?? 30),
    maxRequestTokens: overrides.maxRequestTokens ?? Number(process.env.LLM_MAX_REQUEST_TOKENS ?? 7000),
    reasoningEffort:
      overrides.reasoningEffort !== undefined
        ? overrides.reasoningEffort
        : (process.env.LLM_REASONING_EFFORT ?? (/gpt-oss/i.test(model) ? "low" : null)),
  };
}

/* ------------------------------------------------------------------ *
 * Estimating
 * ------------------------------------------------------------------ */

// Deliberately pessimistic. The first live run measured 4.2 characters a token
// for agent requests and 5.0 for advisory text; 3.5 keeps a margin of at least
// 17%, and calibration raises the estimate if a provider ever reports more.
const CHARS_PER_TOKEN = 3.5;
let calibration = 1;

export const estimateTokens = (text: string) => Math.ceil((text.length / CHARS_PER_TOKEN) * calibration);

/** Input tokens for a request: messages, tool schemas, and per-message framing. */
export function estimateRequest(messages: ChatMessage[], tools?: ToolSchema[]): number {
  return (
    estimateTokens(JSON.stringify(messages)) +
    (tools?.length ? estimateTokens(JSON.stringify(tools)) : 0) +
    8 * messages.length
  );
}

/* ------------------------------------------------------------------ *
 * The per-minute window
 * ------------------------------------------------------------------ */

const WINDOW_MS = 60_000;
const spent: { at: number; tokens: number }[] = [];

export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function prune(now: number) {
  while (spent.length && now - spent[0].at >= WINDOW_MS) spent.shift();
}

/** How long to wait before a request of this size fits the window, and why. */
export function planWait(cfg: LlmConfig, tokens: number): { ms: number; reason: string } {
  const now = Date.now();
  prune(now);
  const used = spent.reduce((sum, s) => sum + s.tokens, 0);
  if (used + tokens <= cfg.tpm && spent.length < cfg.rpm) return { ms: 0, reason: "" };
  const ms = (spent.length ? WINDOW_MS - (now - spent[0].at) : 1_000) + 300;
  const reason =
    used + tokens > cfg.tpm
      ? `${used.toLocaleString()} of ${cfg.tpm.toLocaleString()} tokens used in the last minute, this request needs ~${tokens.toLocaleString()}`
      : `${spent.length} of ${cfg.rpm} requests used in the last minute`;
  return { ms, reason };
}

/** For tests: forget everything spent. */
export function resetBudget() {
  spent.length = 0;
  calibration = 1;
}

/* ------------------------------------------------------------------ *
 * One request
 * ------------------------------------------------------------------ */

export type ChatRequest = {
  messages: ChatMessage[];
  tools?: ToolSchema[];
  toolChoice?: "auto" | "none";
  /** Output tokens reserved for the reply, reasoning included. */
  maxTokens: number;
};

export type ChatUsage = { prompt: number; completion: number; total: number };

export type ChatResult =
  | {
      ok: true;
      content: string;
      toolCalls: ToolCall[];
      finish: string;
      usage: ChatUsage;
      /** What we estimated before sending, input plus reserved output. */
      estimated: number;
    }
  | { ok: false; error: string; status?: number; retryAfterMs?: number };

const why = (e: unknown) => (e instanceof Error ? e.message : String(e));

export async function chat(cfg: LlmConfig, req: ChatRequest): Promise<ChatResult> {
  const inputEstimate = estimateRequest(req.messages, req.tools);
  const estimated = inputEstimate + req.maxTokens;
  const body: Record<string, unknown> = {
    model: cfg.model,
    messages: req.messages,
    temperature: 0,
    max_completion_tokens: req.maxTokens,
  };
  if (req.tools?.length) {
    body.tools = req.tools;
    body.tool_choice = req.toolChoice ?? "auto";
  }
  if (cfg.reasoningEffort) body.reasoning_effort = cfg.reasoningEffort;

  let res: Response;
  try {
    res = await fetch(`${cfg.baseUrl}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${cfg.apiKey}` },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(120_000),
    });
  } catch (e) {
    return { ok: false, error: `Could not reach ${cfg.baseUrl}: ${why(e)}` };
  }

  const text = await res.text();
  if (!res.ok) {
    // A provider that does not know reasoning_effort: drop it once and retry.
    if (res.status === 400 && cfg.reasoningEffort && /reasoning_effort/i.test(text)) {
      cfg.reasoningEffort = null;
      return chat(cfg, req);
    }
    const header = Number(res.headers.get("retry-after"));
    const hinted = Number(text.match(/try again in ([\d.]+)s/i)?.[1]);
    const retryAfterMs =
      res.status === 429
        ? Math.ceil(1000 * (Number.isFinite(header) && header > 0 ? header : Number.isFinite(hinted) && hinted > 0 ? hinted : 10))
        : undefined;
    return { ok: false, status: res.status, retryAfterMs, error: `HTTP ${res.status}: ${text.slice(0, 500)}` };
  }

  let json: {
    choices?: { message?: { content?: string | null; tool_calls?: ToolCall[] }; finish_reason?: string }[];
    usage?: { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number };
  };
  try {
    json = JSON.parse(text);
  } catch (e) {
    return { ok: false, error: `The provider returned a body that is not JSON: ${why(e)}` };
  }

  const choice = json.choices?.[0];
  const prompt = json.usage?.prompt_tokens ?? inputEstimate;
  const completion = json.usage?.completion_tokens ?? 0;
  const total = json.usage?.total_tokens ?? prompt + completion;

  spent.push({ at: Date.now(), tokens: total });
  // If the provider counted more input than we guessed, guess higher from now on.
  if (json.usage?.prompt_tokens && json.usage.prompt_tokens > inputEstimate) {
    calibration *= json.usage.prompt_tokens / inputEstimate;
  }

  return {
    ok: true,
    content: choice?.message?.content ?? "",
    toolCalls: choice?.message?.tool_calls ?? [],
    finish: choice?.finish_reason ?? "unknown",
    usage: { prompt, completion, total },
    estimated,
  };
}

export type WaitEvent = { type: "waiting"; ms: number; reason: string };

/**
 * Send one request inside the budget: wait for room in the window, refuse
 * anything that could never fit, and honour a provider's 429 retry hint.
 * Yields a waiting event whenever it pauses, so a caller can show why.
 */
export async function* callModel(cfg: LlmConfig, req: ChatRequest): AsyncGenerator<WaitEvent, ChatResult, void> {
  const estimated = estimateRequest(req.messages, req.tools) + req.maxTokens;
  if (estimated > cfg.maxRequestTokens) {
    return {
      ok: false,
      error: `Request estimated at ~${estimated.toLocaleString()} tokens, over the ${cfg.maxRequestTokens.toLocaleString()} per-request limit. It was not sent.`,
    };
  }
  for (let attempt = 0; attempt < 5; attempt++) {
    for (let w = planWait(cfg, estimated); w.ms > 0; w = planWait(cfg, estimated)) {
      yield { type: "waiting", ms: w.ms, reason: w.reason };
      await sleep(w.ms);
    }
    const r = await chat(cfg, req);
    if (r.ok || r.status !== 429) return r;
    const ms = r.retryAfterMs ?? 10_000;
    yield { type: "waiting", ms, reason: "the provider returned 429 (rate limited)" };
    await sleep(ms);
  }
  return { ok: false, error: "Still rate limited after 5 attempts." };
}

/* ------------------------------------------------------------------ *
 * Accounting
 * ------------------------------------------------------------------ */

export type RequestUsage = { label: string; estimated: number } & ChatUsage;
export type TokenUsage = ChatUsage & { requests: number; maxRequest: number; perRequest: RequestUsage[] };

export const emptyUsage = (): TokenUsage => ({ prompt: 0, completion: 0, total: 0, requests: 0, maxRequest: 0, perRequest: [] });

export function addRequest(u: TokenUsage, label: string, r: Extract<ChatResult, { ok: true }>) {
  u.prompt += r.usage.prompt;
  u.completion += r.usage.completion;
  u.total += r.usage.total;
  u.requests += 1;
  u.maxRequest = Math.max(u.maxRequest, r.usage.total);
  u.perRequest.push({ label, estimated: r.estimated, ...r.usage });
}

export function mergeUsage(a: TokenUsage, b: TokenUsage): TokenUsage {
  return {
    prompt: a.prompt + b.prompt,
    completion: a.completion + b.completion,
    total: a.total + b.total,
    requests: a.requests + b.requests,
    maxRequest: Math.max(a.maxRequest, b.maxRequest),
    perRequest: [...a.perRequest, ...b.perRequest],
  };
}

/** Pull a JSON object out of a reply that may be fenced or padded with prose. */
export function extractJson(text: string): unknown {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidates = [fenced?.[1], text, text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1)];
  for (const c of candidates) {
    if (!c?.trim()) continue;
    try {
      return JSON.parse(c.trim());
    } catch {
      /* next shape */
    }
  }
  return null;
}
