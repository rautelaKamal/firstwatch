/**
 * POST /api/triage: run FirstWatch on uploaded stack files and stream every
 * step to the browser as server-sent events.
 *
 * Body: { files: { [name]: text }, exampleId?: string, live?: boolean, model?: string }
 *
 * By default this replays a saved run and makes no model calls, so the page
 * can be developed and demoed for free. { live: true } runs the real agent.
 * The scanner baseline is deterministic code and always runs.
 *
 * No `export const runtime`: Cache Components is on in next.config.ts, which
 * requires the Node.js runtime (the default) and rejects the runtime export,
 * even when set to "nodejs". cheerio needs Node, and Node is what it gets.
 */

import { runAgent, type AgentEvent, type FirstWatchReport } from "@/lib/agent";
import { runBaseline } from "@/lib/baseline";
import { caseSpec, savedRun } from "@/lib/examples";
import { emptyUsage, type TokenUsage } from "@/lib/llm";
import { parse_stack } from "@/lib/tools";

// A live run is paced to the provider's per-minute budget and takes minutes.
export const maxDuration = 300;

const MAX_FILES = 12;
const MAX_FILE_CHARS = 200_000;

export type StreamEvent =
  | AgentEvent
  | { type: "baseline"; report: FirstWatchReport; version: string | null }
  | { type: "replay"; note: string };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Replay a saved run as a believable sequence of steps. No model is called. */
async function* replay(exampleId: string | undefined, files: Record<string, string>): AsyncGenerator<StreamEvent> {
  const saved = savedRun(exampleId);
  if (!saved) {
    yield {
      type: "error",
      message: "There is no saved run for this input. Turn on Live run to analyse it, which calls the model and uses API tokens.",
    };
    return;
  }
  const report = saved.report as FirstWatchReport;
  yield { type: "replay", note: "Replaying a saved run of this example. No model calls are made." };

  const parsed = parse_stack(files);
  if (parsed.ok) {
    yield {
      type: "facts", summary: parsed.summary, facts: parsed.facts.length, ecosystems: parsed.ecosystems,
      packages: parsed.packages.length, runtimeEvidence: parsed.hasRuntimeEvidence, unverified: parsed.unverified,
    };
  }
  await sleep(300);

  let i = 0;
  const byPkg = new Map<string, FirstWatchReport["findings"]>();
  for (const f of report.findings) byPkg.set(f.package, [...(byPkg.get(f.package) ?? []), f]);
  for (const [pkg, fs] of byPkg) {
    const id = `replay-${i++}`;
    const tool = fs[0].decided_by?.method === "version_in_range" ? "version_in_range" : "check_distro_fix";
    yield { type: "tool_call", iteration: 1, id, tool, args: { package: pkg, version: fs[0].installed_version, cve: fs.map((f) => f.cve ?? "").filter(Boolean).join(",") } };
    await sleep(350);
    yield { type: "tool_result", iteration: 1, id, tool, ok: true, ms: 0, summary: fs.map((f) => f.decided_by?.detail ?? f.verdict).join(" | ").slice(0, 300), result: null };
  }
  if (report.enforcement_log?.length) yield { type: "enforced", downgrades: report.enforcement_log };
  await sleep(250);
  yield {
    type: "final", iteration: 0, report, text: "", toolCalls: i, ms: 0,
    usage: (saved.usage as TokenUsage) ?? emptyUsage(), digestUsage: (saved.digestUsage as TokenUsage) ?? emptyUsage(),
  };
}

export async function POST(req: Request) {
  let body: { files?: unknown; exampleId?: unknown; live?: unknown; model?: unknown };
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "Send JSON: { files: { name: text } }" }, { status: 400 });
  }

  const files: Record<string, string> = {};
  for (const [name, text] of Object.entries((body.files ?? {}) as Record<string, unknown>).slice(0, MAX_FILES)) {
    if (typeof text === "string" && text.trim()) files[name.slice(0, 100)] = text.slice(0, MAX_FILE_CHARS);
  }
  if (!Object.keys(files).length) return Response.json({ error: "No files were sent." }, { status: 400 });

  const exampleId = typeof body.exampleId === "string" ? body.exampleId : undefined;
  // A visitor may pick a model only from the ones this deployment is configured for.
  const allowed = [process.env.LLM_MODEL, process.env.LLM_FALLBACK_MODEL, ...(process.env.LLM_MODELS ?? "").split(",")]
    .map((m) => m?.trim())
    .filter((m): m is string => !!m);
  const model = typeof body.model === "string" && allowed.includes(body.model) ? body.model : undefined;
  const live = body.live === true;
  const spec = caseSpec(exampleId);
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const send = (event: StreamEvent) => controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
      try {
        const baseline = await runBaseline({ files, cve: spec.cve, cves: spec.cves, target: spec.target });
        send({ type: "baseline", report: baseline.report, version: baseline.version });
        const events = live
          ? runAgent({ stack: spec.stack, files, target: spec.target, cve: spec.cve, cves: spec.cves, sources: spec.sources, model })
          : replay(exampleId, files);
        for await (const event of events) send(event);
      } catch (e) {
        send({ type: "error", message: e instanceof Error ? e.message : String(e) });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-cache, no-transform", connection: "keep-alive" },
  });
}
