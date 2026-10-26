/**
 * POST /api/triage: run FirstWatch on uploaded stack files and stream every
 * step to the browser as server-sent events.
 *
 * Body: { files: { [name]: text }, exampleId?: string, live?: boolean, model?: string }
 *
 * By default this replays a saved run and makes no model calls, so the page
 * can be developed and demoed for free. { live: true } runs the real agent
 * when lib/limits.ts allows it, and otherwise says why and replays. The
 * scanner baseline and stack parsing are code and always run.
 *
 * Input that is not one of the examples ("check your own server") must be in
 * lib/scope.ts's scope first. Outside it the stream carries one "unsupported"
 * message and no verdict, not even the scanner's.
 *
 * Nothing from the request body is stored or logged here. A live run sends
 * the parsed distro, package versions and settings to OSV and to the model
 * provider; lib/limits.ts keeps the client IP for its rate-limit window.
 *
 * No `export const runtime`: Cache Components is on in next.config.ts, which
 * requires the Node.js runtime (the default) and rejects the runtime export,
 * even when set to "nodejs". cheerio needs Node, and Node is what it gets.
 */

import { runAgent, type AgentEvent, type FirstWatchReport } from "@/lib/agent";
import { runBaseline } from "@/lib/baseline";
import { cachedCveNow } from "@/lib/cache";
import { caseSpec, savedRun } from "@/lib/examples";
import { allowLiveRun, clientIp, FALLBACK } from "@/lib/limits";
import { emptyUsage, type TokenUsage } from "@/lib/llm";
import { checkScope } from "@/lib/scope";
import { parse_stack } from "@/lib/tools";

// A live run is paced to the provider's per-minute budget and takes minutes.
// Vercel Hobby with Fluid compute: 300 s default and maximum (docs, 2026-08-24).
export const maxDuration = 300;
// Stop starting requests this long before the limit, so the run ends with a message, not a cut stream.
const DEADLINE_MARGIN_MS = 20_000;

// A comment line every 10 s keeps proxies from dropping a connection that is
// waiting on a rate limit or a model call.
const HEARTBEAT_MS = 10_000;
// Opening padding: some proxies hold a response until a few KB have arrived.
const OPEN_PADDING = `: ${" ".repeat(2048)}\n\n`;

const MAX_FILES = 12;
const MAX_FILE_CHARS = 200_000;

export type StreamEvent =
  | AgentEvent
  | { type: "baseline"; report: FirstWatchReport; version: string | null }
  | { type: "replay"; note: string; recorded: { at: string | null; model: string; tokens: number | null } }
  | { type: "live_unavailable"; reason: string; message: string }
  | { type: "unsupported"; message: string };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Replay a saved run as a believable sequence of steps. No model is called. */
async function* replay(exampleId: string | undefined): AsyncGenerator<StreamEvent> {
  const saved = savedRun(exampleId);
  if (!saved) {
    yield {
      type: "error",
      message: "There is no saved run for this input. Turn on Live run to analyse it, which calls the model and uses API tokens.",
    };
    return;
  }
  const report = saved.report as FirstWatchReport;
  yield {
    type: "replay",
    note: "Replaying a recorded live run of this example. No model calls are made.",
    // Every recording so far used gpt-oss-120b; newer recordings store their model.
    recorded: { at: report.assessed_at ?? null, model: saved.model ?? "openai/gpt-oss-120b", tokens: saved.usage?.total ?? null },
  };
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
  const startedAt = Date.now();
  const ip = clientIp(req);
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
  const wantsLive = body.live === true;
  const spec = caseSpec(exampleId);
  // Not an example with a recording: the visitor's own server.
  const own = !savedRun(exampleId);
  const encoder = new TextEncoder();
  let closed = false;
  let heartbeat: ReturnType<typeof setInterval> | undefined;
  const stop = () => {
    closed = true;
    if (heartbeat) clearInterval(heartbeat);
  };
  // The visitor left: stop the run, so no model call is spent on nobody.
  req.signal?.addEventListener("abort", stop);

  const stream = new ReadableStream<Uint8Array>({
    // start() returns at once and the work runs detached, so nothing about
    // flushing the response depends on when the pipeline finishes.
    start(controller) {
      const write = (text: string) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(text));
        } catch {
          stop();
        }
      };
      const send = (event: StreamEvent) => write(`data: ${JSON.stringify(event)}\n\n`);
      write(OPEN_PADDING);
      heartbeat = setInterval(() => write(`: keepalive ${Date.now()}\n\n`), HEARTBEAT_MS);

      void (async () => {
        try {
          // 0. Own input outside the supported distros, or with no PHP packages: say so, and give no verdict.
          if (own) {
            const scope = checkScope([files["os-release"], files["php-v.txt"], files["dpkg.txt"]].filter(Boolean).join("\n"));
            if (!scope.ok) {
              send({ type: "unsupported", message: scope.message });
              return;
            }
          }

          // 1. The scanner baseline first. Code only, and from the cached NVD records
          //    when we have them, so it goes out before any network or model wait.
          const records = spec.cves.map((id) => cachedCveNow(id));
          const ranges = records.every((r) => r && "found" in r && r.found)
            ? records.flatMap((r) => (r && "found" in r && r.found ? r.affected.filter((a) => a.product === "php/php").map((a) => a.range) : []))
            : undefined;
          const baseline = await runBaseline({ files, cve: spec.cve, cves: spec.cves, target: spec.target, ranges });
          send({ type: "baseline", report: baseline.report, version: baseline.version });
          const parsed = parse_stack(files);
          if (parsed.ok) {
            send({
              type: "facts", summary: parsed.summary, facts: parsed.facts.length, ecosystems: parsed.ecosystems,
              packages: parsed.packages.length, runtimeEvidence: parsed.hasRuntimeEvidence, unverified: parsed.unverified,
            });
          }

          // 2. Only now the checks that may wait.
          let live = false;
          if (wantsLive) {
            const decision = await allowLiveRun(ip);
            live = decision.ok;
            if (!decision.ok) {
              const message = own ? decision.message.replace(FALLBACK, "The scanner result and parsing above are complete; try the AI check again later.") : decision.message;
              send({ type: "live_unavailable", reason: decision.reason, message });
            }
          }
          // Own input has no recording to fall back on: the baseline and parsing are the whole answer.
          if (!live && own) return;
          const events = live
            ? runAgent({ stack: spec.stack, files, target: spec.target, cve: spec.cve, cves: spec.cves, sources: spec.sources, model, deadline: startedAt + maxDuration * 1000 - DEADLINE_MARGIN_MS })
            : replay(exampleId);
          for await (const event of events) {
            if (closed) break; // ends the generator, so the agent makes no further calls
            if (event.type === "facts") continue; // already sent above
            send(event);
          }
        } catch (e) {
          send({ type: "error", message: e instanceof Error ? e.message : String(e) });
        } finally {
          const wasClosed = closed;
          stop();
          if (!wasClosed) {
            try {
              controller.close();
            } catch {
              /* already closed */
            }
          }
        }
      })();
    },
    cancel() {
      stop();
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      // nginx-style proxies: do not buffer this response.
      "x-accel-buffering": "no",
    },
  });
}
