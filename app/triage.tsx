"use client";

import { useRef, useState } from "react";

import type { FirstWatchReport, PackageFinding } from "@/lib/agent";
import { REASSURANCE, VERDICT_LABELS, type Verdict } from "@/lib/verdicts";

type Field = { file: string; label: string; runtime?: boolean };
type Example = { id: string; label: string; description: string; files: Record<string, string> };
type Event = { type: string; [key: string]: unknown };
type LogLine = { tone: "info" | "tool" | "ok" | "warn" | "error"; text: string };

const BADGE: Record<Verdict, string> = {
  AFFECTED: "bg-red-100 text-red-800 ring-red-200 dark:bg-red-950 dark:text-red-200 dark:ring-red-900",
  AFFECTED_MITIGATED: "bg-amber-100 text-amber-900 ring-amber-200 dark:bg-amber-950 dark:text-amber-200 dark:ring-amber-900",
  NOT_AFFECTED: "bg-emerald-100 text-emerald-800 ring-emerald-200 dark:bg-emerald-950 dark:text-emerald-200 dark:ring-emerald-900",
  UNVERIFIED: "bg-neutral-100 text-neutral-700 ring-neutral-200 dark:bg-neutral-800 dark:text-neutral-200 dark:ring-neutral-700",
};

function Badge({ verdict, small }: { verdict: Verdict; small?: boolean }) {
  return (
    <span className={`inline-flex items-center rounded-full font-medium ring-1 ring-inset ${BADGE[verdict]} ${small ? "px-2 py-0.5 text-xs" : "px-2.5 py-1 text-sm"}`}>
      {VERDICT_LABELS[verdict]}
    </span>
  );
}

const worst = (vs: Verdict[]): Verdict =>
  vs.reduce<Verdict>((w, v) => (REASSURANCE[v] < REASSURANCE[w] ? v : w), vs[0] ?? "UNVERIFIED");

const isUrl = (s: string) => /^https?:\/\//i.test(s);

/** One line of the live log for each event worth showing. */
function describe(e: Event): LogLine | null {
  const s = (v: unknown) => String(v ?? "");
  switch (e.type) {
    case "replay":
      return { tone: "warn", text: s(e.note) };
    case "baseline":
      return { tone: "info", text: `Scanner baseline: ${VERDICT_LABELS[(e.report as FirstWatchReport).overall]} from version "${s(e.version) || "none"}"` };
    case "start":
      return { tone: "info", text: `Model ${s(e.model)}` };
    case "facts":
      return { tone: "info", text: `Parsed the stack: ${s(e.summary)}` };
    case "nvd":
      return { tone: "info", text: `NVD ${s(e.id)}: ${s(e.ranges)} PHP ranges${e.note ? ` (${s(e.note)})` : ""}` };
    case "digest":
      return e.error
        ? { tone: "error", text: `Could not digest ${s(e.url)}: ${s(e.error)}` }
        : { tone: "info", text: `Advisory ${s(e.url)}: ${s(e.items)} verified facts${e.cached ? " (cached)" : ""}` };
    case "waiting":
      return { tone: "warn", text: `Waiting ${Math.round(Number(e.ms) / 1000)}s for the rate limit` };
    case "tool_call":
      return {
        tone: "tool",
        text: `${s(e.tool)} ${Object.entries((e.args ?? {}) as Record<string, unknown>).filter(([, v]) => s(v)).map(([k, v]) => `${k}=${s(v)}`).join(" ")}`,
      };
    case "tool_result":
      return { tone: e.ok ? "ok" : "error", text: s(e.summary) };
    case "enforced":
      return { tone: "warn", text: `Invariants downgraded ${(e.downgrades as unknown[]).length} verdict(s)` };
    case "final":
      return { tone: "ok", text: e.report ? "Report ready" : `No valid report: ${s(e.reportError)}` };
    case "error":
      return { tone: "error", text: s(e.message) };
    default:
      return null;
  }
}

const TONE: Record<LogLine["tone"], string> = {
  info: "text-neutral-600 dark:text-neutral-400",
  tool: "text-sky-700 dark:text-sky-300",
  ok: "text-emerald-700 dark:text-emerald-300",
  warn: "text-amber-700 dark:text-amber-300",
  error: "text-red-700 dark:text-red-300",
};

function PackageCard({ name, findings, scanner }: { name: string; findings: PackageFinding[]; scanner: Verdict | null }) {
  const verdict = worst(findings.map((f) => f.verdict));
  const first = findings[0];
  return (
    <article className="rounded-xl border border-neutral-200 bg-white p-4 shadow-sm dark:border-neutral-800 dark:bg-neutral-900">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="break-all font-mono text-base font-semibold">{name}</h3>
          <p className="mt-0.5 break-all font-mono text-xs text-neutral-500">
            {first.installed_version} <span className="font-sans">from {first.version_source}</span>
          </p>
        </div>
        <div className="flex flex-col items-start gap-1.5 text-xs sm:items-end">
          <div className="flex items-center gap-2">
            <span className="text-neutral-500">FirstWatch</span>
            <Badge verdict={verdict} />
          </div>
          {scanner && (
            <div className="flex items-center gap-2">
              <span className="text-neutral-500">Scanner</span>
              <Badge verdict={scanner} small />
            </div>
          )}
        </div>
      </div>

      <div className="mt-4 space-y-3">
        {findings.map((f, i) => (
          <section key={`${f.cve}-${i}`} className="border-t border-neutral-100 pt-3 first:border-0 first:pt-0 dark:border-neutral-800">
            {(findings.length > 1 || f.cve) && (
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-neutral-600 dark:text-neutral-400">{f.cve ?? "CVE not named"}</span>
                <Badge verdict={f.verdict} small />
              </div>
            )}

            {f.enforcement?.length ? (
              f.enforcement.map((e, j) => (
                <p key={j} className="rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:bg-amber-950/60 dark:text-amber-200">
                  <span className="font-medium">Downgraded by {e.invariant}</span> from {VERDICT_LABELS[e.from as Verdict]} to {VERDICT_LABELS[e.to as Verdict]}: {e.why}
                </p>
              ))
            ) : f.allow_reason ? (
              <p className="rounded-lg bg-neutral-50 px-3 py-2 text-sm text-neutral-700 dark:bg-neutral-800/60 dark:text-neutral-300">
                <span className="font-medium">Why this stands:</span> {f.allow_reason}
              </p>
            ) : null}

            {f.citations?.length > 0 && (
              <div className="mt-2 space-y-1.5">
                {f.citations.map((c, j) => (
                  <details key={j} className="group rounded-lg border border-neutral-200 px-3 py-2 text-sm dark:border-neutral-800">
                    <summary className="cursor-pointer list-none text-neutral-800 marker:hidden dark:text-neutral-200">
                      <span className="mr-1 inline-block text-neutral-400 transition group-open:rotate-90">›</span>
                      {c.claim}
                      {c.verified === false && <span className="ml-2 text-xs text-red-700 dark:text-red-300">quote not found in source</span>}
                    </summary>
                    <blockquote className="mt-2 border-l-2 border-neutral-300 pl-3 text-neutral-600 dark:border-neutral-700 dark:text-neutral-400">
                      {c.quote}
                    </blockquote>
                    <p className="mt-1 break-all text-xs text-neutral-500">
                      {isUrl(c.source) ? (
                        <a href={c.source} target="_blank" rel="noreferrer" className="underline underline-offset-2 hover:text-neutral-800 dark:hover:text-neutral-200">
                          {c.source}
                        </a>
                      ) : (
                        c.source
                      )}
                    </p>
                  </details>
                ))}
              </div>
            )}

            {f.remediation?.length > 0 && (
              <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-neutral-700 dark:text-neutral-300">
                {[...f.remediation].sort((a, b) => a.priority - b.priority).map((r, j) => (
                  <li key={j}>
                    <span className="font-medium">{r.action}</span>
                    {r.detail && <span className="text-neutral-500"> {r.detail}</span>}
                  </li>
                ))}
              </ol>
            )}

            {f.unverified?.length > 0 && (
              <ul className="mt-2 space-y-1 text-sm text-neutral-600 dark:text-neutral-400">
                {f.unverified.map((u, j) => (
                  <li key={j}>
                    Needs {u.missing}: <code className="rounded bg-neutral-100 px-1 py-0.5 text-xs dark:bg-neutral-800">{u.how_to_get_it}</code>
                  </li>
                ))}
              </ul>
            )}
          </section>
        ))}
      </div>
    </article>
  );
}

export default function Triage({ examples, fields }: { examples: Example[]; fields: Field[] }) {
  const [files, setFiles] = useState<Record<string, string>>({});
  const [exampleId, setExampleId] = useState<string | null>(null);
  const [live, setLive] = useState(false);
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState<LogLine[]>([]);
  const [report, setReport] = useState<FirstWatchReport | null>(null);
  const [baseline, setBaseline] = useState<FirstWatchReport | null>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  const loadExample = (ex: Example) => {
    setFiles(ex.files);
    setExampleId(ex.id);
    setReport(null);
    setBaseline(null);
    setLog([]);
  };
  const edit = (file: string, text: string) => {
    setFiles((f) => ({ ...f, [file]: text }));
    setExampleId(null); // edited input no longer matches any saved run
  };
  const upload = async (file: string, list: FileList | null) => {
    const f = list?.[0];
    if (f) edit(file, await f.text());
  };

  async function run() {
    setRunning(true);
    setLog([]);
    setReport(null);
    setBaseline(null);
    resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    const push = (l: LogLine | null) => l && setLog((prev) => [...prev, l]);
    try {
      const res = await fetch("/api/triage", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ files, exampleId, live }),
      });
      if (!res.ok || !res.body) {
        push({ tone: "error", text: ((await res.json().catch(() => ({}))) as { error?: string }).error ?? `Request failed (${res.status})` });
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let cut;
        while ((cut = buffer.indexOf("\n\n")) >= 0) {
          const line = buffer.slice(0, cut).split("\n").find((l) => l.startsWith("data: "));
          buffer = buffer.slice(cut + 2);
          if (!line) continue;
          const event = JSON.parse(line.slice(6)) as Event;
          if (event.type === "baseline") setBaseline(event.report as FirstWatchReport);
          if (event.type === "final" && event.report) setReport(event.report as FirstWatchReport);
          push(describe(event));
        }
      }
    } catch (e) {
      push({ tone: "error", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setRunning(false);
    }
  }

  const filled = Object.values(files).some((t) => t.trim());
  const scanner = baseline?.overall ?? null;
  const byPackage = new Map<string, PackageFinding[]>();
  for (const f of report?.findings ?? []) byPackage.set(f.package, [...(byPackage.get(f.package) ?? []), f]);

  return (
    <div className="space-y-8">
      <section>
        <h2 className="text-sm font-medium text-neutral-500">Load an example</h2>
        <div className="mt-2 flex flex-wrap gap-2">
          {examples.map((ex) => (
            <button
              key={ex.id}
              type="button"
              onClick={() => loadExample(ex)}
              className={`rounded-lg border px-3 py-1.5 text-sm transition ${
                exampleId === ex.id
                  ? "border-neutral-900 bg-neutral-900 text-white dark:border-neutral-100 dark:bg-neutral-100 dark:text-neutral-900"
                  : "border-neutral-300 hover:border-neutral-500 dark:border-neutral-700 dark:hover:border-neutral-500"
              }`}
            >
              {ex.label}
            </button>
          ))}
        </div>
        {exampleId && <p className="mt-2 text-sm text-neutral-500">{examples.find((e) => e.id === exampleId)?.description}</p>}
      </section>

      <section className="space-y-4">
        {[false, true].map((runtime) => (
          <div key={String(runtime)}>
            <h2 className="text-sm font-medium text-neutral-500">{runtime ? "Runtime evidence, pasted from the host" : "Build and config files"}</h2>
            <div className="mt-2 grid gap-3 sm:grid-cols-2">
              {fields.filter((f) => !!f.runtime === runtime).map((f) => (
                <label key={f.file} className="block">
                  <span className="flex items-center justify-between gap-2 text-xs">
                    <code className="truncate text-neutral-700 dark:text-neutral-300">{f.label}</code>
                    <span className="shrink-0 cursor-pointer text-neutral-500 underline underline-offset-2">
                      upload
                      <input type="file" className="sr-only" onChange={(e) => upload(f.file, e.target.files)} />
                    </span>
                  </span>
                  <textarea
                    value={files[f.file] ?? ""}
                    onChange={(e) => edit(f.file, e.target.value)}
                    rows={5}
                    spellCheck={false}
                    placeholder={runtime ? `Paste the output of ${f.label}` : `Paste ${f.label}`}
                    className="mt-1 w-full resize-y rounded-lg border border-neutral-300 bg-white p-2 font-mono text-xs leading-5 outline-none focus:border-neutral-500 dark:border-neutral-700 dark:bg-neutral-900"
                  />
                </label>
              ))}
            </div>
          </div>
        ))}

        <div className="flex flex-wrap items-center gap-4">
          <button
            type="button"
            onClick={run}
            disabled={!filled || running}
            className="rounded-lg bg-neutral-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-neutral-700 disabled:cursor-not-allowed disabled:opacity-40 dark:bg-neutral-100 dark:text-neutral-900 dark:hover:bg-neutral-300"
          >
            {running ? "Running…" : "Run triage"}
          </button>
          <label className="flex items-center gap-2 text-sm text-neutral-600 dark:text-neutral-400">
            <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} className="size-4" />
            Live run <span className="text-xs text-neutral-500">(calls the model; off replays a saved run)</span>
          </label>
        </div>
      </section>

      <div ref={resultsRef} className="scroll-mt-6 space-y-8">
        {log.length > 0 && (
          <section>
            <h2 className="text-sm font-medium text-neutral-500">Steps</h2>
            <ol className="mt-2 space-y-1 rounded-xl border border-neutral-200 bg-neutral-50 p-3 font-mono text-xs leading-5 dark:border-neutral-800 dark:bg-neutral-950">
              {log.map((l, i) => (
                <li key={i} className={`break-words ${TONE[l.tone]}`}>
                  {l.text}
                </li>
              ))}
              {running && <li className="animate-pulse text-neutral-400">…</li>}
            </ol>
          </section>
        )}

        {report && (
          <section className="space-y-4">
            <div className="rounded-xl border border-neutral-200 p-4 dark:border-neutral-800">
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
                <div className="flex items-center gap-2">
                  <span className="text-sm text-neutral-500">FirstWatch</span>
                  <Badge verdict={report.overall} />
                </div>
                {scanner && (
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-neutral-500">Version scanner</span>
                    <Badge verdict={scanner} />
                  </div>
                )}
              </div>
              <p className="mt-3 text-sm leading-6 text-neutral-700 dark:text-neutral-300">{report.summary}</p>
              {report.warnings?.map((w, i) => (
                <p key={i} className="mt-2 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-800 dark:bg-red-950/60 dark:text-red-200">
                  {w.why} <span className="font-mono text-xs">({w.where})</span>
                </p>
              ))}
            </div>

            {[...byPackage].map(([name, fs]) => (
              <PackageCard key={name} name={name} findings={fs} scanner={scanner} />
            ))}

            {report.fixed_versions && report.fixed_versions.length > 0 && (
              <details className="rounded-xl border border-neutral-200 p-4 text-sm dark:border-neutral-800">
                <summary className="cursor-pointer font-medium">Patched versions per advisory</summary>
                <ul className="mt-2 space-y-2">
                  {report.fixed_versions.map((f) => (
                    <li key={f.cve}>
                      <span className="font-mono">{f.cve}</span>: {f.patched.join(", ")}{" "}
                      <a href={f.source} target="_blank" rel="noreferrer" className="break-all text-neutral-500 underline underline-offset-2">
                        {f.ghsa ?? f.source}
                      </a>
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </section>
        )}
      </div>
    </div>
  );
}
