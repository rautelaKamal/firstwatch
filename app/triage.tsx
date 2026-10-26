"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import type { FirstWatchReport, PackageFinding } from "@/lib/agent";
import { RUNTIME_COMMAND, splitRuntime } from "@/lib/runtime";
import { INVARIANTS, REASSURANCE, VERDICT_LABELS, type Verdict } from "@/lib/verdicts";

type Example = { id: string; label: string; blurb: string; expected: string; runtime: string; config: Record<string, string> };
type Event = { type: string; [key: string]: unknown };
type LogLine = { tone: "info" | "tool" | "ok" | "warn" | "error"; text: string };
type Recorded = { at: string | null; model: string; tokens: number | null };

const CONFIG_FILES = [
  { file: "Dockerfile", label: "Dockerfile" },
  { file: "php.ini", label: "php.ini" },
  { file: "nginx.conf", label: "nginx.conf or Apache vhost" },
];
const INVARIANT_COUNT = Object.keys(INVARIANTS).length;

const BADGE: Record<Verdict, string> = {
  AFFECTED: "bg-red-100 text-red-800 ring-red-200 dark:bg-red-950 dark:text-red-200 dark:ring-red-900",
  AFFECTED_MITIGATED: "bg-amber-100 text-amber-900 ring-amber-200 dark:bg-amber-950 dark:text-amber-200 dark:ring-amber-900",
  NOT_AFFECTED: "bg-emerald-100 text-emerald-800 ring-emerald-200 dark:bg-emerald-950 dark:text-emerald-200 dark:ring-emerald-900",
  UNVERIFIED: "bg-neutral-100 text-neutral-700 ring-neutral-200 dark:bg-neutral-800 dark:text-neutral-200 dark:ring-neutral-700",
};
const DOT: Record<string, string> = {
  AFFECTED: "bg-red-500",
  AFFECTED_MITIGATED: "bg-amber-500",
  NOT_AFFECTED: "bg-emerald-500",
  UNVERIFIED: "bg-neutral-400",
};
const PANEL: Record<Verdict, string> = {
  AFFECTED: "border-red-300 bg-red-50 dark:border-red-900 dark:bg-red-950/40",
  AFFECTED_MITIGATED: "border-amber-300 bg-amber-50 dark:border-amber-900 dark:bg-amber-950/40",
  NOT_AFFECTED: "border-emerald-300 bg-emerald-50 dark:border-emerald-900 dark:bg-emerald-950/40",
  UNVERIFIED: "border-neutral-300 bg-neutral-50 dark:border-neutral-700 dark:bg-neutral-900",
};

function Badge({ verdict, size = "md" }: { verdict: Verdict; size?: "sm" | "md" | "lg" }) {
  const pad = size === "lg" ? "px-3 py-1.5 text-base" : size === "sm" ? "px-2 py-0.5 text-xs" : "px-2.5 py-1 text-sm";
  return <span className={`inline-flex items-center rounded-full font-medium ring-1 ring-inset ${BADGE[verdict]} ${pad}`}>{VERDICT_LABELS[verdict]}</span>;
}

const worst = (vs: Verdict[]): Verdict => vs.reduce<Verdict>((w, v) => (REASSURANCE[v] < REASSURANCE[w] ? v : w), vs[0] ?? "UNVERIFIED");
const isAffected = (v: Verdict) => v === "AFFECTED" || v === "AFFECTED_MITIGATED";
const isUrl = (s: string) => /^https?:\/\//i.test(s);
const CODENAME: Record<string, string> = {
  "Debian:11": "bullseye", "Debian:12": "bookworm", "Debian:13": "trixie",
  "Ubuntu:20.04:LTS": "focal", "Ubuntu:22.04:LTS": "jammy", "Ubuntu:24.04:LTS": "noble",
};

/** The engine's evidence sentence, rewritten as something a person reads in one pass. */
function explain(reason: string): string {
  let m = reason.match(/^OSV row: (\S+) (\S+) (\S+) is fixed(?: \(fixed in (\S+)\))?(?: for (\S+))?, in this stack's own ecosystem, with no affected row; installed version read from (.+?)\.$/);
  if (m) {
    const [, eco, src, ver, fixedIn, cve, where] = m;
    return `${eco.split(":")[0]}'s own security data, checked through OSV, lists ${src} ${ver} as fixed${cve ? ` for ${cve}` : ""}${fixedIn && fixedIn !== ver ? `; the fix shipped in ${fixedIn}` : ""}. The installed version was read from ${where}.`;
  }
  m = reason.match(/^An alarm needs no permission\. Supported by OSV row (\S+) (\S+) (\S+) affected\.$/);
  if (m) return `${m[1].split(":")[0]}'s own security data, checked through OSV, lists ${m[2]} ${m[3]} as still affected.`;
  m = reason.match(/^An alarm needs no permission\. Supported by (\S+) inside "(.+?)"(?:, the range stated for (.+?)|, a range no fetched source states)?\.$/);
  if (m) return `Version ${m[1]} falls inside the affected range ${m[2]}${m[3] ? `, as published for ${m[3]}` : ""}.`;
  if (/^An alarm needs no permission\. No supporting tool result/.test(reason)) return "Reported as affected; no tool result was recorded to back the alarm, so treat it as unconfirmed.";
  m = reason.match(/^Range result: (\S+) is outside "(.+?)", read in (.+?), which covers .*$/);
  if (m) return `Version ${m[1]} is outside the affected range ${m[2]}, as stated in ${m[3]}.`;
  if (/^UNVERIFIED asserts nothing/.test(reason)) return "There is not enough evidence to decide. What is missing is listed below.";
  return reason.replace(/; /g, ". ");
}

function describe(e: Event): LogLine | null {
  const s = (v: unknown) => String(v ?? "");
  switch (e.type) {
    case "replay": return { tone: "warn", text: s(e.note) };
    case "live_unavailable": return { tone: "warn", text: s(e.message) };
    case "baseline": return { tone: "info", text: `Version scanner: ${VERDICT_LABELS[(e.report as FirstWatchReport).overall]} from "${s(e.version) || "no version"}"` };
    case "start": return { tone: "info", text: `Model ${s(e.model)}` };
    case "facts": return { tone: "info", text: `Parsed the stack: ${s(e.summary)}` };
    case "nvd": return { tone: "info", text: `NVD ${s(e.id)}: ${s(e.ranges)} PHP ranges${e.note ? ` (${s(e.note)})` : ""}` };
    case "digest": return e.error ? { tone: "error", text: `Could not read ${s(e.url)}: ${s(e.error)}` } : { tone: "info", text: `Advisory ${s(e.url)}: ${s(e.items)} verified facts${e.cached ? " (cached)" : ""}` };
    case "model_switch": return { tone: "warn", text: `Switched model from ${s(e.from)} to ${s(e.to)}: ${s(e.reason)}` };
    case "waiting": return { tone: "warn", text: `Waiting ${Math.round(Number(e.ms) / 1000)}s for the rate limit` };
    case "tool_call": return { tone: "tool", text: `${s(e.tool)} ${Object.entries((e.args ?? {}) as Record<string, unknown>).filter(([, v]) => s(v)).map(([k, v]) => `${k}=${s(v)}`).join(" ")}` };
    case "tool_result": return { tone: e.ok ? "ok" : "error", text: s(e.summary) };
    case "enforced": return { tone: "warn", text: `Safety checks downgraded ${(e.downgrades as unknown[]).length} verdict(s)` };
    case "final": return { tone: "ok", text: e.report ? "Report ready" : `No valid report: ${s(e.reportError)}` };
    case "error": return { tone: "error", text: s(e.message) };
    default: return null;
  }
}
const TONE: Record<LogLine["tone"], string> = {
  info: "text-neutral-600 dark:text-neutral-400",
  tool: "text-sky-700 dark:text-sky-300",
  ok: "text-emerald-700 dark:text-emerald-300",
  warn: "text-amber-700 dark:text-amber-300",
  error: "text-red-700 dark:text-red-300",
};

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => navigator.clipboard?.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); })}
      className="text-xs text-neutral-600 underline underline-offset-2 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100"
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

/** The headline: how many engine packages are affected, why, and the exact next step. */
function ResultBanner({ report, scanner, ecosystem, held }: { report: FirstWatchReport; scanner: Verdict | null; ecosystem: string | null; held: string[] }) {
  const byPkg = new Map<string, PackageFinding[]>();
  for (const f of report.findings) byPkg.set(f.package, [...(byPkg.get(f.package) ?? []), f]);
  const pkgs = [...byPkg].map(([name, fs]) => ({ name, fs, verdict: worst(fs.map((f) => f.verdict)) }));
  const affected = pkgs.filter((p) => isAffected(p.verdict));
  const first = affected[0]?.fs.find((f) => isAffected(f.verdict));
  const distro = !!ecosystem && affected.some((p) => p.name !== "php");
  const codename = ecosystem ? CODENAME[ecosystem] : undefined;
  const isolate = first?.remediation?.find((r) => r.type === "isolate");
  const patch = first?.remediation?.slice().sort((a, b) => a.priority - b.priority).find((r) => r.type === "patch");

  // The distro's fixed version: recorded by code on newer runs, else named in the remediation.
  const fixedIn = first?.fixed_in ?? patch?.action.match(/\b\d+\.\d+\.\d+-[\w.~+]+/)?.[0];
  const reason = !affected.length
    ? report.overall === "NOT_AFFECTED"
      ? "Every engine package is fixed in the distribution's own packages, even though the upstream version number looks old."
      : report.findings.flatMap((f) => f.unverified ?? [])[0]?.missing
        ? `Not enough evidence: needs ${report.findings.flatMap((f) => f.unverified ?? [])[0].missing}.`
        : "Not enough evidence to decide."
    : fixedIn && distro
      ? `${affected.map((p) => p.name).join(" and ")} ${affected.length > 1 ? "are" : "is"} at ${first?.installed_version}; ${ecosystem?.split(":")[0] ?? "the distribution"} fixed both CVEs in ${fixedIn}.`
      : first?.allow_reason
        ? explain(first.allow_reason)
        : `${first?.package} ${first?.installed_version} is inside the affected range.`;

  const upgrade = [...new Set([...affected.map((p) => p.name).filter((n) => n !== "php"), ...(report.covered_packages ?? [])])];
  const heldNow = upgrade.filter((p) => held.includes(p));
  const command = `${heldNow.length ? `sudo apt-mark unhold ${heldNow.join(" ")} && ` : ""}sudo apt-get update && sudo apt-get install --only-upgrade ${upgrade.join(" ")}`;

  return (
    <div className={`rounded-xl border p-4 sm:p-5 ${PANEL[report.overall]}`}>
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <div className="flex items-center gap-2">
          <span className="text-sm text-neutral-600 dark:text-neutral-400">FirstWatch</span>
          <Badge verdict={report.overall} size="lg" />
        </div>
        {scanner && (
          <div className="flex items-center gap-2">
            <span className="text-sm text-neutral-600 dark:text-neutral-400">Version scanner</span>
            <Badge verdict={scanner} />
          </div>
        )}
      </div>
      <p className="mt-4 text-lg font-semibold">
        {affected.length} of {pkgs.length} engine package{pkgs.length === 1 ? "" : "s"} affected
      </p>
      <p className="mt-1 text-sm leading-6 text-neutral-800 dark:text-neutral-200">{reason}</p>

      {affected.length > 0 && (
        <div className="mt-4">
          {distro ? (
            <>
              <div className="flex items-center justify-between gap-2">
                <p className="text-xs font-medium uppercase tracking-wide text-neutral-500">Fix</p>
                <CopyButton text={command} />
              </div>
              <pre className="mt-1 whitespace-pre-wrap break-all rounded-lg bg-neutral-900 px-3 py-2 text-xs leading-5 text-neutral-100 dark:bg-black">
                <code>{command}</code>
              </pre>
              {heldNow.length > 0 && (
                <p className="mt-2 text-sm text-neutral-700 dark:text-neutral-300">
                  <code className="text-xs">{heldNow.join(" ")}</code> {heldNow.length > 1 ? "are" : "is"} on hold, which is why upgrades skipped {heldNow.length > 1 ? "them" : "it"}. Unhold, upgrade, then restart PHP-FPM.
                </p>
              )}
              {ecosystem?.startsWith("Debian") && codename && (
                <p className="mt-2 text-sm text-neutral-700 dark:text-neutral-300">
                  Debian ships this fix in <code className="text-xs">{codename}-security</code>. If apt finds nothing newer, add{" "}
                  <code className="break-all text-xs">deb http://security.debian.org/debian-security {codename}-security main</code> to your apt sources, then run it again.
                </p>
              )}
              {ecosystem?.startsWith("Ubuntu") && codename && (
                <p className="mt-2 text-sm text-neutral-700 dark:text-neutral-300">
                  Ubuntu ships this fix in <code className="text-xs">{codename}-security</code>.
                </p>
              )}
            </>
          ) : isolate ? (
            <>
              <p className="text-xs font-medium uppercase tracking-wide text-neutral-500">Do this now</p>
              <p className="mt-1 text-sm font-medium">{isolate.action}</p>
              <p className="text-sm text-neutral-700 dark:text-neutral-300">{isolate.detail}</p>
              {patch && <p className="mt-2 text-sm text-neutral-700 dark:text-neutral-300">Then: {patch.action}</p>}
            </>
          ) : patch ? (
            <>
              <p className="text-xs font-medium uppercase tracking-wide text-neutral-500">Fix</p>
              <p className="mt-1 text-sm font-medium">{patch.action}</p>
            </>
          ) : null}
        </div>
      )}
      {report.warnings?.map((w, i) => (
        <p key={i} className="mt-3 rounded-lg bg-red-100 px-3 py-2 text-sm text-red-900 dark:bg-red-950 dark:text-red-200">{w.why}</p>
      ))}
    </div>
  );
}

function PackageCard({ name, findings, scanner }: { name: string; findings: PackageFinding[]; scanner: Verdict | null }) {
  const verdict = worst(findings.map((f) => f.verdict));
  const first = findings[0];
  const downgrades = findings.reduce((n, f) => n + (f.enforcement?.length ?? 0), 0);
  return (
    <article className="rounded-xl border border-neutral-200 bg-white p-4 shadow-sm dark:border-neutral-800 dark:bg-neutral-900">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="break-all font-mono text-base font-semibold">{name}</h3>
          <p className="mt-0.5 text-xs text-neutral-500">
            <span className="break-all font-mono">{first.installed_version}</span> from {first.version_source}
          </p>
        </div>
        <div className="flex flex-col items-start gap-1.5 text-xs sm:items-end">
          <div className="flex items-center gap-2"><span className="text-neutral-500">FirstWatch</span><Badge verdict={verdict} /></div>
          {scanner && <div className="flex items-center gap-2"><span className="text-neutral-500">Scanner</span><Badge verdict={scanner} size="sm" /></div>}
        </div>
      </div>
      <p className="mt-2 text-xs text-neutral-500">
        Safety checks: {INVARIANT_COUNT} invariants checked · {downgrades} downgrade{downgrades === 1 ? "" : "s"}
      </p>

      <div className="mt-3 space-y-4">
        {findings.map((f, i) => (
          <section key={`${f.cve}-${i}`} className="border-t border-neutral-100 pt-3 first:border-0 first:pt-0 dark:border-neutral-800">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-neutral-600 dark:text-neutral-400">{f.cve ?? "CVE not named"}</span>
              <Badge verdict={f.verdict} size="sm" />
            </div>
            {f.enforcement?.length
              ? f.enforcement.map((e, j) => (
                  <p key={j} className="text-sm leading-6 text-amber-900 dark:text-amber-200">
                    <span className="font-medium">A safety check downgraded this</span> from {VERDICT_LABELS[e.from as Verdict]} to {VERDICT_LABELS[e.to as Verdict]}. {e.why}
                  </p>
                ))
              : f.allow_reason && (
                  <p className="text-sm leading-6 text-neutral-700 dark:text-neutral-300">
                    <span className="font-medium text-neutral-900 dark:text-neutral-100">Why this stands:</span> {explain(f.allow_reason)}
                  </p>
                )}

            {f.citations?.length > 0 && (
              <div className="mt-2 space-y-1.5">
                {f.citations.map((c, j) => (
                  <details key={j} className="group rounded-lg border border-neutral-200 px-3 py-2 text-sm dark:border-neutral-800">
                    <summary className="cursor-pointer list-none text-neutral-800 marker:hidden dark:text-neutral-200">
                      <span className="mr-1 inline-block text-neutral-400 transition group-open:rotate-90">›</span>
                      {c.claim}
                      {c.verified === false && <span className="ml-2 text-xs text-red-700 dark:text-red-300">quote not found in source</span>}
                    </summary>
                    <blockquote className="mt-2 border-l-2 border-neutral-300 pl-3 text-neutral-600 dark:border-neutral-700 dark:text-neutral-400">{c.quote}</blockquote>
                    <p className="mt-1 break-all text-xs text-neutral-500">
                      {isUrl(c.source) ? <a href={c.source} target="_blank" rel="noreferrer" className="underline underline-offset-2">{c.source}</a> : c.source}
                    </p>
                  </details>
                ))}
              </div>
            )}

            {f.unverified?.length > 0 && (
              <ul className="mt-2 space-y-1 text-sm text-neutral-600 dark:text-neutral-400">
                {f.unverified.map((u, j) => (
                  <li key={j}>Needs {u.missing}: <code className="rounded bg-neutral-100 px-1 py-0.5 text-xs dark:bg-neutral-800">{u.how_to_get_it}</code></li>
                ))}
              </ul>
            )}
          </section>
        ))}
      </div>
    </article>
  );
}

export default function Triage({ examples, defaultExampleId, liveEnabled }: { examples: Example[]; defaultExampleId: string; liveEnabled: boolean }) {
  // Open on the default example, already running: a first-time visitor should see the point before reading anything.
  const initial = examples.find((e) => e.id === defaultExampleId) ?? null;
  const [runtime, setRuntime] = useState(initial?.runtime ?? "");
  const [config, setConfig] = useState<Record<string, string>>(initial?.config ?? {});
  const [exampleId, setExampleId] = useState<string | null>(initial?.id ?? null);
  const [running, setRunning] = useState(!!initial);
  const [log, setLog] = useState<LogLine[]>([]);
  const [report, setReport] = useState<FirstWatchReport | null>(null);
  const [baseline, setBaseline] = useState<FirstWatchReport | null>(null);
  const [ecosystem, setEcosystem] = useState<string | null>(null);
  const [recorded, setRecorded] = useState<Recorded | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [inputsOpen, setInputsOpen] = useState(false);
  const resultsRef = useRef<HTMLDivElement>(null);
  const started = useRef(false);

  const split = useMemo(() => splitRuntime(runtime), [runtime]);
  const example = examples.find((e) => e.id === exampleId) ?? null;

  type RunOpts = { runtime: string; config: Record<string, string>; exampleId: string | null; live: boolean };

  function run(opts: RunOpts) {
    setRunning(true);
    setLog([]);
    setReport(null);
    setBaseline(null);
    setRecorded(null);
    setNotice(null);
    setFailure(null);
    setInputsOpen(false);
    requestAnimationFrame(() => resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
    void stream(opts);
  }

  /** Fetch and apply the event stream. State only changes after the first await. */
  async function stream(opts: RunOpts) {
    const parts = splitRuntime(opts.runtime);
    const files: Record<string, string> = Object.fromEntries(
      Object.entries({ "os-release": parts["os-release"], "php-v.txt": parts["php-v.txt"], "dpkg.txt": parts["dpkg.txt"], ...opts.config }).filter(([, t]) => t.trim()),
    );
    const push = (l: LogLine | null) => l && setLog((prev) => [...prev, l]);
    try {
      const res = await fetch("/api/triage", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ files, exampleId: opts.exampleId, live: opts.live }),
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
          if (event.type === "facts") setEcosystem(((event.ecosystems as string[]) ?? [])[0] ?? null);
          if (event.type === "replay") setRecorded(event.recorded as Recorded);
          if (event.type === "live_unavailable") setNotice(String(event.message));
          if (event.type === "error") setFailure(String(event.message));
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

  const pickExample = (ex: Example) => {
    setRuntime(ex.runtime);
    setConfig(ex.config);
    setExampleId(ex.id);
    run({ runtime: ex.runtime, config: ex.config, exampleId: ex.id, live: false });
  };

  useEffect(() => {
    if (started.current || !initial) return;
    started.current = true;
    void stream({ runtime: initial.runtime, config: initial.config, exampleId: initial.id, live: false });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const rawUrl = useMemo(
    () => (report ? URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" })) : null),
    [report],
  );
  useEffect(() => () => { if (rawUrl) URL.revokeObjectURL(rawUrl); }, [rawUrl]);

  const scanner = baseline?.overall ?? null;
  const byPackage = new Map<string, PackageFinding[]>();
  for (const f of report?.findings ?? []) byPackage.set(f.package, [...(byPackage.get(f.package) ?? []), f]);
  const canRun = !!split["php-v.txt"] || !!split["dpkg.txt"] || Object.values(config).some((t) => t.trim());

  return (
    <div className="space-y-6">
      <section>
        <div className="flex flex-wrap gap-2">
          {examples.map((ex) => (
            <button
              key={ex.id}
              type="button"
              disabled={running}
              onClick={() => pickExample(ex)}
              className={`inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm transition disabled:opacity-60 ${
                exampleId === ex.id
                  ? "border-neutral-900 bg-neutral-900 text-white dark:border-neutral-100 dark:bg-neutral-100 dark:text-neutral-900"
                  : "border-neutral-300 hover:border-neutral-500 dark:border-neutral-700 dark:hover:border-neutral-500"
              }`}
            >
              <span className={`size-2 rounded-full ${DOT[ex.expected] ?? "bg-neutral-400"}`} aria-hidden />
              {ex.label}
            </button>
          ))}
        </div>
      </section>

      <details
        open={inputsOpen}
        onToggle={(e) => setInputsOpen((e.target as HTMLDetailsElement).open)}
        className="rounded-xl border border-neutral-200 p-4 dark:border-neutral-800"
      >
        <summary className="cursor-pointer text-sm font-medium">Edit inputs, or analyse your own server</summary>
        <div className="mt-4 space-y-4">
          <label className="block">
            <span className="text-sm text-neutral-700 dark:text-neutral-300">Run this on the server and paste the output:</span>
            <code className="mt-1 block break-all rounded-lg bg-neutral-100 px-3 py-2 text-xs dark:bg-neutral-900">{RUNTIME_COMMAND}</code>
            <textarea
              value={runtime}
              onChange={(e) => { setRuntime(e.target.value); setExampleId(null); }}
              rows={10}
              spellCheck={false}
              placeholder="Paste the output here"
              className="mt-2 w-full resize-y rounded-lg border border-neutral-300 bg-white p-2 font-mono text-xs leading-5 outline-none focus:border-neutral-500 dark:border-neutral-700 dark:bg-neutral-900"
            />
            <span className="mt-1 block text-xs text-neutral-500">
              Detected: os-release {split["os-release"] ? "✓" : "missing"} · php -v {split["php-v.txt"] ? "✓" : "missing"} · dpkg {split.packages} PHP package{split.packages === 1 ? "" : "s"}
            </span>
          </label>

          <details className="rounded-lg border border-neutral-200 p-3 dark:border-neutral-800">
            <summary className="cursor-pointer text-sm">Add config (optional, for mitigations)</summary>
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              {CONFIG_FILES.map((f) => (
                <label key={f.file} className="block">
                  <code className="text-xs text-neutral-700 dark:text-neutral-300">{f.label}</code>
                  <textarea
                    value={config[f.file] ?? ""}
                    onChange={(e) => { setConfig((c) => ({ ...c, [f.file]: e.target.value })); setExampleId(null); }}
                    rows={5}
                    spellCheck={false}
                    className="mt-1 w-full resize-y rounded-lg border border-neutral-300 bg-white p-2 font-mono text-xs leading-5 outline-none focus:border-neutral-500 dark:border-neutral-700 dark:bg-neutral-900"
                  />
                </label>
              ))}
            </div>
          </details>

          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              disabled={!canRun || running}
              onClick={() => run({ runtime, config, exampleId, live: false })}
              className="rounded-lg bg-neutral-900 px-4 py-2 text-sm font-medium text-white hover:bg-neutral-700 disabled:opacity-40 dark:bg-neutral-100 dark:text-neutral-900"
            >
              {exampleId ? "Replay this example" : "Run (scanner and parsing only)"}
            </button>
            {liveEnabled && (
              <button
                type="button"
                disabled={!canRun || running}
                onClick={() => run({ runtime, config, exampleId, live: true })}
                className="rounded-lg border border-neutral-400 px-4 py-2 text-sm font-medium hover:border-neutral-700 disabled:opacity-40 dark:border-neutral-600"
              >
                Run live
              </button>
            )}
          </div>
        </div>
      </details>

      <div ref={resultsRef} className="scroll-mt-6 space-y-4">
        {example && <p className="text-sm leading-6 text-neutral-700 dark:text-neutral-300">{example.blurb}</p>}
        {notice && (
          <p className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950/60 dark:text-amber-200">{notice}</p>
        )}
        {running && !report && <p className="animate-pulse text-sm text-neutral-500">Running…</p>}
        {!running && !report && (failure || baseline) && (
          <div className="rounded-xl border border-neutral-300 p-4 dark:border-neutral-700">
            {baseline && (
              <div className="flex items-center gap-2">
                <span className="text-sm text-neutral-600 dark:text-neutral-400">Version scanner</span>
                <Badge verdict={baseline.overall} />
              </div>
            )}
            {failure && <p className="mt-3 text-sm leading-6 text-neutral-800 dark:text-neutral-200">{failure}</p>}
          </div>
        )}

        {report && (
          <>
            <ResultBanner report={report} scanner={scanner} ecosystem={ecosystem} held={split.held} />
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-neutral-500">
              {recorded ? (
                <span>
                  Recorded live run · {recorded.at ? new Date(recorded.at).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "date unknown"} · {recorded.model}
                  {recorded.tokens ? ` · ${recorded.tokens.toLocaleString()} tokens` : ""}
                </span>
              ) : (
                <span>Live run</span>
              )}
              {recorded && liveEnabled && (
                <button type="button" disabled={running} onClick={() => run({ runtime, config, exampleId, live: true })} className="underline underline-offset-2 hover:text-neutral-800 dark:hover:text-neutral-200">
                  Run it live
                </button>
              )}
              {rawUrl && <a href={rawUrl} target="_blank" rel="noreferrer" className="underline underline-offset-2 hover:text-neutral-800 dark:hover:text-neutral-200">View raw report JSON</a>}
            </div>

            {[...byPackage].map(([name, fs]) => <PackageCard key={name} name={name} findings={fs} scanner={scanner} />)}

            {report.fixed_versions && report.fixed_versions.length > 0 && (
              <details className="rounded-xl border border-neutral-200 p-4 text-sm dark:border-neutral-800">
                <summary className="cursor-pointer font-medium">Patched versions per advisory</summary>
                <ul className="mt-2 space-y-2">
                  {report.fixed_versions.map((f) => (
                    <li key={f.cve}>
                      <span className="font-mono">{f.cve}</span>: {f.patched.join(", ")}{" "}
                      <a href={f.source} target="_blank" rel="noreferrer" className="break-all text-neutral-500 underline underline-offset-2">{f.ghsa ?? f.source}</a>
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </>
        )}

        {log.length > 0 && (
          <details open={running} className="rounded-xl border border-neutral-200 p-4 dark:border-neutral-800">
            <summary className="cursor-pointer text-sm font-medium">{running ? "Steps" : `Show the ${log.length} steps`}</summary>
            <ol className="mt-2 space-y-1 font-mono text-xs leading-5">
              {log.map((l, i) => <li key={i} className={`break-words ${TONE[l.tone]}`}>{l.text}</li>)}
            </ol>
          </details>
        )}
      </div>
    </div>
  );
}
