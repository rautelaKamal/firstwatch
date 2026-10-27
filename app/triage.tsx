"use client";

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import type { FirstWatchReport, PackageFinding } from "@/lib/agent";
import { RUNTIME_COMMAND, splitRuntime } from "@/lib/runtime";
import type { PackageAware, PackageAwareRow } from "@/lib/packageaware";
import { checkScope, SCOPE_LINE } from "@/lib/scope";
import { INVARIANTS, REASSURANCE, VERDICT_LABELS, type Verdict } from "@/lib/verdicts";

type Example = { id: string; label: string; blurb: string; expected: string; runtime: string; config: Record<string, string> };
type Event = { type: string; [key: string]: unknown };
type LogLine = { tone: "info" | "tool" | "ok" | "warn" | "error"; text: string };
type Recorded = { at: string | null; model: string; tokens: number | null };
type LiveMeta = { ms: number; tokens: number; model: string };
type WhatIfState = { memory: boolean; rlimit: boolean };
type Mode = "examples" | "own";

const duration = (ms: number) => {
  const s = Math.round(ms / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
};

/** The example's config with the what-if toggles applied. */
function applyWhatIf(config: Record<string, string>, w: WhatIfState): Record<string, string> {
  const out = { ...config };
  if (w.memory) {
    const lines = (out["php.ini"] ?? "").split("\n").filter((l) => !/^\s*memory_limit\s*=/.test(l));
    out["php.ini"] = [...lines, "memory_limit = -1"].join("\n").trim();
  }
  if (w.rlimit) out.Dockerfile = `${out.Dockerfile ?? ""}\nRUN ulimit -v 2097152`.trim();
  return out;
}

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

/** What a citation's evidence is, named by its source rather than by the claim it supports. */
function citationLabel(source: string, ecosystem: string | null): string {
  const s = source.trim();
  const ghsa = s.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i)?.[0];
  if (ghsa) return `Quote: ${ghsa}`;
  if (/php\.net/i.test(s)) return "Quote: php.net announcement";
  // The OSV check links each distribution's own tracker page.
  if (/security-tracker\.debian\.org/i.test(s)) return "Source: Debian security data via OSV";
  if (/ubuntu\.com\/security/i.test(s)) return "Source: Ubuntu security data via OSV";
  if (/check_distro_fix|osv/i.test(s)) return `Source: ${ecosystem?.split(":")[0] ?? "distribution"} security data via OSV`;
  if (/^NVD|nvd\.nist|fetch_cve/i.test(s)) return `Source: NVD record${s.match(/CVE-\d{4}-\d+/i) ? ` ${s.match(/CVE-\d{4}-\d+/i)![0]}` : ""}`;
  if (/version_in_range|compare_versions/i.test(s)) return "Source: version range check";
  if (/check_eol|endoflife/i.test(s)) return "Source: endoflife.date";
  if (/usn-/i.test(s)) return "Source: Ubuntu security notice";
  if (/^https?:\/\//i.test(s)) return `Source: ${new URL(s).hostname}`;
  return `Source: ${s}`;
}

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
  m = reason.match(/^Affected per OSV row (\S+) (\S+) (\S+) affected; mitigated by (\S+?)=(\S+), quoted from (\S+) and set at (\S+?); installed version read from (.+?)\.$/);
  if (m) {
    const [, eco, src, ver, setting, value, from, where] = m;
    const doc = from.match(/GHSA-[a-z0-9-]+/i)?.[0] ?? from;
    return `${eco.split(":")[0]}'s own security data lists ${src} ${ver} as still affected, but ${setting}=${value} is set (${where}), which ${doc} names as a mitigation. Exposure is reduced, not removed: patching is still the fix.`;
  }
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
    case "baseline": return { tone: "info", text: `Version-string check: ${VERDICT_LABELS[(e.report as FirstWatchReport).overall]} from "${s(e.version) || "no version"}"` };
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

/** What the two comparison rows are: a toggle under them, closed, so the outcome comes first. */
function ComparisonNote() {
  return (
    <details className="mt-2 text-xs leading-5 text-neutral-600 dark:text-neutral-400">
      <summary className="cursor-pointer select-none font-medium underline underline-offset-2">What is this comparison?</summary>
      <p className="mt-1">
        A version-string check compares one PHP version number to the advisory, the way
      banner-based scans and quick <code>php -v</code> checks do. The package-aware check is our own code-only version of what package scanners do: each
      installed dpkg version against the distribution&apos;s fix record. It is not the output of any of those tools.
      </p>
    </details>
  );
}

type Cell = { verdict: Verdict | null; note: string | null };

/** The package-aware answer for one FirstWatch verdict, or a dash where it has no way to say what FirstWatch says. */
function packageAwareCell(fw: Verdict | null, rows: PackageAwareRow[], fallback: string | null): Cell {
  if (!rows.length) return { verdict: null, note: fallback ?? "Nothing to compare." };
  const vs = rows.map((r) => r.verdict);
  const own: Verdict | null = vs.includes("AFFECTED") ? "AFFECTED" : vs.every((v) => v === "NOT_AFFECTED") ? "NOT_AFFECTED" : null;
  const alone = own ? `; by package version alone it says ${VERDICT_LABELS[own]}` : "";
  if (fw === "AFFECTED_MITIGATED") return { verdict: null, note: `It has no "exposure reduced" verdict${alone}.` };
  if (fw === "UNVERIFIED") return { verdict: null, note: `It has no "unverified" verdict${alone}.` };
  if (!own) return { verdict: null, note: rows.find((r) => !r.verdict)?.note ?? "Nothing to compare." };
  return { verdict: own, note: null };
}

/** Three rows, weakest method first: version-string check, package-aware check, FirstWatch. */
function ComparisonRows({ version, pkg, firstwatch, compact = false }: { version: Verdict | null; pkg: Cell | null; firstwatch: Verdict | null; compact?: boolean }) {
  const label = compact ? "text-xs text-neutral-500" : "text-sm text-neutral-600 dark:text-neutral-400";
  return (
    <dl className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-2">
      {version && (
        <>
          <dt className={label}>Version-string check</dt>
          <dd className="justify-self-end"><Badge verdict={version} size="sm" /></dd>
        </>
      )}
      {pkg && (
        <>
          <dt className={label}>
            Package-aware check
            <span className="block text-[11px] leading-4 text-neutral-500">dpkg + distro data, like Trivy or debsecan</span>
          </dt>
          <dd className="justify-self-end">{pkg.verdict ? <Badge verdict={pkg.verdict} size="sm" /> : <span className="px-2 text-neutral-500">—</span>}</dd>
          {!pkg.verdict && pkg.note && <dd className="col-span-2 -mt-1 text-xs leading-5 text-neutral-500">{pkg.note}</dd>}
        </>
      )}
      {firstwatch && (
        <>
          <dt className={`${label} font-medium text-neutral-900 dark:text-neutral-100`}>FirstWatch</dt>
          <dd className="justify-self-end"><Badge verdict={firstwatch} size={compact ? "md" : "lg"} /></dd>
        </>
      )}
    </dl>
  );
}

/** One package's package-aware rows, collapsed to a cell for the given FirstWatch verdict. */
const cellFor = (pa: PackageAware | null, fw: Verdict | null, pkg?: string): Cell | null =>
  pa ? packageAwareCell(fw, pkg ? pa.rows.filter((r) => r.package === pkg) : pa.rows, pa.note) : null;

/** For each package and CVE: the evidence that let the verdict stand, or the rule that downgraded it. */
function SafetyLedger({ report, defaultOpen }: { report: FirstWatchReport; defaultOpen: boolean }) {
  const downgrades = report.findings.reduce((n, f) => n + (f.enforcement?.length ?? 0), 0);
  return (
    <details open={defaultOpen} className="rounded-xl border border-neutral-300 p-4 dark:border-neutral-700">
      <summary className="cursor-pointer">
        <span className="text-sm font-semibold">Safety ledger</span>
        <span className="ml-2 text-xs text-neutral-500">{INVARIANT_COUNT} rules checked in code · {downgrades} downgrade{downgrades === 1 ? "" : "s"}</span>
      </summary>
      <p className="mt-2 text-xs leading-5 text-neutral-500">
        For each package and CVE: the evidence that let the verdict stand, or the rule that downgraded it. The rules can only make a verdict less reassuring.
      </p>
      <ul className="mt-3 space-y-3">
        {report.findings.map((f, i) => (
          <li key={`${f.package}-${f.cve}-${i}`} className="border-t border-neutral-200 pt-3 first:border-0 first:pt-0 dark:border-neutral-800">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className="break-all font-mono text-sm font-medium">{f.package}</span>
              <span className="font-mono text-xs text-neutral-500">{f.cve ?? "CVE not named"}</span>
              <Badge verdict={f.verdict} size="sm" />
            </div>
            {f.enforcement?.length ? (
              f.enforcement.map((e, j) => (
                <p key={j} className="mt-1 text-sm leading-6 text-amber-900 dark:text-amber-200">
                  <span className="font-medium">Downgraded by {e.invariant}</span> from {VERDICT_LABELS[e.from as Verdict]} to {VERDICT_LABELS[e.to as Verdict]}. {e.why}
                </p>
              ))
            ) : f.allow_reason ? (
              <p className="mt-1 text-sm leading-6 text-neutral-700 dark:text-neutral-300">
                <span className="font-medium text-neutral-900 dark:text-neutral-100">Stands because:</span> {explain(f.allow_reason)}
              </p>
            ) : (
              <p className="mt-1 text-sm text-neutral-500">No evidence was recorded for this verdict.</p>
            )}
          </li>
        ))}
      </ul>
    </details>
  );
}

/** The headline: how many engine packages are affected, why, and the exact next step. */
function ResultBanner({ report, scanner, pa, ecosystem, held }: { report: FirstWatchReport; scanner: Verdict | null; pa: PackageAware | null; ecosystem: string | null; held: string[] }) {
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
      <ComparisonRows version={scanner} pkg={cellFor(pa, report.overall)} firstwatch={report.overall} />
      {(scanner || pa) && <ComparisonNote />}
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

function PackageCard({ name, findings, scanner, pa, ecosystem }: { name: string; findings: PackageFinding[]; scanner: Verdict | null; pa: PackageAware | null; ecosystem: string | null }) {
  const verdict = worst(findings.map((f) => f.verdict));
  const first = findings[0];
  const downgrades = findings.reduce((n, f) => n + (f.enforcement?.length ?? 0), 0);
  return (
    <article className="rounded-xl border border-neutral-200 bg-white p-4 shadow-sm dark:border-neutral-800 dark:bg-neutral-900">
      <div className="min-w-0">
        <h3 className="break-all font-mono text-base font-semibold">{name}</h3>
        <p className="mt-0.5 text-xs text-neutral-500">
          <span className="break-all font-mono">{first.installed_version}</span> from {first.version_source}
        </p>
      </div>
      <div className="mt-3">
        <ComparisonRows version={scanner} pkg={cellFor(pa, verdict, name)} firstwatch={verdict} compact />
      </div>
      <p className="mt-2 text-xs text-neutral-500">
        Safety ledger: {INVARIANT_COUNT} rules checked · {downgrades} downgrade{downgrades === 1 ? "" : "s"}
      </p>

      <div className="mt-3 space-y-4">
        {findings.map((f, i) => (
          <section key={`${f.cve}-${i}`} className="border-t border-neutral-100 pt-3 first:border-0 first:pt-0 dark:border-neutral-800">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-neutral-600 dark:text-neutral-400">{f.cve ?? "CVE not named"}</span>
              <Badge verdict={f.verdict} size="sm" />
            </div>
            {f.citations?.length > 0 && (
              <div className="mt-2 space-y-1.5">
                {f.citations.map((c, j) => (
                  <details key={j} className="group rounded-lg border border-neutral-200 px-3 py-2 text-sm dark:border-neutral-800">
                    <summary className="cursor-pointer list-none text-neutral-800 marker:hidden dark:text-neutral-200">
                      <span className="mr-1 inline-block text-neutral-400 transition group-open:rotate-90">›</span>
                      {citationLabel(c.source, ecosystem)}
                      {c.verified === false && <span className="ml-2 text-xs text-red-700 dark:text-red-300">quote not found in source</span>}
                    </summary>
                    <p className="mt-2 text-neutral-700 dark:text-neutral-300">{c.claim}</p>
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

function Step({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <li className="flex gap-3">
      <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-neutral-900 text-xs font-semibold text-white dark:bg-neutral-100 dark:text-neutral-900">{n}</span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium">{title}</p>
        <div className="mt-2">{children}</div>
      </div>
    </li>
  );
}

export default function Triage({
  examples, defaultExampleId, sampleExampleId, liveEnabled, ipWindowMinutes,
}: { examples: Example[]; defaultExampleId: string; sampleExampleId: string; liveEnabled: boolean; ipWindowMinutes: number }) {
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
  const [liveRun, setLiveRun] = useState(false);
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [now, setNow] = useState(0);
  const [liveMeta, setLiveMeta] = useState<LiveMeta | null>(null);
  const [recordedReport, setRecordedReport] = useState<FirstWatchReport | null>(null);
  const [whatIf, setWhatIf] = useState<WhatIfState>({ memory: false, rlimit: false });
  const [whatIfResult, setWhatIfResult] = useState<{ label: string; changes: string[] } | null>(null);
  const [whatIfBusy, setWhatIfBusy] = useState(false);
  const [mode, setMode] = useState<Mode>("examples");
  const [ownText, setOwnText] = useState("");
  const [parsed, setParsed] = useState<string | null>(null);
  const [scannerFrom, setScannerFrom] = useState<string | null>(null);
  const [unsupported, setUnsupported] = useState<string | null>(null);
  const [pa, setPa] = useState<PackageAware | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const resultsRef = useRef<HTMLDivElement>(null);
  const started = useRef(false);
  // Set by a click; consumed once the result has rendered. Never set on first load.
  const scrollPending = useRef(false);

  const split = useMemo(() => splitRuntime(runtime), [runtime]);
  const ownSplit = useMemo(() => splitRuntime(ownText), [ownText]);
  const example = examples.find((e) => e.id === exampleId) ?? null;
  const sample = examples.find((e) => e.id === sampleExampleId) ?? null;
  // Unedited sample output replays the sample's recording instead of spending a live run.
  const usingSample = !!sample && ownText === sample.runtime;

  type RunOpts = { runtime: string; config: Record<string, string>; exampleId: string | null; live: boolean };

  function resetResults() {
    setLog([]);
    setReport(null);
    setBaseline(null);
    setRecorded(null);
    setNotice(null);
    setFailure(null);
    setLiveRun(false);
    setLiveMeta(null);
    setRecordedReport(null);
    setWhatIf({ memory: false, rlimit: false });
    setWhatIfResult(null);
    setParsed(null);
    setScannerFrom(null);
    setUnsupported(null);
    setPa(null);
  }

  function run(opts: RunOpts, { scroll = true }: { scroll?: boolean } = {}) {
    resetResults();
    setRunning(true);
    setRuntime(opts.runtime);
    setLiveRun(opts.live);
    setStartedAt(Date.now());
    setNow(Date.now());
    // Scrolling now would aim at a spot that moves when the inputs above collapse.
    scrollPending.current = scroll;
    void stream(opts);
  }

  /** Fetch and apply the event stream. State only changes after the first await. */
  async function stream(opts: RunOpts) {
    const parts = splitRuntime(opts.runtime);
    const files: Record<string, string> = Object.fromEntries(
      Object.entries({ "os-release": parts["os-release"], "php-v.txt": parts["php-v.txt"], "dpkg.txt": parts["dpkg.txt"], ...opts.config }).filter(([, t]) => t.trim()),
    );
    const push = (l: LogLine | null) => l && setLog((prev) => [...prev, l]);
    const t0 = Date.now();
    let liveModel = "";
    // One stream at a time: a new run or a mode switch stops the old one, and the server stops its model calls.
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    try {
      const res = await fetch("/api/triage", {
        signal: ctrl.signal,
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
          if (event.type === "baseline") {
            setBaseline(event.report as FirstWatchReport);
            setScannerFrom(event.version ? String(event.version) : null);
          }
          if (event.type === "facts") {
            setEcosystem(((event.ecosystems as string[]) ?? [])[0] ?? null);
            setParsed(String(event.summary ?? ""));
          }
          if (event.type === "unsupported") setUnsupported(String(event.message));
          if (event.type === "package_aware") setPa({ overall: (event.overall as PackageAware["overall"]) ?? null, rows: (event.rows as PackageAwareRow[]) ?? [], note: (event.note as string | null) ?? null });
          if (event.type === "replay") setRecorded(event.recorded as Recorded);
          if (event.type === "live_unavailable") setNotice(String(event.message));
          if (event.type === "error") setFailure(String(event.message));
          if (event.type === "start") liveModel = String(event.model ?? "");
          if (event.type === "model_switch") liveModel = String(event.to ?? liveModel);
          if (event.type === "final" && event.report) {
            setReport(event.report as FirstWatchReport);
            setRecordedReport(event.report as FirstWatchReport);
            if (opts.live) {
              const u = event.usage as { total?: number } | undefined;
              const d = event.digestUsage as { total?: number } | undefined;
              setLiveMeta({ ms: Number(event.ms ?? Date.now() - t0), tokens: (u?.total ?? 0) + (d?.total ?? 0), model: liveModel });
            }
          }
          push(describe(event));
        }
      }
    } catch (e) {
      if (ctrl.signal.aborted) return;
      push({ tone: "error", text: e instanceof Error ? e.message : String(e) });
    } finally {
      if (abortRef.current === ctrl) setRunning(false);
    }
  }

  function switchMode(next: Mode) {
    if (next === mode) return;
    setMode(next);
    if (next === "own") {
      abortRef.current?.abort();
      resetResults();
      setRunning(false);
      setExampleId(null);
      history.replaceState(null, "", "?check");
    } else {
      pickExample(examples.find((e) => e.id === exampleId) ?? initial ?? examples[0], { scroll: false });
    }
  }

  function check() {
    // The same rule the route applies: outside the scope there is a message, never a verdict.
    const scope = checkScope(ownText);
    if (!scope.ok) {
      abortRef.current?.abort();
      resetResults();
      setRunning(false);
      setUnsupported(scope.message);
      return;
    }
    setExampleId(usingSample ? sampleExampleId : null);
    run({ runtime: ownText, config: {}, exampleId: usingSample ? sampleExampleId : null, live: !usingSample && liveEnabled });
  }

  async function toggleWhatIf(next: WhatIfState) {
    setWhatIf(next);
    if (!next.memory && !next.rlimit) {
      setReport(recordedReport);
      setWhatIfResult(null);
      return;
    }
    if (!exampleId) return;
    setWhatIfBusy(true);
    const parts = splitRuntime(runtime);
    const files = Object.fromEntries(
      Object.entries({ "os-release": parts["os-release"], "php-v.txt": parts["php-v.txt"], "dpkg.txt": parts["dpkg.txt"], ...applyWhatIf(config, next) }).filter(([, t]) => t.trim()),
    );
    try {
      const res = await fetch("/api/whatif", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ exampleId, files }) });
      const body = (await res.json()) as { report?: FirstWatchReport; changes?: string[]; label?: string; error?: string };
      if (body.report) {
        setReport(body.report);
        setWhatIfResult({ label: body.label ?? "Re-evaluated by the safety engine · no model call", changes: body.changes ?? [] });
      } else {
        setWhatIfResult({ label: body.error ?? "Re-evaluation failed", changes: [] });
      }
    } catch (e) {
      setWhatIfResult({ label: e instanceof Error ? e.message : String(e), changes: [] });
    } finally {
      setWhatIfBusy(false);
    }
  }

  const pickExample = (ex: Example, { scroll = true }: { scroll?: boolean } = {}) => {
    setRuntime(ex.runtime);
    setConfig(ex.config);
    setExampleId(ex.id);
    // Keep the address shareable: ?example=a opens this case for anyone with the link.
    history.replaceState(null, "", `?example=${ex.id.split("-")[0]}`);
    run({ runtime: ex.runtime, config: ex.config, exampleId: ex.id, live: false }, { scroll });
  };

  // A ticking clock while a live run streams, so a long rate-limit wait never looks like a hang.
  useEffect(() => {
    if (!running || !liveRun) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [running, liveRun]);

  // Bring the example sentence and verdict box to the top once a clicked run has a result.
  useEffect(() => {
    if (!report || !scrollPending.current) return;
    scrollPending.current = false;
    requestAnimationFrame(() => resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
  }, [report]);

  useEffect(() => {
    if (started.current || !initial) return;
    started.current = true;
    // A reload should open at the top, on the headline, not where the last visit left off.
    if ("scrollRestoration" in history) history.scrollRestoration = "manual";
    window.scrollTo(0, 0);
    // A deep link (?example=a, or the full case id) opens that case instead of the default, without scrolling.
    const wanted = new URLSearchParams(window.location.search).get("example")?.trim().toLowerCase();
    const linked = wanted ? examples.find((e) => e.id === wanted || e.id.startsWith(`${wanted}-`)) : undefined;
    // ?check opens the check-your-own-server steps, with nothing running.
    if (new URLSearchParams(window.location.search).has("check")) {
      queueMicrotask(() => {
        setMode("own");
        setRunning(false);
      });
      return;
    }
    if (linked && linked.id !== initial.id) {
      queueMicrotask(() => pickExample(linked, { scroll: false }));
      return;
    }
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

  return (
    <div className="space-y-6">
      <div role="group" aria-label="Choose what to do" className="grid grid-cols-2 gap-2">
        {([["examples", "See how it works"], ["own", "Check your own server"]] as const).map(([m, label]) => (
          <button
            key={m}
            type="button"
            aria-pressed={mode === m}
            onClick={() => switchMode(m)}
            className={`rounded-xl border px-3 py-3 text-sm font-medium transition ${
              mode === m
                ? "border-neutral-900 bg-neutral-900 text-white dark:border-neutral-100 dark:bg-neutral-100 dark:text-neutral-900"
                : "border-neutral-300 hover:border-neutral-500 dark:border-neutral-700 dark:hover:border-neutral-500"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {mode === "examples" && (
        <section className="space-y-3">
          <p className="text-sm leading-6 text-neutral-700 dark:text-neutral-300">
            Pick an example, then compare a version-string check and a package-aware check with what FirstWatch finds, and why.
          </p>
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
      )}

      {mode === "own" && (
        <section className="space-y-5 rounded-xl border border-neutral-200 p-4 dark:border-neutral-800">
          <p className="text-sm font-medium">{SCOPE_LINE}</p>
          <ol className="space-y-5">
            <Step n={1} title="Run this one command on the server">
              <div className="flex items-start gap-2 rounded-lg bg-neutral-100 px-3 py-2 dark:bg-neutral-900">
                <code className="min-w-0 flex-1 break-words text-xs leading-5">{RUNTIME_COMMAND}</code>
                <CopyButton text={RUNTIME_COMMAND} />
              </div>
              <p className="mt-1 text-xs text-neutral-500">It only reads: the distribution, the PHP version, and the installed PHP packages.</p>
            </Step>
            <Step n={2} title="Paste its output">
              <textarea
                value={ownText}
                onChange={(e) => setOwnText(e.target.value)}
                rows={8}
                spellCheck={false}
                aria-label="Command output"
                placeholder="Paste the whole output here"
                className="w-full resize-y rounded-lg border border-neutral-300 bg-white p-2 font-mono text-xs leading-5 outline-none focus:border-neutral-500 dark:border-neutral-700 dark:bg-neutral-900"
              />
              <div className="mt-1 flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs text-neutral-500">
                  Detected: os-release {ownSplit["os-release"] ? "✓" : "missing"} · php -v {ownSplit["php-v.txt"] ? "✓" : "missing"} · {ownSplit.packages} PHP package{ownSplit.packages === 1 ? "" : "s"}
                </span>
                {sample && (
                  <button type="button" onClick={() => setOwnText(sample.runtime)} className="text-xs text-neutral-700 underline underline-offset-2 hover:text-neutral-900 dark:text-neutral-300 dark:hover:text-neutral-100">
                    Try with sample output
                  </button>
                )}
              </div>
            </Step>
            <Step n={3} title="Check">
              <button
                type="button"
                disabled={!ownText.trim() || running}
                onClick={check}
                className="rounded-lg bg-neutral-900 px-5 py-2 text-sm font-medium text-white hover:bg-neutral-700 disabled:opacity-40 dark:bg-neutral-100 dark:text-neutral-900"
              >
                {running ? "Checking…" : "Check"}
              </button>
              <p className="mt-2 text-xs leading-5 text-neutral-500">
                {usingSample
                  ? `This is sample output from the "${sample?.label}" example, so Check shows its recorded run. No model call.`
                  : liveEnabled
                    ? "The two code-only checks and parsing appear within seconds. The AI check follows and takes 2–4 minutes."
                    : "The two code-only checks and parsing appear within seconds. The AI check is switched off on this deployment."}
              </p>
            </Step>
          </ol>
          <p className="border-t border-neutral-100 pt-3 text-xs leading-5 text-neutral-500 dark:border-neutral-800">
            Privacy: FirstWatch doesn&apos;t save or log what you paste. The AI check sends the distribution and PHP package versions to OSV and to the model
            provider (Groq), and keeps your IP address for {ipWindowMinutes} minutes to enforce its rate limit.
          </p>
        </section>
      )}

      <div ref={resultsRef} className="scroll-mt-6 space-y-4">
        {mode === "examples" && example && <p className="text-sm leading-6 text-neutral-700 dark:text-neutral-300">{example.blurb}</p>}
        {unsupported && (
          <section className="rounded-xl border border-neutral-300 bg-neutral-50 p-4 dark:border-neutral-700 dark:bg-neutral-900">
            <p className="text-sm font-medium">No verdict</p>
            <p className="mt-1 text-sm leading-6 text-neutral-800 dark:text-neutral-200">{unsupported}</p>
          </section>
        )}
        {notice && (
          <p className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950/60 dark:text-amber-200">{notice}</p>
        )}
        {running && !report && !liveRun && <p className="animate-pulse text-sm text-neutral-500">Loading the recorded run…</p>}
        {baseline && !report && (liveRun || !running) && (
          <section className="rounded-xl border border-neutral-300 p-4 dark:border-neutral-700">
            <p className="text-xs font-medium uppercase tracking-wide text-neutral-500">Instant · code only</p>
            <div className="mt-2">
              <ComparisonRows version={baseline.overall} pkg={pa ? { verdict: pa.overall, note: pa.overall ? null : pa.note ?? pa.rows.find((r) => !r.verdict)?.note ?? null } : null} firstwatch={null} />
              <ComparisonNote />
              <p className="mt-1 text-xs text-neutral-500">Version-string check read &quot;{scannerFrom ?? "no version"}&quot;.</p>
            </div>
            {parsed && <p className="mt-2 text-sm leading-6 text-neutral-700 dark:text-neutral-300">Parsed: {parsed}</p>}
            {failure && <p className="mt-3 text-sm leading-6 text-neutral-800 dark:text-neutral-200">{failure}</p>}
            {mode === "own" && !running && !liveRun && !notice && !failure && (
              <p className="mt-3 text-sm leading-6 text-neutral-800 dark:text-neutral-200">
                No FirstWatch verdict yet: that needs the AI check, which is switched off on this deployment. The rows above are the two code-only comparisons.
              </p>
            )}
          </section>
        )}
        {!baseline && !running && failure && (
          <p className="rounded-xl border border-neutral-300 p-4 text-sm leading-6 text-neutral-800 dark:border-neutral-700 dark:text-neutral-200">{failure}</p>
        )}
        {running && liveRun && (
          <section className="rounded-xl border border-sky-300 bg-sky-50 p-4 dark:border-sky-900 dark:bg-sky-950/40">
            <p className="text-sm font-medium text-sky-900 dark:text-sky-200">
              AI check in progress · {startedAt ? `${Math.floor((now - startedAt) / 60000)}:${String(Math.floor(((now - startedAt) % 60000) / 1000)).padStart(2, "0")}` : "0:00"}
              <span className="ml-2 font-normal text-sky-800/80 dark:text-sky-300/80">Takes 2–4 minutes: requests are paced to the free tier&apos;s rate limit.</span>
            </p>
            <ol className="mt-3 space-y-1 font-mono text-xs leading-5">
              {log.length === 0 && <li className="animate-pulse text-neutral-500">Connecting…</li>}
              {log.map((l, i) => <li key={i} className={`break-words ${TONE[l.tone]}`}>{l.text}</li>)}
            </ol>
          </section>
        )}
        {report && (
          <>
            <ResultBanner report={report} scanner={scanner} pa={pa} ecosystem={ecosystem} held={split.held} />
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-neutral-500">
              {whatIfResult ? (
                <span className="font-medium text-sky-800 dark:text-sky-300">{whatIfResult.label}</span>
              ) : recorded ? (
                <span>
                  Recorded live run · {recorded.at ? new Date(recorded.at).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "date unknown"} · {recorded.model}
                  {recorded.tokens ? ` · ${recorded.tokens.toLocaleString()} tokens` : ""}
                </span>
              ) : liveMeta ? (
                <span>
                  Live run · {duration(liveMeta.ms)}
                  {liveMeta.model ? ` · ${liveMeta.model}` : ""} · {liveMeta.tokens.toLocaleString()} tokens
                </span>
              ) : (
                <span>Run</span>
              )}
              {recorded && liveEnabled && mode === "examples" && (
                <button
                  type="button"
                  disabled={running}
                  onClick={() => run({ runtime, config, exampleId, live: true })}
                  className="rounded-lg border border-neutral-400 px-3 py-1 text-xs font-medium text-neutral-800 hover:border-neutral-700 disabled:opacity-40 dark:border-neutral-600 dark:text-neutral-200"
                >
                  Run live (≈2 min)
                </button>
              )}
              {rawUrl && <a href={rawUrl} target="_blank" rel="noreferrer" className="underline underline-offset-2 hover:text-neutral-800 dark:hover:text-neutral-200">View raw report JSON</a>}
            </div>

            <SafetyLedger key={`${exampleId}-${report.assessed_at}`} report={report} defaultOpen={!!exampleId?.startsWith("g-")} />

            {recorded && exampleId && mode === "examples" && (
              <section className="rounded-xl border border-neutral-200 p-4 dark:border-neutral-800">
                <h3 className="text-sm font-medium">What if the configuration changed?</h3>
                <p className="mt-1 text-xs text-neutral-500">Re-checked instantly by the same safety engine, against this run&apos;s recorded evidence. No model call.</p>
                <div className="mt-3 space-y-2 text-sm">
                  <label className="flex items-start gap-2">
                    <input type="checkbox" className="mt-0.5 size-4" checked={whatIf.memory} disabled={whatIfBusy} onChange={(e) => toggleWhatIf({ ...whatIf, memory: e.target.checked })} />
                    <span>Set <code className="text-xs">memory_limit = -1</code> in php.ini <span className="text-neutral-500">(GHSA-w8hw&apos;s main configuration mitigation)</span></span>
                  </label>
                  <label className="flex items-start gap-2">
                    <input type="checkbox" className="mt-0.5 size-4" checked={whatIf.rlimit} disabled={whatIfBusy} onChange={(e) => toggleWhatIf({ ...whatIf, rlimit: e.target.checked })} />
                    <span>Cap memory with <code className="text-xs">ulimit -v</code> (RLIMIT_AS) in the Dockerfile <span className="text-neutral-500">(the advisory says not to)</span></span>
                  </label>
                </div>
                {whatIfResult && (
                  <ul className="mt-3 space-y-0.5 text-xs text-neutral-700 dark:text-neutral-300">
                    {whatIfResult.changes.length ? whatIfResult.changes.map((c, i) => <li key={i}>{c}</li>) : <li>No verdict changed.</li>}
                  </ul>
                )}
              </section>
            )}

            {[...byPackage].map(([name, fs]) => <PackageCard key={name} name={name} findings={fs} scanner={scanner} pa={pa} ecosystem={ecosystem} />)}

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

        {log.length > 0 && !(running && liveRun) && (
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
