/**
 * What if the configuration changed? Re-evaluate a recorded run in code only.
 *
 * The model's work (which packages, which CVEs, what it found) stays as
 * recorded. Only the toggled settings change: the edited files are parsed
 * again, a mitigation is claimed where the finding's own CVE advisory states it
 * and the stack now sets it (or dropped where the stack no longer does), and
 * the same safety engine that checks live runs decides what survives. No model
 * call, so the same inputs always give the same report.
 *
 * Server only: reads the committed cache seed.
 */

import { annotate, emptyLedger, enforceInvariants, type FirstWatchReport, type Ledger, type PackageFinding, type SavedLedger } from "./agent";
import { cacheEntries, cachedAdvisoryNow, cachedCveNow } from "./cache";
import type { AdvisoryDigest } from "./digest";
import { parse_stack, type StackFiles } from "./tools";
import { VERDICT_LABELS, type Verdict } from "./verdicts";

/** The settings the what-if toggles may change. Others keep their recorded mitigations. */
export const WHATIF_SETTINGS = ["memory_limit"];

const normaliseIni = (v: string) => {
  const x = v.trim().replace(/^["']|["']$/g, "").toLowerCase();
  if (["0", "off", "false", "no"].includes(x)) return "0";
  if (["1", "on", "true", "yes"].includes(x)) return "1";
  return x;
};

/** The digests for these CVEs, from the cache or the committed seed. */
function digestsFor(cves: string[]): AdvisoryDigest[] {
  const byUrl = new Map<string, AdvisoryDigest>();
  for (const d of cacheEntries<AdvisoryDigest>("digest-v3-")) {
    if (d?.url && (!d.cve || cves.includes(d.cve))) byUrl.set(d.url, d);
  }
  return [...byUrl.values()];
}

/** The ledger the engine checks against: saved tool results, plus facts and fetched text rebuilt from files and cache. */
function rebuildLedger(saved: SavedLedger, files: StackFiles, digests: AdvisoryDigest[]): Ledger {
  const parsed = parse_stack(files);
  const ledger = emptyLedger(parsed.ok ? parsed.facts : []);
  ledger.cves = saved.cves;
  ledger.distro = saved.distro.map((d) => ({ ...d }));
  ledger.ranges = saved.ranges.map((r) => ({ ...r, cves: r.cves ? [...r.cves] : undefined }));
  for (const id of saved.cves) {
    const rec = cachedCveNow(id);
    if (rec) ledger.fetched.push({ source: `NVD ${id}`, text: JSON.stringify(rec), cve: id });
  }
  for (const d of digests) {
    const page = cachedAdvisoryNow(d.url);
    if (page) ledger.fetched.push({ source: d.url, text: page.text, cve: d.cve });
  }
  return ledger;
}

/** Sentences the engine appends to a summary, removed so they are not appended twice. */
function baseSummary(summary: string): string {
  return summary
    .replace(/ Also installed: [^]*?covered by the SAPI verdicts\)\./, "")
    .replace(/ CVE-\d{4}-\d+ \([^)]*\) and CVE-\d{4}-\d+ \([^)]*\) list identical patched versions: [^.]*(?:\.\d+)*[^.]*\./, "")
    .replace(/ The CVEs have different patched versions: [^]*?\./, "")
    .replace(/ Warning: [^]*?increases risk\./, "")
    .trim();
}

const isSynthesized = (f: PackageFinding) => f.decided_by?.method === "none" && /^No finding was produced/.test(f.decided_by.detail ?? "");

export type WhatIf = {
  report: FirstWatchReport;
  /** One line per verdict or warning that changed against the recording. */
  changes: string[];
};

export function reevaluate(recorded: FirstWatchReport, saved: SavedLedger, files: StackFiles): WhatIf {
  const digests = digestsFor(saved.cves);
  const ledger = rebuildLedger(saved, files, digests);
  const ini = new Map(ledger.facts.filter((f) => f.field.startsWith("ini.")).map((f) => [f.field.slice(4), f.value]));

  const findings = recorded.findings
    .filter((f) => !isSynthesized(f)) // I6 recreates these
    .map((f): PackageFinding => {
      const { enforcement: _e, allow_reason: _a, fixed_in: _x, ...base } = f;
      void _e; void _a; void _x;
      // Mitigations for the toggled settings, as this finding's own CVE advisory states them.
      const stated = digests
        .filter((d) => d.cve && d.cve === f.cve)
        .flatMap((d) =>
          d.items
            .filter((i) => i.kind === "mitigation" && WHATIF_SETTINGS.includes(String(i.setting)) && String(i.value ?? "").trim())
            .map((i) => ({ setting: String(i.setting), value: String(i.value), quote: i.quote, source: d.url })),
        );
      const inStack = stated.filter((m) => ini.has(m.setting) && normaliseIni(ini.get(m.setting)!) === normaliseIni(m.value));
      const kept = (f.mitigations ?? []).filter((m) => !WHATIF_SETTINGS.includes(m.setting));
      const mitigations = [...kept, ...inStack];
      let verdict = f.verdict;
      // A claim only: the engine below decides whether it stands.
      if (verdict === "AFFECTED" && inStack.length) verdict = "AFFECTED_MITIGATED";
      if (verdict === "AFFECTED_MITIGATED" && !mitigations.length) verdict = "AFFECTED";
      return { ...base, mitigations, verdict };
    });

  const input: FirstWatchReport = {
    ...recorded,
    summary: baseSummary(recorded.summary),
    findings,
    corrections: [],
    warnings: undefined,
    citation_issues: undefined,
    enforcement_log: undefined,
  };
  const { report: enforced } = enforceInvariants(input, ledger);
  const report = annotate(enforced, ledger, digests);

  const key = (f: PackageFinding) => `${f.package}|${f.cve ?? ""}`;
  const label = (v: Verdict) => VERDICT_LABELS[v] ?? v;
  const before = new Map(recorded.findings.map((f) => [key(f), f.verdict]));
  const changes: string[] = [];
  for (const f of report.findings) {
    const was = before.get(key(f));
    if (was && was !== f.verdict) changes.push(`${f.package}${f.cve ? ` (${f.cve})` : ""}: ${label(was)} → ${label(f.verdict)}`);
  }
  if (recorded.overall !== report.overall) changes.push(`Overall: ${label(recorded.overall)} → ${label(report.overall)}`);
  const warned = (r: FirstWatchReport) => new Set((r.warnings ?? []).map((w) => `${w.setting}@${w.where}`));
  for (const w of warned(report)) if (!warned(recorded).has(w)) changes.push(`Warning added: ${w.split("@")[0]} is set (${w.split("@")[1]}), which the advisory says increases risk`);
  for (const w of warned(recorded)) if (!warned(report).has(w)) changes.push(`Warning cleared: ${w.split("@")[0]}`);
  return { report, changes };
}
