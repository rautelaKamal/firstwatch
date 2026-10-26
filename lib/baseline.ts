/**
 * The NVD-only baseline: what a version scanner does, in code, for free.
 *
 * It reads the one version string the host reports (php -v, or failing that
 * the image tag), takes its upstream part, and tests it against NVD's php/php
 * ranges. No distro data, no package split, no model. This is the thing
 * FirstWatch has to beat, so it must be honest and deterministic.
 */

import type { FirstWatchReport, Verdict } from "./agent";
import { cachedCve } from "./cache";
import { parse_stack, version_in_range, type Fact, type StackFiles } from "./tools";

/** The single version string a scanner would read from this stack. */
export function scannerVersion(facts: Fact[]): { version: string; from: string } | null {
  const pick = facts.find((f) => f.field === "php.version" && f.kind === "runtime") ?? facts.find((f) => f.field === "php.version");
  return pick ? { version: pick.value, from: `${pick.file}:${pick.line}` } : null;
}

export function baselineVerdict(
  version: string | null,
  ranges: string[],
): { verdict: Verdict; upstream: string | null; matched: string | null } {
  // "8.1.2-1ubuntu2.28" -> "8.1.2": exactly the information loss that makes scanners wrong.
  const upstream = version?.match(/^\d+\.\d+(?:\.\d+)?/)?.[0] ?? null;
  if (!upstream || !ranges.length) return { verdict: "UNVERIFIED", upstream, matched: null };
  for (const range of ranges) {
    const r = version_in_range(upstream, range);
    if (r.ok && r.inRange) return { verdict: "AFFECTED", upstream, matched: range };
  }
  return { verdict: "NOT_AFFECTED", upstream, matched: null };
}

export async function runBaseline(input: {
  files?: StackFiles;
  cve: string;
  target: string;
  /** Inject ranges to run offline; otherwise they come from the cached NVD record. */
  ranges?: string[];
}): Promise<{ report: FirstWatchReport; version: string | null; upstream: string | null; ms: number; note: string }> {
  const started = Date.now();
  const parsed = input.files ? parse_stack(input.files) : null;
  const seen = parsed?.ok ? scannerVersion(parsed.facts) : null;

  let ranges = input.ranges ?? [];
  let cvss: string | null = null;
  let score: number | null = null;
  let note = "";
  if (!input.ranges) {
    const rec = await cachedCve(input.cve);
    if (rec.ok && "found" in rec && rec.found) {
      ranges = rec.affected.filter((a) => a.product === "php/php").map((a) => a.range);
      cvss = rec.severity?.scale ?? null;
      score = rec.severity?.score ?? null;
    } else {
      note = rec.ok ? `NVD has no record of ${input.cve}` : rec.error;
    }
  }

  const { verdict, upstream, matched } = baselineVerdict(seen?.version ?? null, ranges);
  const report: FirstWatchReport = {
    schema_version: 2,
    cve: input.cve,
    target: input.target,
    assessed_at: new Date().toISOString(),
    overall: verdict,
    summary: matched
      ? `PHP ${upstream} is inside NVD range "${matched}".`
      : upstream
        ? `PHP ${upstream} is outside every NVD php/php range.`
        : "No PHP version string found.",
    findings: [
      {
        package: "php",
        installed_version: seen?.version ?? "unknown",
        version_source: seen?.from.includes("php-v") ? "php -v" : seen ? "image-tag" : "unknown",
        sapi: null,
        verdict,
        decided_by: {
          method: upstream ? "version_in_range" : "none",
          detail: matched ? `${upstream} is inside "${matched}"` : upstream ? `${upstream} matched no range` : "no version string",
        },
        exploitation_confidence: "not-applicable",
        severity: { cvss, score, note: "" },
        citations: matched ? [{ claim: "Inside an NVD affected range", quote: matched, source: `NVD ${input.cve}` }] : [],
        mitigations: [],
        eol: null,
        remediation: [],
        unverified: upstream ? [] : [{ missing: "A PHP version", why_it_matters: "Nothing to compare", how_to_get_it: "php -v" }],
      },
    ],
  };
  return { report, version: seen?.version ?? null, upstream, ms: Date.now() - started, note };
}
