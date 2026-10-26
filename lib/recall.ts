/**
 * Digest recall: score a digest against a hand-verified answer key.
 *
 * The digest is the only view of an advisory the agent gets, so a fact it drops
 * is a fact the agent cannot reason about. This measures what survived, per
 * category, and flags any fact the key says the advisory does not state that a
 * digest or report attributes to it anyway.
 */

import type { FirstWatchReport } from "./agent";
import { cacheEntries } from "./cache";
import type { AdvisoryDigest } from "./digest";
import { normaliseProse } from "./tools";

export type KeyEntry = {
  cve?: string;
  ranges?: string[];
  fixed?: string[];
  sapi?: Record<string, string>;
  mitigations_partial?: string[];
  anti_mitigations?: string[];
  complete_fix_phrase?: string;
  no_generic_config_fix_phrase?: string;
  backport_phrase?: string;
  not_stated?: string[];
};
export type AnswerKey = { advisories: Record<string, KeyEntry> };

export type Recall = {
  url: string;
  checks: { category: string; expected: string; found: boolean }[];
  byCategory: Record<string, { found: number; total: number }>;
  found: number;
  total: number;
  violations: string[];
};

// The key quotes from a rendered page, so *emphasis* markers are not part of the text.
const norm = (s: string) => normaliseProse(s.replace(/\*/g, "")).toLowerCase();
const overlaps = (a: string, b: string) => norm(a).includes(norm(b)) || norm(b).includes(norm(a));

const SAPI_ALIAS: [RegExp, string][] = [
  [/mod_php|apache/i, "mod_php"],
  [/franken/i, "frankenphp"],
  [/lsapi|litespeed/i, "lsapi"],
  [/fpm/i, "fpm"],
  [/php-cgi|\bcgi\b/i, "cgi"],
  [/\bcli\b/i, "cli"],
];
const canonSapi = (s: string) => SAPI_ALIAS.find(([re]) => re.test(s))?.[1] ?? s.toLowerCase();

/** What "the advisory states X" looks like for each not-stated fact. */
const NOT_STATED: Record<string, RegExp> = {
  cgi: /php-cgi|\bcgi\b/i,
  cli: /\bcli\b/i,
  "8.1": /(?<![\d.])8\.1(?![\d])/,
  backport: /backport/i,
};

export function scoreDigest(d: AdvisoryDigest, key: KeyEntry): Recall {
  const checks: Recall["checks"] = [];
  const add = (category: string, expected: string, found: boolean) => checks.push({ category, expected, found });
  const of = (kind: string) => d.items.filter((i) => i.kind === kind);
  const text = (i: AdvisoryDigest["items"][number]) => `${i.setting ?? ""} ${i.quote}`;

  if (key.cve) add("cve", key.cve, d.cve === key.cve);
  for (const r of key.ranges ?? []) add("ranges", r, of("affected").some((i) => norm(String(i.range)) === norm(r)));
  for (const v of key.fixed ?? []) add("fixed", v, of("fixed").some((i) => i.fixed_version === v));
  for (const [sapi, phrase] of Object.entries(key.sapi ?? {})) {
    add("sapi", sapi, of("sapi").some((i) => canonSapi(String(i.sapi)) === sapi && overlaps(i.quote, phrase)));
  }
  for (const m of key.mitigations_partial ?? []) add("mitigations", m, of("mitigation").some((i) => norm(text(i)).includes(norm(m))));
  for (const m of key.anti_mitigations ?? []) add("anti_mitigations", m, of("anti_mitigation").some((i) => norm(text(i)).includes(norm(m))));
  for (const phrase of [key.complete_fix_phrase, key.no_generic_config_fix_phrase].filter((p): p is string => !!p)) {
    add("notes", phrase, d.items.some((i) => overlaps(i.quote, phrase)));
  }
  if (key.backport_phrase) add("backport", key.backport_phrase, of("backport").some((i) => overlaps(i.quote, key.backport_phrase!)));

  const violations: string[] = [];
  for (const fact of key.not_stated ?? []) {
    const re = NOT_STATED[fact] ?? new RegExp(fact, "i");
    for (const i of d.items) {
      const said = [i.sapi, i.setting, i.point, i.wording, i.branches?.join(" "), i.quote].filter(Boolean).join(" ");
      if (re.test(said)) violations.push(`digest attributes "${fact}" to ${d.url}: ${i.kind} "${said.slice(0, 120)}"`);
    }
  }

  const byCategory: Recall["byCategory"] = {};
  for (const c of checks) {
    byCategory[c.category] ??= { found: 0, total: 0 };
    byCategory[c.category].total++;
    if (c.found) byCategory[c.category].found++;
  }
  return { url: d.url, checks, byCategory, found: checks.filter((c) => c.found).length, total: checks.length, violations };
}

/** Report citations that attribute a not-stated fact to an advisory that does not state it. */
export function reportViolations(report: FirstWatchReport, key: AnswerKey): string[] {
  const out: string[] = [];
  for (const [url, entry] of Object.entries(key.advisories)) {
    for (const fact of entry.not_stated ?? []) {
      const re = NOT_STATED[fact] ?? new RegExp(fact, "i");
      for (const f of report.findings) {
        for (const c of f.citations ?? []) {
          if (c.source?.includes(url.replace(/^https?:\/\//, "")) && re.test(`${c.claim} ${c.quote}`)) {
            out.push(`${f.package}${f.cve ? ` (${f.cve})` : ""} cites "${fact}" to ${url}: "${c.claim}"`);
          }
        }
      }
    }
  }
  return out;
}

/** The current-version digests in the cache, newest per URL. */
export function cachedDigests(): AdvisoryDigest[] {
  const byUrl = new Map<string, AdvisoryDigest>();
  for (const d of cacheEntries<AdvisoryDigest>("digest-v3-")) if (d?.url) byUrl.set(d.url, d);
  return [...byUrl.values()];
}

export function formatRecall(r: Recall): string {
  const cats = Object.entries(r.byCategory).map(([k, v]) => `${k} ${v.found}/${v.total}`).join(", ");
  return `${r.found}/${r.total} (${Math.round((100 * r.found) / Math.max(1, r.total))}%): ${cats}`;
}
