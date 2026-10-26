/**
 * Score every cached digest against eval/digest-answer-key.json.
 *
 * Hard failures: an advisory's code-parsed fields (CVE id, ranges, patched
 * versions) not reproduced exactly, or any fact the key marks as not stated
 * (cgi, cli, 8.1, backports) attributed to an advisory that does not state it.
 * Prose recall is reported; it measures the model, and a low number is a
 * finding, not a broken build.
 *
 *   npm test   (skips advisories that have not been digested yet)
 */

import { readFileSync } from "node:fs";

import { cachedDigests, formatRecall, scoreDigest, type AnswerKey } from "../lib/recall";

const key = JSON.parse(readFileSync("eval/digest-answer-key.json", "utf8")) as AnswerKey;
const digests = cachedDigests();
const STRUCTURED = ["cve", "ranges", "fixed"];
let failures = 0;
let scored = 0;

for (const [url, entry] of Object.entries(key.advisories)) {
  const d = digests.find((x) => x.url === url);
  if (!d) {
    console.log(`skip ${url}: not digested yet (run the eval to build it)`);
    continue;
  }
  scored++;
  const r = scoreDigest(d, entry);
  console.log(`\n${url}\n  recall ${formatRecall(r)}`);
  for (const c of r.checks.filter((x) => !x.found)) console.log(`  missing ${c.category}: ${c.expected}`);
  const structuralMisses = r.checks.filter((c) => STRUCTURED.includes(c.category) && !c.found);
  if (structuralMisses.length) {
    failures++;
    console.log(`  FAIL ${structuralMisses.length} code-parsed field(s) missing`);
  }
  if (r.violations.length) {
    failures++;
    for (const v of r.violations) console.log(`  FAIL not stated by this advisory: ${v}`);
  }
}

console.log(`\n${scored} digest(s) scored, ${failures ? `${failures} FAILED` : "no hard failures"}`);
process.exit(failures ? 1 : 0);
