/**
 * Rebuild the saved ledger for recordings made before runs saved their own.
 *
 * Re-runs the same code tools the agent called, on the packages, versions and
 * CVEs the recorded report names: check_distro_fix (OSV) for distro packages,
 * version_in_range against each CVE's NVD ranges for upstream builds. No model
 * call. New recordings carry their ledger directly; this is only for the old.
 *
 *   npm run build-ledgers
 */

import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { FirstWatchReport, SavedLedger } from "../lib/agent";
import { cachedCveNow } from "../lib/cache";
import { check_distro_fix, parse_stack, version_in_range } from "../lib/tools";

for (const file of readdirSync("fixtures").filter((f) => f.endsWith(".json") && !f.endsWith(".ledger.json"))) {
  const id = file.replace(/\.json$/, "");
  const saved = JSON.parse(readFileSync(join("fixtures", file), "utf8")) as { report: FirstWatchReport; ledger?: SavedLedger };
  if (saved.ledger) {
    console.log(`${id}: recorded with its own ledger, skipped`);
    continue;
  }
  const dir = join("eval/cases", id);
  const files = Object.fromEntries(readdirSync(dir).filter((f) => f !== "case.json").map((f) => [f, readFileSync(join(dir, f), "utf8")]));
  const parsed = parse_stack(files);
  if (!parsed.ok) throw new Error(`${id}: ${parsed.error}`);
  const ecosystem = parsed.ecosystems[0];
  const cves = [...new Set(saved.report.findings.map((f) => f.cve).filter((c): c is string => !!c))];
  const ledger: SavedLedger = {
    cves,
    distro: [],
    ranges: [],
    rebuiltBy: "scripts/build-ledgers.mts: the recording's packages, re-checked with the same code tools (OSV, version_in_range); no model call",
  };
  const seen = new Set<string>();
  for (const f of saved.report.findings) {
    if (!f.cve || seen.has(`${f.package}|${f.installed_version}|${f.cve}`)) continue;
    seen.add(`${f.package}|${f.installed_version}|${f.cve}`);
    if (f.package !== "php" && ecosystem) {
      const r = await check_distro_fix(f.cve, ecosystem, f.package, f.installed_version);
      if (r.ok) ledger.distro.push({ cve: r.cve, ecosystem: r.ecosystem, package: r.package, sourcePackage: r.sourcePackage, version: r.version, status: r.status, fixedVersion: r.fixedVersion });
    } else {
      const rec = cachedCveNow(f.cve);
      const ranges = rec && "found" in rec && rec.found ? rec.affected.filter((a) => a.product === "php/php").map((a) => a.range) : [];
      for (const range of ranges) {
        const r = version_in_range(f.installed_version, range);
        if (r.ok) ledger.ranges.push({ version: r.version, range: r.range, inRange: r.inRange, cves: [f.cve] });
      }
    }
  }
  writeFileSync(join("fixtures", `${id}.ledger.json`), `${JSON.stringify(ledger, null, 2)}\n`);
  console.log(`${id}: ${ledger.distro.length} OSV rows, ${ledger.ranges.length} range results -> fixtures/${id}.ledger.json`);
}
