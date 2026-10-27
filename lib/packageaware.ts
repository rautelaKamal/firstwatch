/**
 * The package-aware baseline: our own code-only reimplementation of the
 * approach package scanners such as Trivy or debsecan take, not their output.
 * Each installed engine package's dpkg version is compared with the
 * distribution's fix record in OSV. No advisory reading, no mitigations, no
 * model: Affected, Not affected, or nothing it can say.
 */

import { carriesEngine, type Ledger } from "./agent";
import { check_distro_fix, type StackFacts } from "./tools";

export type PackageAwareVerdict = "AFFECTED" | "NOT_AFFECTED";
export type PackageAwareRow = {
  package: string;
  cve: string;
  version: string;
  verdict: PackageAwareVerdict | null;
  fixedVersion: string | null;
  note: string;
};
export type PackageAware = { overall: PackageAwareVerdict | null; rows: PackageAwareRow[]; note: string | null };

type Row = Pick<Ledger["distro"][number], "cve" | "package" | "version" | "status" | "fixedVersion">;

/** Engine packages installed from the distribution, as dpkg reports them. */
export function dpkgEnginePackages(parsed: StackFacts): { name: string; version: string }[] {
  const byName = new Map<string, { name: string; version: string }>();
  for (const p of parsed.packages) if (p.source && p.kind === "runtime" && carriesEngine(p.name, true)) byName.set(p.name, { name: p.name, version: p.version });
  return [...byName.values()];
}

/** The package-aware answer from distro fix rows already in hand (a saved ledger, or fresh OSV results). */
export function packageAwareFrom(parsed: StackFacts | null, cves: string[], rows: Row[]): PackageAware {
  const pkgs = parsed ? dpkgEnginePackages(parsed) : [];
  if (!pkgs.length) {
    const note = parsed?.hasRuntimeEvidence
      ? "PHP here is not installed from distribution packages, so there is no dpkg version for a package-aware check to compare."
      : "No list of installed packages (dpkg output), so a package-aware check has nothing to compare.";
    return { overall: null, rows: [], note };
  }
  const out = pkgs.flatMap(({ name, version }) =>
    cves.map((cve): PackageAwareRow => {
      const r = rows.find((x) => x.package === name && x.version === version && x.cve === cve);
      if (!r || r.status === "unknown") {
        return { package: name, cve, version, verdict: null, fixedVersion: r?.fixedVersion ?? null, note: "No distribution fix record for this version." };
      }
      const fixed = r.status === "fixed";
      const note = fixed ? `Fixed in ${r.fixedVersion ?? version}.` : r.fixedVersion ? `Fixed in ${r.fixedVersion}; ${version} is older.` : "No fixed version published yet.";
      return { package: name, cve, version, verdict: fixed ? "NOT_AFFECTED" : "AFFECTED", fixedVersion: r.fixedVersion, note };
    }),
  );
  const vs = out.map((r) => r.verdict);
  const overall = vs.includes("AFFECTED") ? "AFFECTED" : vs.every((v) => v === "NOT_AFFECTED") ? "NOT_AFFECTED" : null;
  return { overall, rows: out, note: null };
}

/** Ask OSV now, for every dpkg engine package and CVE. A failed lookup is "nothing it can say", never a verdict. */
export async function packageAware(parsed: StackFacts, cves: string[]): Promise<PackageAware> {
  const eco = parsed.ecosystems[0];
  const pkgs = dpkgEnginePackages(parsed);
  if (!eco || !pkgs.length) return packageAwareFrom(eco ? parsed : null, cves, []);
  const rows = await Promise.all(
    pkgs.flatMap((p) => cves.map((cve) => check_distro_fix(cve, eco, p.name, p.version).then((r) => (r.ok ? r : null)).catch(() => null))),
  );
  return packageAwareFrom(parsed, cves, rows.filter((r): r is NonNullable<typeof r> => !!r));
}
