/**
 * Tests for the verdict invariants. No model, no network: each test builds the
 * ledger a run would have produced, hands enforceInvariants a report, and
 * checks what survives. Facts come from the real eval fixtures via parse_stack.
 *
 *   npm test
 */

import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import {
  emptyLedger,
  enforceInvariants,
  type FirstWatchReport,
  type Ledger,
  type PackageFinding,
  type Verdict,
} from "../lib/agent";
import { parse_stack, sourcePackageOf, type Fact } from "../lib/tools";

const CVE = "CVE-2026-109618";

function factsOf(caseId: string): Fact[] {
  const dir = join("eval/cases", caseId);
  const files = Object.fromEntries(
    readdirSync(dir).filter((f) => f !== "case.json").map((f) => [f, readFileSync(join(dir, f), "utf8")]),
  );
  const parsed = parse_stack(files);
  assert.ok(parsed.ok, `parse_stack failed for ${caseId}`);
  return parsed.facts;
}

function finding(pkg: string, version: string, verdict: Verdict, extra: Partial<PackageFinding> = {}): PackageFinding {
  return {
    package: pkg,
    installed_version: version,
    version_source: "dpkg",
    sapi: null,
    verdict,
    decided_by: { method: "check_distro_fix", detail: "test" },
    exploitation_confidence: "presumed",
    severity: { cvss: null, score: null, note: "" },
    citations: [{ claim: "test", quote: "test", source: "test" }],
    mitigations: [],
    eol: null,
    remediation: [],
    unverified: [],
    ...extra,
  };
}

const report = (findings: PackageFinding[]): FirstWatchReport => ({
  schema_version: 2,
  cve: CVE,
  target: "test",
  assessed_at: "2026-10-26T00:00:00Z",
  overall: "NOT_AFFECTED", // deliberately optimistic: the engine must recompute it
  summary: "",
  findings,
});

function osv(ledger: Ledger, ecosystem: string, pkg: string, version: string, status: "fixed" | "affected" | "unknown") {
  ledger.distro.push({ cve: CVE, ecosystem, package: pkg, sourcePackage: sourcePackageOf(pkg), version, status, fixedVersion: null });
}

const verdictOf = (r: FirstWatchReport, pkg: string) => r.findings.find((f) => f.package === pkg)?.verdict;
const logged = (log: { package: string; invariant: string }[], pkg: string, inv: string) =>
  log.some((l) => l.package === pkg && l.invariant === inv);

/* --- runner ------------------------------------------------------- */
const results: { name: string; error?: unknown }[] = [];
function test(name: string, fn: () => void) {
  try {
    fn();
    results.push({ name });
  } catch (error) {
    results.push({ name, error });
  }
}

/* ================================================================== *
 * I6: coverage
 * ================================================================== */

test("I6: case (g) with php8.4-fpm omitted cannot come back NOT_AFFECTED", () => {
  const ledger = emptyLedger(factsOf("g-split-cli-patched-fpm-stale"));
  osv(ledger, "Debian:13", "php8.4-cli", "8.4.27-1~deb13u1", "fixed");
  osv(ledger, "Debian:13", "php8.4-common", "8.4.27-1~deb13u1", "fixed");

  // The model looked at what php -v pointed it to and forgot the FPM package.
  const { report: out, log } = enforceInvariants(
    report([
      finding("php8.4-cli", "8.4.27-1~deb13u1", "NOT_AFFECTED"),
      finding("php8.4-common", "8.4.27-1~deb13u1", "NOT_AFFECTED"),
    ]),
    ledger,
  );

  assert.notEqual(out.overall, "NOT_AFFECTED");
  assert.equal(out.overall, "UNVERIFIED");
  const fpm = out.findings.find((f) => f.package === "php8.4-fpm");
  assert.ok(fpm, "a finding must be synthesized for php8.4-fpm");
  assert.equal(fpm.verdict, "UNVERIFIED");
  assert.equal(fpm.decided_by.method, "none");
  assert.equal(fpm.installed_version, "8.4.16-1~deb13u1", "uses the fpm package's own installed version");
  assert.ok(fpm.unverified.length > 0);
  assert.ok(logged(log, "php8.4-fpm", "I6"));
  // The two the model did assess keep their verdicts.
  assert.equal(verdictOf(out, "php8.4-cli"), "NOT_AFFECTED");
});

test("I6: case (g) assessed correctly is AFFECTED with nothing synthesized", () => {
  const ledger = emptyLedger(factsOf("g-split-cli-patched-fpm-stale"));
  osv(ledger, "Debian:13", "php8.4-cli", "8.4.27-1~deb13u1", "fixed");
  osv(ledger, "Debian:13", "php8.4-common", "8.4.27-1~deb13u1", "fixed");
  osv(ledger, "Debian:13", "php8.4-fpm", "8.4.16-1~deb13u1", "affected");
  const { report: out, log } = enforceInvariants(
    report([
      finding("php8.4-cli", "8.4.27-1~deb13u1", "NOT_AFFECTED"),
      finding("php8.4-common", "8.4.27-1~deb13u1", "NOT_AFFECTED"),
      finding("php8.4-fpm", "8.4.16-1~deb13u1", "AFFECTED"),
    ]),
    ledger,
  );
  assert.equal(out.overall, "AFFECTED");
  assert.equal(out.findings.length, 3);
  assert.equal(log.length, 0);
});

test("I6: does not over-fire when every package is assessed and fixed (case d)", () => {
  const ledger = emptyLedger(factsOf("d-debian12-security-pocket"));
  for (const p of ["php8.2-cli", "php8.2-common", "php8.2-fpm"]) osv(ledger, "Debian:12", p, "8.2.35-1~deb12u1", "fixed");
  const { report: out, log } = enforceInvariants(
    report(["php8.2-cli", "php8.2-common", "php8.2-fpm"].map((p) => finding(p, "8.2.35-1~deb12u1", "NOT_AFFECTED"))),
    ledger,
  );
  assert.equal(out.overall, "NOT_AFFECTED");
  assert.equal(log.length, 0);
});

/* ================================================================== *
 * I7: range provenance
 * ================================================================== */

const GHSA_TEXT = "Affected versions < 8.2.35 < 8.3.36 < 8.4.27 < 8.5.12 Patched versions 8.2.35 8.3.36 8.4.27 8.5.12";

test("I7: a fabricated range cannot clear a package", () => {
  const ledger = emptyLedger(factsOf("h-upstream-84-mitigated")); // php 8.4.12 from php -v
  ledger.fetched.push({ source: "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w", text: GHSA_TEXT });
  // "< 8.4.2" is invented, and is a substring of the real "8.4.27" on the page.
  ledger.ranges.push({ version: "8.4.12", range: "< 8.4.2", inRange: false });

  const { report: out, log } = enforceInvariants(
    report([finding("php", "8.4.12", "NOT_AFFECTED", { version_source: "php -v", decided_by: { method: "version_in_range", detail: "8.4.12 is outside < 8.4.2" } })]),
    ledger,
  );
  assert.notEqual(verdictOf(out, "php"), "NOT_AFFECTED");
  assert.ok(logged(log, "php", "I7"), "the downgrade must be attributed to I7");
  assert.notEqual(out.overall, "NOT_AFFECTED");
});

test("I7: a fabricated range can still raise an alarm", () => {
  const ledger = emptyLedger(factsOf("h-upstream-84-mitigated"));
  ledger.fetched.push({ source: "ghsa", text: GHSA_TEXT });
  ledger.ranges.push({ version: "8.4.12", range: "< 8.4.99", inRange: true });
  const { report: out, log } = enforceInvariants(
    report([finding("php", "8.4.12", "AFFECTED", { version_source: "php -v", decided_by: { method: "version_in_range", detail: "in range" } })]),
    ledger,
  );
  assert.equal(verdictOf(out, "php"), "AFFECTED");
  assert.ok(!logged(log, "php", "I7"));
});

test("I7: a range that was actually fetched can clear a package", () => {
  const facts: Fact[] = [
    { field: "php.version", value: "8.4.27", kind: "runtime", file: "php-v.txt", line: 1, text: "PHP 8.4.27 (fpm-fcgi)" },
    { field: "pkg.php", value: "8.4.27", kind: "runtime", file: "php-v.txt", line: 1, text: "PHP 8.4.27 (fpm-fcgi)" },
  ];
  const ledger = emptyLedger(facts);
  ledger.fetched.push({ source: `fetch_cve ${CVE}`, text: JSON.stringify({ affected: [{ product: "php/php", range: ">= 8.4.0 and < 8.4.27" }] }) });
  ledger.ranges.push({ version: "8.4.27", range: ">= 8.4.0 and < 8.4.27", inRange: false });
  const { report: out, log } = enforceInvariants(
    report([finding("php", "8.4.27", "NOT_AFFECTED", { version_source: "php -v", decided_by: { method: "version_in_range", detail: "outside" } })]),
    ledger,
  );
  assert.equal(verdictOf(out, "php"), "NOT_AFFECTED");
  assert.equal(log.length, 0);
});

/* ================================================================== *
 * I1 to I5, and the severity-only guarantee
 * ================================================================== */

test("I1: NOT_AFFECTED with no evidence at all becomes UNVERIFIED", () => {
  const facts = factsOf("a-ubuntu2204-patched");
  const pkgs = ["php8.1", "php8.1-cli", "php8.1-common", "php8.1-mysql", "libapache2-mod-php8.1"];
  const { report: out } = enforceInvariants(report(pkgs.map((p) => finding(p, "8.1.2-1ubuntu2.28", "NOT_AFFECTED"))), emptyLedger(facts));
  for (const p of pkgs) assert.equal(verdictOf(out, p), "UNVERIFIED", p);
});

test("I1: NOT_AFFECTED contradicted by OSV becomes AFFECTED", () => {
  const ledger = emptyLedger(factsOf("b-ubuntu2204-stale"));
  osv(ledger, "Ubuntu:22.04:LTS", "libapache2-mod-php8.1", "8.1.2-1ubuntu2.21", "affected");
  const { report: out, log } = enforceInvariants(report([finding("libapache2-mod-php8.1", "8.1.2-1ubuntu2.21", "NOT_AFFECTED")]), ledger);
  assert.equal(verdictOf(out, "libapache2-mod-php8.1"), "AFFECTED");
  assert.ok(logged(log, "libapache2-mod-php8.1", "I1"));
});

test("I1 + OSV: the jammy backport clears every package (case a)", () => {
  const ledger = emptyLedger(factsOf("a-ubuntu2204-patched"));
  const pkgs = ["php8.1", "php8.1-cli", "php8.1-common", "php8.1-mysql", "libapache2-mod-php8.1"];
  for (const p of pkgs) osv(ledger, "Ubuntu:22.04:LTS", p, "8.1.2-1ubuntu2.28", "fixed");
  const { report: out, log } = enforceInvariants(report(pkgs.map((p) => finding(p, "8.1.2-1ubuntu2.28", "NOT_AFFECTED"))), ledger);
  assert.equal(out.overall, "NOT_AFFECTED");
  assert.equal(log.length, 0);
});

test("I2: AFFECTED_MITIGATED without a quoted mitigation becomes AFFECTED", () => {
  const ledger = emptyLedger(factsOf("h-upstream-84-mitigated"));
  ledger.fetched.push({ source: "ghsa", text: GHSA_TEXT });
  ledger.ranges.push({ version: "8.4.12", range: "< 8.4.27", inRange: true });
  const { report: out, log } = enforceInvariants(report([finding("php", "8.4.12", "AFFECTED_MITIGATED", { version_source: "php -v" })]), ledger);
  assert.equal(verdictOf(out, "php"), "AFFECTED");
  assert.ok(logged(log, "php", "I2"));
});

test("I2: AFFECTED_MITIGATED with a quoted mitigation survives (case h)", () => {
  const ledger = emptyLedger(factsOf("h-upstream-84-mitigated"));
  ledger.fetched.push({ source: "ghsa", text: GHSA_TEXT });
  ledger.ranges.push({ version: "8.4.12", range: "< 8.4.27", inRange: true });
  const { report: out } = enforceInvariants(
    report([
      finding("php", "8.4.12", "AFFECTED_MITIGATED", {
        version_source: "php -v",
        mitigations: [{ setting: "memory_limit", value: "-1", quote: "setting and enforcing memory_limit=-1 administratively is the primary configuration mitigation", source: "ghsa" }],
      }),
    ]),
    ledger,
  );
  assert.equal(verdictOf(out, "php"), "AFFECTED_MITIGATED");
});

test("I3: no runtime evidence caps reassurance at UNVERIFIED (case i)", () => {
  const ledger = emptyLedger(factsOf("i-dockerfile-only"));
  ledger.ranges.push({ version: "8.4", range: "< 8.4.27", inRange: true });
  const { report: out, log } = enforceInvariants(
    report([finding("php", "8.4", "AFFECTED_MITIGATED", { version_source: "image-tag", mitigations: [{ setting: "x", value: "y", quote: "q", source: "s" }] })]),
    ledger,
  );
  assert.equal(verdictOf(out, "php"), "UNVERIFIED");
  assert.ok(logged(log, "php", "I3") || logged(log, "php", "I4"));
});

test("I4: floating 8.4 cannot be CLEARED by a range that splits inside the branch", () => {
  // Isolate I4: runtime evidence exists (so I3 is quiet), and the range was
  // genuinely fetched (so I1 and I7 are quiet). Only inexactness is wrong.
  const facts: Fact[] = [
    { field: "os.id", value: "debian", kind: "runtime", file: "os-release", line: 4, text: "ID=debian" },
    { field: "pkg.php", value: "8.4", kind: "build", file: "Dockerfile", line: 1, text: "FROM php:8.4-fpm" },
  ];
  const ledger = emptyLedger(facts);
  ledger.fetched.push({ source: "advisory", text: "Affected: >= 8.4.20 and < 8.4.27" });
  // "8.4" compares as 8.4.0, which is below 8.4.20, so the check says "outside".
  // But the tag could resolve to 8.4.22, which is inside.
  ledger.ranges.push({ version: "8.4", range: ">= 8.4.20 and < 8.4.27", inRange: false });
  const { report: out, log } = enforceInvariants(
    report([finding("php", "8.4", "NOT_AFFECTED", { version_source: "image-tag", decided_by: { method: "version_in_range", detail: "outside" } })]),
    ledger,
  );
  assert.equal(verdictOf(out, "php"), "UNVERIFIED");
  assert.ok(logged(log, "php", "I4"), "the downgrade must be attributed to I4");
});

test("I4: an alarm on floating 8.4 stands, because alarms are always allowed", () => {
  const ledger = emptyLedger(factsOf("i-dockerfile-only"));
  ledger.ranges.push({ version: "8.4", range: ">= 8.4.0 and < 8.4.27", inRange: true });
  const { report: out, log } = enforceInvariants(report([finding("php", "8.4", "AFFECTED", { version_source: "image-tag" })]), ledger);
  assert.equal(verdictOf(out, "php"), "AFFECTED");
  assert.equal(log.length, 0);
});

test("I4: floating 8.1 IS decided when the whole branch is in range", () => {
  const ledger = emptyLedger(factsOf("f-upstream-php81-fpm-image"));
  ledger.ranges.push({ version: "8.1", range: ">= 5.4.0 and < 8.2.35", inRange: true });
  const { report: out } = enforceInvariants(report([finding("php", "8.1", "AFFECTED", { version_source: "image-tag" })]), ledger);
  assert.equal(verdictOf(out, "php"), "AFFECTED");
});

test("I5: php8.4-fpm cannot be cleared with the CLI's version", () => {
  const ledger = emptyLedger(factsOf("g-split-cli-patched-fpm-stale"));
  // The model passed the CLI's version for the FPM package, and OSV duly said fixed.
  osv(ledger, "Debian:13", "php8.4-fpm", "8.4.27-1~deb13u1", "fixed");
  osv(ledger, "Debian:13", "php8.4-cli", "8.4.27-1~deb13u1", "fixed");
  osv(ledger, "Debian:13", "php8.4-common", "8.4.27-1~deb13u1", "fixed");
  const { report: out, log } = enforceInvariants(
    report([
      finding("php8.4-cli", "8.4.27-1~deb13u1", "NOT_AFFECTED"),
      finding("php8.4-common", "8.4.27-1~deb13u1", "NOT_AFFECTED"),
      finding("php8.4-fpm", "8.4.27-1~deb13u1", "NOT_AFFECTED"),
    ]),
    ledger,
  );
  assert.equal(verdictOf(out, "php8.4-fpm"), "UNVERIFIED");
  assert.ok(logged(log, "php8.4-fpm", "I5"));
  assert.notEqual(out.overall, "NOT_AFFECTED");
});

test("exploitation_confidence never changes a verdict", () => {
  const verdicts = (["confirmed", "presumed", "unaddressed", "not-applicable"] as const).map((conf) => {
    const ledger = emptyLedger(factsOf("e-debian12-no-security-pocket"));
    for (const p of ["php8.2-cli", "php8.2-common", "php8.2-fpm"]) osv(ledger, "Debian:12", p, "8.2.32-1~deb12u1", "affected");
    const { report: out } = enforceInvariants(
      report(["php8.2-cli", "php8.2-common", "php8.2-fpm"].map((p) => finding(p, "8.2.32-1~deb12u1", "AFFECTED", { exploitation_confidence: conf }))),
      ledger,
    );
    return out.overall;
  });
  assert.deepEqual(verdicts, ["AFFECTED", "AFFECTED", "AFFECTED", "AFFECTED"]);
});

test("overall is recomputed, not trusted from the model", () => {
  const ledger = emptyLedger(factsOf("e-debian12-no-security-pocket"));
  for (const p of ["php8.2-cli", "php8.2-common", "php8.2-fpm"]) osv(ledger, "Debian:12", p, "8.2.32-1~deb12u1", "affected");
  const r = report(["php8.2-cli", "php8.2-common", "php8.2-fpm"].map((p) => finding(p, "8.2.32-1~deb12u1", "AFFECTED")));
  r.overall = "NOT_AFFECTED";
  assert.equal(enforceInvariants(r, ledger).report.overall, "AFFECTED");
});

/* --- report ------------------------------------------------------- */
let failed = 0;
for (const r of results) {
  if (r.error) {
    failed++;
    console.log(`FAIL ${r.name}\n     ${r.error instanceof Error ? r.error.message.split("\n")[0] : String(r.error)}`);
  } else {
    console.log(`ok   ${r.name}`);
  }
}
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
