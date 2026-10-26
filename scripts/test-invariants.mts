/**
 * Tests for the verdict invariants. No model, no network: each test builds the
 * ledger a run would have produced, hands enforceInvariants a report, and
 * checks what survives. Facts come from the real eval fixtures via parse_stack
 * wherever a fixture fits, and are written out by hand where a test needs to
 * isolate one invariant.
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
import { parse_stack, sourcePackageOf, version_in_range, type Fact } from "../lib/tools";

const CVE = "CVE-2026-109618";

/* --- fixtures ----------------------------------------------------- */

function factsOf(caseId: string): Fact[] {
  const dir = join("eval/cases", caseId);
  const files = Object.fromEntries(
    readdirSync(dir).filter((f) => f !== "case.json").map((f) => [f, readFileSync(join(dir, f), "utf8")]),
  );
  const parsed = parse_stack(files);
  assert.ok(parsed.ok, `parse_stack failed for ${caseId}`);
  return parsed.facts;
}

const fact = (field: string, value: string, kind: Fact["kind"] = "runtime", file = "dpkg.txt", line = 6): Fact => ({
  field, value, kind, file, line, text: `${field} ${value}`,
});

/** An upstream build whose only installed-version evidence is php -v. */
const upstream = (version: string): Fact[] => [
  fact("php.version", version, "runtime", "php-v.txt", 1),
  fact("pkg.php", version, "runtime", "php-v.txt", 1),
];

const NVD_TEXT = JSON.stringify({
  id: CVE,
  affected: [
    { product: "php/php", range: ">= 7.3.0 and < 8.2.35" },
    { product: "php/php", range: ">= 8.3.0 and < 8.3.36" },
    { product: "php/php", range: ">= 8.4.0 and < 8.4.27" },
    { product: "php/php", range: ">= 8.5.0 and < 8.5.12" },
  ],
});
const GHSA_TEXT = "Affected versions < 8.2.35 < 8.3.36 < 8.4.27 < 8.5.12 Patched versions 8.2.35 8.3.36 8.4.27 8.5.12";
const MITIGATION_TEXT =
  "Updating to a PHP release containing the patch to this vulnerability is the only complete mitigation. " +
  "If updating is not possible, setting and enforcing memory_limit=-1 administratively is the primary configuration mitigation. " +
  "This is not a complete mitigation. For PHP 8.5, set fatal_error_backtraces=0 administratively and restart every worker. " +
  "For the session lifecycle case, set session.upload_progress.enabled=0 administratively and restart every worker.";
const MEMORY_QUOTE = "setting and enforcing memory_limit=-1 administratively is the primary configuration mitigation";

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
  summary: "Test summary.",
  findings,
});

function osv(ledger: Ledger, ecosystem: string, pkg: string, version: string, status: "fixed" | "affected" | "unknown") {
  ledger.distro.push({ cve: CVE, ecosystem, package: pkg, sourcePackage: sourcePackageOf(pkg), version, status, fixedVersion: null });
}

const get = (r: FirstWatchReport, pkg: string) => r.findings.find((f) => f.package === pkg);
const verdictOf = (r: FirstWatchReport, pkg: string) => get(r, pkg)?.verdict;
const logged = (log: { package: string; invariant: string }[], pkg: string, ...invs: string[]) =>
  log.some((l) => l.package === pkg && invs.includes(l.invariant));

const JAMMY = "8.1.2-1ubuntu2.28";
const JAMMY_ALL = ["php8.1", "php8.1-cli", "php8.1-common", "php8.1-mysql", "libapache2-mod-php8.1"];
const JAMMY_ENGINE = ["php8.1-cli", "libapache2-mod-php8.1"];

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
 * Review item A: range clearance must address the version's own branch
 * ================================================================== */

test("A/I8: 8.4.16 checked only against the 8.5 range is not NOT_AFFECTED", () => {
  const ledger = emptyLedger(upstream("8.4.16"));
  ledger.fetched.push({ source: `fetch_cve ${CVE}`, text: NVD_TEXT }); // the 8.5 range is real, so I7 is satisfied
  ledger.ranges.push({ version: "8.4.16", range: ">= 8.5.0 and < 8.5.12", inRange: false });
  const { report: out, log } = enforceInvariants(
    report([finding("php", "8.4.16", "NOT_AFFECTED", { version_source: "php -v", decided_by: { method: "version_in_range", detail: "outside 8.5" } })]),
    ledger,
  );
  assert.notEqual(verdictOf(out, "php"), "NOT_AFFECTED");
  assert.ok(logged(log, "php", "I8"));
});

test("A/I8: an out-of-range result cannot outvote an in-range one", () => {
  const ledger = emptyLedger(upstream("8.4.16"));
  ledger.fetched.push({ source: `fetch_cve ${CVE}`, text: NVD_TEXT });
  ledger.ranges.push({ version: "8.4.16", range: ">= 8.4.0 and < 8.4.27", inRange: true });
  ledger.ranges.push({ version: "8.4.16", range: ">= 8.5.0 and < 8.5.12", inRange: false });
  const { report: out, log } = enforceInvariants(
    report([finding("php", "8.4.16", "NOT_AFFECTED", { version_source: "php -v", decided_by: { method: "version_in_range", detail: "outside 8.5" } })]),
    ledger,
  );
  assert.equal(verdictOf(out, "php"), "AFFECTED", "the in-range result is evidence it is affected");
  assert.ok(logged(log, "php", "I8"));
});

test("A: the right branch's range still clears a patched version", () => {
  const ledger = emptyLedger(upstream("8.4.27"));
  ledger.fetched.push({ source: `fetch_cve ${CVE}`, text: NVD_TEXT });
  ledger.ranges.push({ version: "8.4.27", range: ">= 8.4.0 and < 8.4.27", inRange: false });
  const { report: out, log } = enforceInvariants(
    report([finding("php", "8.4.27", "NOT_AFFECTED", { version_source: "php -v", decided_by: { method: "version_in_range", detail: "outside" } })]),
    ledger,
  );
  assert.equal(verdictOf(out, "php"), "NOT_AFFECTED");
  assert.equal(log.length, 0);
});

/* ================================================================== *
 * Review item B: inventory, and per-package runtime evidence
 * ================================================================== */

test("B/I9: a finding named php8.1 with no php8.1 dpkg row cannot clear", () => {
  const ledger = emptyLedger([
    fact("os.ecosystem", "Ubuntu:22.04:LTS", "runtime", "os-release", 3),
    fact("pkg.php8.1-fpm", JAMMY),
  ]);
  // OSV genuinely says the source package is fixed at this version, in this ecosystem.
  osv(ledger, "Ubuntu:22.04:LTS", "php8.1", JAMMY, "fixed");
  const { report: out, log } = enforceInvariants(report([finding("php8.1", JAMMY, "NOT_AFFECTED")]), ledger);
  assert.notEqual(verdictOf(out, "php8.1"), "NOT_AFFECTED");
  assert.ok(logged(log, "php8.1", "I9"));
});

test("B/I3: runtime evidence is per package, not stack-wide", () => {
  // The stack has runtime evidence (os-release), but php8.2-fpm's version only
  // comes from an apt pin in the Dockerfile. That is build intent.
  const ledger = emptyLedger([
    fact("os.id", "debian", "runtime", "os-release", 4),
    fact("os.ecosystem", "Debian:12", "runtime", "os-release", 4),
    fact("pkg.php8.2-fpm", "8.2.35-1~deb12u1", "build", "Dockerfile", 3),
  ]);
  osv(ledger, "Debian:12", "php8.2-fpm", "8.2.35-1~deb12u1", "fixed");
  const { report: out, log } = enforceInvariants(report([finding("php8.2-fpm", "8.2.35-1~deb12u1", "NOT_AFFECTED", { version_source: "apt-pin" })]), ledger);
  assert.equal(verdictOf(out, "php8.2-fpm"), "UNVERIFIED");
  assert.ok(logged(log, "php8.2-fpm", "I3"));
});

test("B: a finding named php may not use php -v on a host with distro packages (case g)", () => {
  const ledger = emptyLedger(factsOf("g-split-cli-patched-fpm-stale")); // php -v says 8.4.27
  ledger.fetched.push({ source: `fetch_cve ${CVE}`, text: NVD_TEXT });
  ledger.ranges.push({ version: "8.4.27", range: ">= 8.4.0 and < 8.4.27", inRange: false });
  const { report: out, log } = enforceInvariants(
    report([finding("php", "8.4.27", "NOT_AFFECTED", { version_source: "php -v", decided_by: { method: "version_in_range", detail: "outside" } })]),
    ledger,
  );
  assert.notEqual(verdictOf(out, "php"), "NOT_AFFECTED");
  assert.ok(logged(log, "php", "I9", "I3"));
  assert.notEqual(out.overall, "NOT_AFFECTED", "and the fpm package it skipped is synthesized by I6");
});

/* ================================================================== *
 * Review item C: OSV rows must be unambiguous and in this ecosystem
 * ================================================================== */

test("C: a fixed row from another ecosystem cannot clear (jammy stack, noble row)", () => {
  const ledger = emptyLedger(factsOf("a-ubuntu2204-patched"));
  for (const p of JAMMY_ENGINE) osv(ledger, "Ubuntu:24.04:LTS", p, JAMMY, "fixed");
  const { report: out, log } = enforceInvariants(report(JAMMY_ENGINE.map((p) => finding(p, JAMMY, "NOT_AFFECTED"))), ledger);
  for (const p of JAMMY_ENGINE) assert.notEqual(verdictOf(out, p), "NOT_AFFECTED", p);
  assert.ok(log.some((l) => l.invariant === "I1" && l.why.includes("Ubuntu:24.04:LTS")), "the reason names the mismatched ecosystem");
});

test("C: a fixed row and an affected row for the same version cannot clear", () => {
  const ledger = emptyLedger(factsOf("a-ubuntu2204-patched"));
  osv(ledger, "Ubuntu:22.04:LTS", "libapache2-mod-php8.1", JAMMY, "fixed");
  osv(ledger, "Ubuntu:22.04:LTS", "libapache2-mod-php8.1", JAMMY, "affected");
  const { report: out, log } = enforceInvariants(report([finding("libapache2-mod-php8.1", JAMMY, "NOT_AFFECTED")]), ledger);
  assert.equal(verdictOf(out, "libapache2-mod-php8.1"), "AFFECTED");
  assert.ok(logged(log, "libapache2-mod-php8.1", "I1"));
});

test("C: no detected ecosystem means no OSV row can clear", () => {
  const ledger = emptyLedger([fact("pkg.php8.2-fpm", "8.2.35-1~deb12u1")]);
  osv(ledger, "Debian:12", "php8.2-fpm", "8.2.35-1~deb12u1", "fixed");
  const { report: out } = enforceInvariants(report([finding("php8.2-fpm", "8.2.35-1~deb12u1", "NOT_AFFECTED")]), ledger);
  assert.notEqual(verdictOf(out, "php8.2-fpm"), "NOT_AFFECTED");
});

/* ================================================================== *
 * Review item D: mitigations must be quoted from a fetched advisory
 * (plus: the stack must actually set them)
 * ================================================================== */

const mitigated = (setting: string, value: string, quote: string): Partial<PackageFinding> => ({
  version_source: "php -v",
  mitigations: [{ setting, value, quote, source: "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w" }],
});

test("D/I10: a mitigation quote that is not in any fetched text does not count", () => {
  const ledger = emptyLedger(factsOf("h-upstream-84-mitigated"));
  ledger.fetched.push({ source: "ghsa", text: GHSA_TEXT }); // versions only, no mitigation prose
  ledger.ranges.push({ version: "8.4.12", range: "< 8.4.27", inRange: true });
  const { report: out, log } = enforceInvariants(report([finding("php", "8.4.12", "AFFECTED_MITIGATED", mitigated("memory_limit", "-1", MEMORY_QUOTE))]), ledger);
  assert.equal(verdictOf(out, "php"), "AFFECTED");
  assert.ok(logged(log, "php", "I10"));
});

test("D/I10 (extra): a correctly quoted mitigation the stack does not set does not count", () => {
  const ledger = emptyLedger(factsOf("h-upstream-84-mitigated")); // sets memory_limit and upload_progress, not fatal_error_backtraces
  ledger.fetched.push({ source: "ghsa", text: `${GHSA_TEXT} ${MITIGATION_TEXT}` });
  ledger.ranges.push({ version: "8.4.12", range: "< 8.4.27", inRange: true });
  const { report: out, log } = enforceInvariants(
    report([finding("php", "8.4.12", "AFFECTED_MITIGATED", mitigated("fatal_error_backtraces", "0", "set fatal_error_backtraces=0 administratively and restart every worker"))]),
    ledger,
  );
  assert.equal(verdictOf(out, "php"), "AFFECTED");
  assert.ok(log.some((l) => l.invariant === "I10" && l.why.includes("not set anywhere")));
});

test("D: a fetched, stack-present mitigation survives (case h)", () => {
  const ledger = emptyLedger(factsOf("h-upstream-84-mitigated"));
  ledger.fetched.push({ source: "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w", text: `${GHSA_TEXT} ${MITIGATION_TEXT}` });
  ledger.ranges.push({ version: "8.4.12", range: "< 8.4.27", inRange: true });
  const { report: out, log } = enforceInvariants(report([finding("php", "8.4.12", "AFFECTED_MITIGATED", mitigated("memory_limit", "-1", MEMORY_QUOTE))]), ledger);
  assert.equal(verdictOf(out, "php"), "AFFECTED_MITIGATED");
  assert.equal(log.length, 0);
});

test("I2 (extra): an unsourced in-range result cannot unlock AFFECTED_MITIGATED", () => {
  const ledger = emptyLedger(factsOf("h-upstream-84-mitigated"));
  ledger.fetched.push({ source: "ghsa", text: MITIGATION_TEXT }); // mitigation prose, but no version boundaries
  ledger.ranges.push({ version: "8.4.12", range: "< 8.4.27", inRange: true }); // never read anywhere
  const { report: out, log } = enforceInvariants(report([finding("php", "8.4.12", "AFFECTED_MITIGATED", mitigated("memory_limit", "-1", MEMORY_QUOTE))]), ledger);
  assert.equal(verdictOf(out, "php"), "UNVERIFIED");
  assert.ok(logged(log, "php", "I2"));
});

/* ================================================================== *
 * Review item E: surviving verdicts record what permitted them
 * ================================================================== */

test("E: a cleared package's allow_reason names the OSV row and the runtime evidence", () => {
  const ledger = emptyLedger(factsOf("a-ubuntu2204-patched"));
  for (const p of JAMMY_ENGINE) osv(ledger, "Ubuntu:22.04:LTS", p, JAMMY, "fixed");
  const { report: out } = enforceInvariants(report(JAMMY_ENGINE.map((p) => finding(p, JAMMY, "NOT_AFFECTED"))), ledger);
  const reason = get(out, "libapache2-mod-php8.1")?.allow_reason ?? "";
  assert.match(reason, /OSV row: Ubuntu:22\.04:LTS php8\.1 8\.1\.2-1ubuntu2\.28 is fixed/);
  assert.match(reason, /dpkg\.txt:\d+/);
});

test("E: a range clearance's allow_reason names the range and where it was read", () => {
  const ledger = emptyLedger(upstream("8.4.27"));
  ledger.fetched.push({ source: `fetch_cve ${CVE}`, text: NVD_TEXT });
  ledger.ranges.push({ version: "8.4.27", range: ">= 8.4.0 and < 8.4.27", inRange: false });
  const { report: out } = enforceInvariants(report([finding("php", "8.4.27", "NOT_AFFECTED", { version_source: "php -v" })]), ledger);
  assert.match(get(out, "php")?.allow_reason ?? "", /outside ">= 8\.4\.0 and < 8\.4\.27", read in fetch_cve/);
});

test("E: an alarm's allow_reason names its support; a demoted finding has none", () => {
  const ledger = emptyLedger(factsOf("g-split-cli-patched-fpm-stale"));
  osv(ledger, "Debian:13", "php8.4-fpm", "8.4.16-1~deb13u1", "affected");
  const { report: out } = enforceInvariants(
    report([finding("php8.4-fpm", "8.4.16-1~deb13u1", "AFFECTED"), finding("php8.4-cli", "8.4.27-1~deb13u1", "NOT_AFFECTED")]),
    ledger,
  );
  assert.match(get(out, "php8.4-fpm")?.allow_reason ?? "", /An alarm needs no permission\. Supported by OSV row Debian:13 php8\.4/);
  const cli = get(out, "php8.4-cli");
  assert.ok(cli?.enforcement?.length, "cli had no OSV row, so it was demoted");
  assert.equal(cli?.allow_reason, undefined);
});

/* ================================================================== *
 * I6: coverage, scoped to engine-carrying packages
 * ================================================================== */

test("I6: case (g) with php8.4-fpm omitted cannot come back NOT_AFFECTED", () => {
  const ledger = emptyLedger(factsOf("g-split-cli-patched-fpm-stale"));
  osv(ledger, "Debian:13", "php8.4-cli", "8.4.27-1~deb13u1", "fixed");
  const { report: out, log } = enforceInvariants(report([finding("php8.4-cli", "8.4.27-1~deb13u1", "NOT_AFFECTED")]), ledger);
  assert.notEqual(out.overall, "NOT_AFFECTED");
  assert.equal(out.overall, "UNVERIFIED");
  const fpm = get(out, "php8.4-fpm");
  assert.ok(fpm, "a finding must be synthesized for php8.4-fpm");
  assert.equal(fpm.verdict, "UNVERIFIED");
  assert.equal(fpm.decided_by.method, "none");
  assert.equal(fpm.installed_version, "8.4.16-1~deb13u1", "uses the fpm package's own installed version");
  assert.ok(logged(log, "php8.4-fpm", "I6"));
  assert.equal(verdictOf(out, "php8.4-cli"), "NOT_AFFECTED");
});

test("I6 scope: extension packages need no finding and are listed once in the summary", () => {
  const ledger = emptyLedger(factsOf("a-ubuntu2204-patched"));
  for (const p of JAMMY_ENGINE) osv(ledger, "Ubuntu:22.04:LTS", p, JAMMY, "fixed");
  const { report: out, log } = enforceInvariants(report(JAMMY_ENGINE.map((p) => finding(p, JAMMY, "NOT_AFFECTED"))), ledger);
  assert.equal(out.overall, "NOT_AFFECTED");
  assert.ok(!log.some((l) => l.invariant === "I6"), "no synthesized findings");
  assert.deepEqual([...(out.covered_packages ?? [])].sort(), ["php8.1", "php8.1-common", "php8.1-mysql"]);
  const phrase = "share the source package; covered by the SAPI verdicts";
  assert.equal(out.summary.split(phrase).length - 1, 1, "the phrase appears exactly once");
  assert.ok(out.summary.startsWith("Test summary."), "the model's summary is kept");
});

test("I6 scope: an assessed extension package is not also listed as covered", () => {
  const ledger = emptyLedger(factsOf("a-ubuntu2204-patched"));
  for (const p of JAMMY_ALL) osv(ledger, "Ubuntu:22.04:LTS", p, JAMMY, "fixed");
  const { report: out, log } = enforceInvariants(report(JAMMY_ALL.map((p) => finding(p, JAMMY, "NOT_AFFECTED"))), ledger);
  assert.equal(out.overall, "NOT_AFFECTED");
  assert.equal(log.length, 0);
  assert.deepEqual(out.covered_packages, []);
});

test("I6: does not over-fire when the engine packages are assessed and fixed (case d)", () => {
  const ledger = emptyLedger(factsOf("d-debian12-security-pocket"));
  for (const p of ["php8.2-cli", "php8.2-fpm"]) osv(ledger, "Debian:12", p, "8.2.35-1~deb12u1", "fixed");
  const { report: out, log } = enforceInvariants(report(["php8.2-cli", "php8.2-fpm"].map((p) => finding(p, "8.2.35-1~deb12u1", "NOT_AFFECTED"))), ledger);
  assert.equal(out.overall, "NOT_AFFECTED");
  assert.equal(log.length, 0);
});

/* ================================================================== *
 * I7: range provenance
 * ================================================================== */

test("I7: a fabricated range cannot clear a package, even one that is a substring of a real one", () => {
  const ledger = emptyLedger(factsOf("h-upstream-84-mitigated"));
  ledger.fetched.push({ source: "ghsa", text: GHSA_TEXT });
  ledger.ranges.push({ version: "8.4.12", range: "< 8.4.2", inRange: false }); // "8.4.2" is inside "8.4.27"
  const { report: out, log } = enforceInvariants(
    report([finding("php", "8.4.12", "NOT_AFFECTED", { version_source: "php -v", decided_by: { method: "version_in_range", detail: "outside" } })]),
    ledger,
  );
  assert.notEqual(verdictOf(out, "php"), "NOT_AFFECTED");
  assert.ok(logged(log, "php", "I7"));
});

test("I7: a fabricated range can still raise an alarm", () => {
  const ledger = emptyLedger(factsOf("h-upstream-84-mitigated"));
  ledger.fetched.push({ source: "ghsa", text: GHSA_TEXT });
  ledger.ranges.push({ version: "8.4.12", range: "< 8.4.99", inRange: true });
  const { report: out, log } = enforceInvariants(report([finding("php", "8.4.12", "AFFECTED", { version_source: "php -v" })]), ledger);
  assert.equal(verdictOf(out, "php"), "AFFECTED");
  assert.equal(log.length, 0);
});

/* ================================================================== *
 * I1, I3, I4, I5, and the cross-cutting guarantees
 * ================================================================== */

test("I1: NOT_AFFECTED with no evidence at all becomes UNVERIFIED", () => {
  const { report: out } = enforceInvariants(report(JAMMY_ENGINE.map((p) => finding(p, JAMMY, "NOT_AFFECTED"))), emptyLedger(factsOf("a-ubuntu2204-patched")));
  for (const p of JAMMY_ENGINE) assert.equal(verdictOf(out, p), "UNVERIFIED", p);
});

test("I1: NOT_AFFECTED contradicted by OSV becomes AFFECTED", () => {
  const ledger = emptyLedger(factsOf("b-ubuntu2204-stale"));
  osv(ledger, "Ubuntu:22.04:LTS", "libapache2-mod-php8.1", "8.1.2-1ubuntu2.21", "affected");
  const { report: out, log } = enforceInvariants(report([finding("libapache2-mod-php8.1", "8.1.2-1ubuntu2.21", "NOT_AFFECTED")]), ledger);
  assert.equal(verdictOf(out, "libapache2-mod-php8.1"), "AFFECTED");
  assert.ok(logged(log, "libapache2-mod-php8.1", "I1"));
});

test("I3: a stack with no runtime evidence at all cannot clear anything", () => {
  const ledger = emptyLedger([fact("pkg.php", "8.4.27", "build", "Dockerfile", 1)]); // FROM php:8.4.27-fpm, nothing else
  ledger.fetched.push({ source: `fetch_cve ${CVE}`, text: NVD_TEXT });
  ledger.ranges.push({ version: "8.4.27", range: ">= 8.4.0 and < 8.4.27", inRange: false });
  const { report: out, log } = enforceInvariants(report([finding("php", "8.4.27", "NOT_AFFECTED", { version_source: "image-tag" })]), ledger);
  assert.equal(verdictOf(out, "php"), "UNVERIFIED");
  assert.ok(log.some((l) => l.invariant === "I3" && l.why.includes("only build files")));
});

test("I4/I8: floating 8.4 cannot be cleared by a range that splits inside the branch", () => {
  const ledger = emptyLedger([fact("os.id", "debian", "runtime", "os-release", 4), fact("pkg.php", "8.4", "build", "Dockerfile", 1)]);
  ledger.fetched.push({ source: "advisory", text: "Affected: >= 8.4.20 and < 8.4.27" });
  // "8.4" compares as 8.4.0, below 8.4.20. The tag could still resolve to 8.4.22.
  ledger.ranges.push({ version: "8.4", range: ">= 8.4.20 and < 8.4.27", inRange: false });
  const { report: out, log } = enforceInvariants(report([finding("php", "8.4", "NOT_AFFECTED", { version_source: "image-tag" })]), ledger);
  assert.equal(verdictOf(out, "php"), "UNVERIFIED");
  assert.ok(logged(log, "php", "I8", "I4"));
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
  const { report: out, log } = enforceInvariants(
    report([finding("php8.4-cli", "8.4.27-1~deb13u1", "NOT_AFFECTED"), finding("php8.4-fpm", "8.4.27-1~deb13u1", "NOT_AFFECTED")]),
    ledger,
  );
  assert.equal(verdictOf(out, "php8.4-fpm"), "UNVERIFIED");
  assert.ok(log.some((l) => l.package === "php8.4-fpm" && l.invariant === "I5" && l.why.includes("php8.4-cli")));
  assert.notEqual(out.overall, "NOT_AFFECTED");
});

test("exploitation_confidence never changes a verdict", () => {
  const verdicts = (["confirmed", "presumed", "unaddressed", "not-applicable"] as const).map((conf) => {
    const ledger = emptyLedger(factsOf("e-debian12-no-security-pocket"));
    for (const p of ["php8.2-cli", "php8.2-fpm"]) osv(ledger, "Debian:12", p, "8.2.32-1~deb12u1", "affected");
    const { report: out } = enforceInvariants(
      report(["php8.2-cli", "php8.2-fpm"].map((p) => finding(p, "8.2.32-1~deb12u1", "AFFECTED", { exploitation_confidence: conf }))),
      ledger,
    );
    return out.overall;
  });
  assert.deepEqual(verdicts, ["AFFECTED", "AFFECTED", "AFFECTED", "AFFECTED"]);
});

test("overall is recomputed, not trusted from the model", () => {
  const ledger = emptyLedger(factsOf("e-debian12-no-security-pocket"));
  for (const p of ["php8.2-cli", "php8.2-fpm"]) osv(ledger, "Debian:12", p, "8.2.32-1~deb12u1", "affected");
  const r = report(["php8.2-cli", "php8.2-fpm"].map((p) => finding(p, "8.2.32-1~deb12u1", "AFFECTED")));
  r.overall = "NOT_AFFECTED";
  assert.equal(enforceInvariants(r, ledger).report.overall, "AFFECTED");
});

test("version_in_range (extra): refuses a distro version instead of comparing it upstream", () => {
  const r = version_in_range(JAMMY, "< 8.2.35");
  assert.equal(r.ok, false, "8.1.2-1ubuntu2.28 is patched, but an upstream range would call it affected");
  assert.equal(version_in_range("8.1.33", "< 8.2.35").ok, true);
});

/* ================================================================== *
 * Two CVEs in one disclosure: evidence for one never clears the other
 * ================================================================== */

const CVE_A = "CVE-2026-109618";
const CVE_B = "CVE-2026-109619";
function osvFor(ledger: Ledger, cve: string, ecosystem: string, pkg: string, version: string, status: "fixed" | "affected") {
  ledger.distro.push({ cve, ecosystem, package: pkg, sourcePackage: sourcePackageOf(pkg), version, status, fixedVersion: null });
}
const jammyBoth = () => {
  const ledger = emptyLedger(factsOf("a-ubuntu2204-patched"));
  ledger.cves = [CVE_A, CVE_B];
  return ledger;
};

test("two CVEs: packages cleared for one CVE only cannot come back NOT_AFFECTED", () => {
  const ledger = jammyBoth();
  for (const p of JAMMY_ENGINE) osvFor(ledger, CVE_A, "Ubuntu:22.04:LTS", p, JAMMY, "fixed");
  const { report: out, log } = enforceInvariants(report(JAMMY_ENGINE.map((p) => finding(p, JAMMY, "NOT_AFFECTED", { cve: CVE_A }))), ledger);
  assert.equal(out.overall, "UNVERIFIED");
  for (const p of JAMMY_ENGINE) {
    const missing = out.findings.find((f) => f.package === p && f.cve === CVE_B);
    assert.ok(missing, `${p} needs a finding for ${CVE_B}`);
    assert.equal(missing.verdict, "UNVERIFIED");
    assert.ok(log.some((l) => l.package === p && l.invariant === "I6" && l.why.includes(CVE_B)));
  }
});

test("two CVEs: a fixed row for one CVE cannot clear a finding about the other", () => {
  const ledger = jammyBoth();
  osvFor(ledger, CVE_A, "Ubuntu:22.04:LTS", "libapache2-mod-php8.1", JAMMY, "fixed");
  const { report: out, log } = enforceInvariants(report([finding("libapache2-mod-php8.1", JAMMY, "NOT_AFFECTED", { cve: CVE_B })]), ledger);
  assert.notEqual(verdictOf(out, "libapache2-mod-php8.1"), "NOT_AFFECTED");
  assert.ok(logged(log, "libapache2-mod-php8.1", "I1"));
});

test("two CVEs: a range read only in one CVE's advisory cannot clear the other CVE", () => {
  const ledger = emptyLedger(upstream("8.4.27"));
  ledger.cves = [CVE_A, CVE_B];
  // Only GHSA-w8hw (CVE_A) was read. Nothing about CVE_B states this range.
  ledger.fetched.push({ source: "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w", text: `>= 8.4.0 and < 8.4.27 ${CVE_A}`, cve: CVE_A });
  ledger.ranges.push({ version: "8.4.27", range: ">= 8.4.0 and < 8.4.27", inRange: false });
  const { report: out } = enforceInvariants(
    report([
      finding("php", "8.4.27", "NOT_AFFECTED", { cve: CVE_A, version_source: "php -v", decided_by: { method: "version_in_range", detail: "" } }),
      finding("php", "8.4.27", "NOT_AFFECTED", { cve: CVE_B, version_source: "php -v", decided_by: { method: "version_in_range", detail: "" } }),
    ]),
    ledger,
  );
  assert.equal(out.findings.find((f) => f.cve === CVE_A)?.verdict, "NOT_AFFECTED");
  assert.notEqual(out.findings.find((f) => f.cve === CVE_B)?.verdict, "NOT_AFFECTED");
});

test("two CVEs: findings about a CVE out of scope, or naming none, cannot clear (I11)", () => {
  const ledger = jammyBoth();
  for (const c of [CVE_A, CVE_B, "CVE-2026-999999"]) osvFor(ledger, c, "Ubuntu:22.04:LTS", "php8.1-cli", JAMMY, "fixed");
  const { report: out, log } = enforceInvariants(
    report([finding("php8.1-cli", JAMMY, "NOT_AFFECTED", { cve: "CVE-2026-999999" }), finding("libapache2-mod-php8.1", JAMMY, "NOT_AFFECTED")]),
    ledger,
  );
  assert.ok(log.some((l) => l.invariant === "I11" && l.why.includes("not one of the CVEs")));
  assert.ok(log.some((l) => l.invariant === "I11" && l.why.includes("names no CVE")));
  assert.notEqual(out.overall, "NOT_AFFECTED");
});

test("two CVEs: cleared for both is NOT_AFFECTED, each allow_reason naming its CVE", () => {
  const ledger = jammyBoth();
  const findings = [];
  for (const c of [CVE_A, CVE_B]) {
    for (const p of JAMMY_ENGINE) {
      osvFor(ledger, c, "Ubuntu:22.04:LTS", p, JAMMY, "fixed");
      findings.push(finding(p, JAMMY, "NOT_AFFECTED", { cve: c }));
    }
  }
  const { report: out, log } = enforceInvariants(report(findings), ledger);
  assert.equal(out.overall, "NOT_AFFECTED");
  assert.equal(log.length, 0);
  for (const f of out.findings) assert.ok(f.allow_reason?.includes(`for ${f.cve}`), `${f.package} ${f.cve}`);
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
