/**
 * Example stacks for the web page, taken from the eval cases, and saved
 * reports that can be replayed without calling a model.
 *
 * Server only: reads from disk.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { baselineVerdict, scannerVersion } from "./baseline";
import { cachedCveNow } from "./cache";
import { packageAwareFrom, type PackageAware } from "./packageaware";
import { splitRuntime } from "./runtime";
import { parse_stack } from "./tools";
import type { Verdict } from "./verdicts";

export type CaseSpec = { cve: string; cves: string[]; target: string; sources: string[]; stack: string };

/** The disclosure every example is about, and the default for anything uploaded. */
export const DEFAULT_SPEC: CaseSpec = {
  cve: "CVE-2026-109618",
  cves: ["CVE-2026-109618", "CVE-2026-109619"],
  target: "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
  sources: ["https://www.php.net/archive/2026.php"],
  stack: "",
};

export const EXAMPLES = [
  {
    id: "g-split-cli-patched-fpm-stale",
    label: "Debian 13, FPM held back",
    blurb: "php8.4-fpm was on apt hold, so the last upgrade patched the CLI that php -v reports (8.4.27) but left the FPM that serves traffic at 8.4.16.",
  },
  {
    id: "a-ubuntu2204-patched",
    label: "Ubuntu 22.04, patched",
    blurb: "Upstream PHP 8.1 is end of life with no fixed release, but Ubuntu backported the fix into 8.1.2-1ubuntu2.28.",
  },
  {
    id: "e-debian12-no-security-pocket",
    label: "Debian 12, no security pocket",
    blurb: "Debian 12 never enabled bookworm-security, so php8.2 is stuck at 8.2.32-1~deb12u1 while Debian's fix sits in 8.2.35-1~deb12u1.",
  },
  {
    id: "j-ubuntu2404-backport-cve-2024-11236",
    label: "Second CVE: Ubuntu 24.04",
    blurb: "Second CVE (CVE-2024-11236): same pipeline, no code changes. Upstream fixed it in 8.3.14; Ubuntu 24.04 backported the fix into 8.3.6-0ubuntu0.24.04.3.",
  },
  {
    id: "i-dockerfile-only",
    label: "Dockerfile only",
    blurb: "Only a Dockerfile with a floating php:8.4-fpm tag, no output from the running server. FirstWatch abstains: without the installed version there is nothing to prove.",
  },
] as const;

// The php:8.1 image run stays recorded in fixtures/ and in the eval; it is no longer a button.

// Named explicitly, so reordering the buttons never changes what a visitor lands on.
export const DEFAULT_EXAMPLE = "g-split-cli-patched-fpm-stale";

// "Try with sample output" on the check-your-own-server path fills in this example's output, and Check replays its recording.
export const SAMPLE_EXAMPLE = "a-ubuntu2204-patched";

export type Example = {
  id: string;
  label: string;
  blurb: string;
  /** The verdict this example is expected to reach, from its case file. */
  expected: string;
  /** os-release, php -v and dpkg output, as one pasted block. */
  runtime: string;
  /** Optional config files, keyed by name. */
  config: Record<string, string>;
};

const caseDir = (id: string) => join(process.cwd(), "eval", "cases", id);
const read = (dir: string, f: string) => (existsSync(join(dir, f)) ? readFileSync(join(dir, f), "utf8").trimEnd() : "");

export function loadExamples(): Example[] {
  return EXAMPLES.map(({ id, label, blurb }) => {
    const dir = caseDir(id);
    const spec = JSON.parse(readFileSync(join(dir, "case.json"), "utf8")) as { expect: { verdict: string } };
    const runtime = [
      ["cat /etc/os-release", read(dir, "os-release")],
      ["php -v", read(dir, "php-v.txt")],
      ["dpkg -l 'php*' 'libapache2-mod-php*'", read(dir, "dpkg.txt")],
    ]
      .filter(([, t]) => t)
      .map(([cmd, t]) => `$ ${cmd}\n${t}`)
      .join("\n");
    const config: Record<string, string> = {};
    for (const [file, slot] of [["Dockerfile", "Dockerfile"], ["php.ini", "php.ini"], ["nginx.conf", "nginx.conf"], ["vhost.conf", "nginx.conf"]]) {
      const t = read(dir, file);
      if (t) config[slot] = t;
    }
    return { id, label, blurb, expected: spec.expect.verdict, runtime, config };
  });
}

export function caseSpec(id: string | undefined): CaseSpec {
  if (!id || !EXAMPLES.some((e) => e.id === id)) return DEFAULT_SPEC;
  const c = JSON.parse(readFileSync(join(caseDir(id), "case.json"), "utf8")) as Partial<CaseSpec>;
  return { ...DEFAULT_SPEC, ...c, cves: c.cves ?? DEFAULT_SPEC.cves, sources: c.sources ?? DEFAULT_SPEC.sources };
}

/** A saved report for this example, if a run has been recorded. */
export function savedRun(id: string | undefined): { report: unknown; usage?: { total?: number }; digestUsage?: unknown; model?: string } | null {
  if (!id || !EXAMPLES.some((e) => e.id === id)) return null;
  const path = join(process.cwd(), "fixtures", `${id}.json`);
  if (!existsSync(path)) return null;
  const saved = JSON.parse(readFileSync(path, "utf8")) as { report: unknown; usage?: { total?: number }; digestUsage?: unknown; model?: string };
  return saved.report ? saved : null;
}

/** The ledger a saved run was checked against: recorded with the run, or rebuilt by scripts/build-ledgers.mts. */
export function savedLedger(id: string | undefined): import("./agent").SavedLedger | null {
  if (!id) return null;
  const run = savedRun(id) as { ledger?: import("./agent").SavedLedger } | null;
  if (run?.ledger) return run.ledger;
  const path = join(process.cwd(), "fixtures", `${id}.ledger.json`);
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : null;
}

/** An example's recorded result, computed on the server so the first paint already shows it. Code only. */
export type InitialRun = {
  exampleId: string;
  report: unknown;
  recorded: { at: string | null; model: string; tokens: number | null };
  scanner: { overall: Verdict; version: string | null };
  packageAware: PackageAware;
  ecosystem: string | null;
  parsed: string | null;
};

export function initialRun(id: string): InitialRun | null {
  const saved = savedRun(id);
  const example = loadExamples().find((e) => e.id === id);
  if (!saved || !example) return null;
  // The same files the page sends when this example is clicked.
  const parts = splitRuntime(example.runtime);
  const files = Object.fromEntries(
    Object.entries({ "os-release": parts["os-release"], "php-v.txt": parts["php-v.txt"], "dpkg.txt": parts["dpkg.txt"], ...example.config }).filter(([, t]) => t.trim()),
  );
  const parsed = parse_stack(files);
  const spec = caseSpec(id);
  const ranges = spec.cves.flatMap((c) => {
    const rec = cachedCveNow(c);
    return rec && "found" in rec && rec.found ? rec.affected.filter((a) => a.product === "php/php").map((a) => a.range) : [];
  });
  const version = parsed.ok ? (scannerVersion(parsed.facts)?.version ?? null) : null;
  const report = saved.report as { assessed_at?: string };
  return {
    exampleId: id,
    report: saved.report,
    recorded: { at: report.assessed_at ?? null, model: saved.model ?? "openai/gpt-oss-120b", tokens: saved.usage?.total ?? null },
    scanner: { overall: baselineVerdict(version, ranges).verdict, version },
    packageAware: packageAwareFrom(parsed.ok ? parsed : null, spec.cves, savedLedger(id)?.distro ?? []),
    ecosystem: parsed.ok ? (parsed.ecosystems[0] ?? null) : null,
    parsed: parsed.ok ? parsed.summary : null,
  };
}
