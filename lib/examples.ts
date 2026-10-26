/**
 * Example stacks for the web page, taken from the eval cases, and saved
 * reports that can be replayed without calling a model.
 *
 * Server only: reads from disk.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

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
] as const;

// The php:8.1 image run stays recorded in fixtures/ and in the eval; it is no longer a button.

// Named explicitly, so reordering the buttons never changes what a visitor lands on.
export const DEFAULT_EXAMPLE = "g-split-cli-patched-fpm-stale";

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
