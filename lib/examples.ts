/**
 * Example stacks for the web page, taken from the eval cases, and saved
 * reports that can be replayed without calling a model.
 *
 * Server only: reads from disk.
 */

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

/** The upload slots on the page, in order. Each maps to a file name parse_stack understands. */
export const FIELDS = [
  { file: "Dockerfile", label: "Dockerfile" },
  { file: "php.ini", label: "php.ini" },
  { file: "nginx.conf", label: "nginx.conf or Apache vhost" },
  { file: "os-release", label: "cat /etc/os-release", runtime: true },
  { file: "php-v.txt", label: "php -v", runtime: true },
  { file: "dpkg.txt", label: "dpkg -l 'php*' 'libapache2-mod-php*'", runtime: true },
] as const;

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
  { id: "a-ubuntu2204-patched", label: "Ubuntu 22.04, patched" },
  { id: "e-debian12-no-security-pocket", label: "Debian 12, no security pocket" },
  { id: "f-upstream-php81-fpm-image", label: "Official php:8.1 image" },
] as const;

export type Example = { id: string; label: string; description: string; files: Record<string, string> };

const caseDir = (id: string) => join(process.cwd(), "eval", "cases", id);

/** Which case file goes in which upload slot. */
const SLOT: Record<string, string> = {
  Dockerfile: "Dockerfile",
  "php.ini": "php.ini",
  "nginx.conf": "nginx.conf",
  "vhost.conf": "nginx.conf",
  "os-release": "os-release",
  "php-v.txt": "php-v.txt",
  "dpkg.txt": "dpkg.txt",
};

export function loadExamples(): Example[] {
  return EXAMPLES.map(({ id, label }) => {
    const dir = caseDir(id);
    const spec = JSON.parse(readFileSync(join(dir, "case.json"), "utf8")) as { description: string };
    const files: Record<string, string> = {};
    for (const f of readdirSync(dir)) if (SLOT[f]) files[SLOT[f]] = readFileSync(join(dir, f), "utf8");
    return { id, label, description: spec.description, files };
  });
}

export function caseSpec(id: string | undefined): CaseSpec {
  if (!id || !EXAMPLES.some((e) => e.id === id)) return DEFAULT_SPEC;
  const c = JSON.parse(readFileSync(join(caseDir(id), "case.json"), "utf8")) as Partial<CaseSpec>;
  return { ...DEFAULT_SPEC, ...c, cves: c.cves ?? DEFAULT_SPEC.cves, sources: c.sources ?? DEFAULT_SPEC.sources };
}

/** A saved report for this example, if a run has been recorded. */
export function savedRun(id: string | undefined): { report: unknown; usage?: unknown; digestUsage?: unknown } | null {
  if (!id || !EXAMPLES.some((e) => e.id === id)) return null;
  const path = join(process.cwd(), "fixtures", `${id}.json`);
  if (!existsSync(path)) return null;
  const saved = JSON.parse(readFileSync(path, "utf8")) as { report: unknown; usage?: unknown; digestUsage?: unknown };
  return saved.report ? saved : null;
}
