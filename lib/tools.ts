/**
 * The four tools the FirstWatch agent can call.
 *
 * Contract for all of them: return a plain JSON object, never throw. A dead
 * host, a rate limit or a bad argument comes back as data the model can read
 * and route around, instead of killing the agent loop.
 *
 * Node runtime only (cheerio needs it), so any route that imports this file
 * must declare `export const runtime = "nodejs"`.
 */

import * as cheerio from "cheerio";

const UA =
  "FirstWatch/0.1 (advisory triage; +https://github.com/rautelaKamal/firstwatch)";
const TIMEOUT_MS = 12_000;
const MAX_TEXT = 40_000; // the GHSA advisories run to ~20k chars; leave headroom

export type Fail = { ok: false; error: string };

const fail = (error: string): Fail => ({ ok: false, error });
const why = (e: unknown) => (e instanceof Error ? e.message : String(e));

function http(url: string, headers: Record<string, string> = {}) {
  return fetch(url, {
    headers: { "user-agent": UA, ...headers },
    signal: AbortSignal.timeout(TIMEOUT_MS),
    redirect: "follow",
  });
}

/**
 * The URL arrives from the model or from whatever the user pasted, so it must
 * not be able to reach the machine we are running on or the private network
 * around it. Public http(s) only.
 */
const PRIVATE_HOST =
  /^(localhost|0\.0\.0\.0|127(\.\d{1,3}){3}|10(\.\d{1,3}){3}|192\.168(\.\d{1,3}){2}|169\.254(\.\d{1,3}){2}|172\.(1[6-9]|2\d|3[01])(\.\d{1,3}){2}|\[?::1\]?|.*\.(local|internal|localhost))$/i;

function publicUrl(raw: string): URL | null {
  try {
    const u = new URL(String(raw).trim());
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return PRIVATE_HOST.test(u.hostname) ? null : u;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ *
 * TOOL 1: fetch_advisory
 * Read a page written for humans and hand back clean text.
 * This is the one that buys us the first hour.
 * ------------------------------------------------------------------ */

export type Advisory = {
  ok: true;
  url: string;
  title: string;
  text: string;
  chars: number;
  truncated: boolean;
  links: string[];
  fetchedAt: string;
};

export async function fetch_advisory(url: string): Promise<Advisory | Fail> {
  const u = publicUrl(url);
  if (!u) return fail(`"${url}" is not a public http(s) URL, so nothing was fetched.`);

  let res: Response;
  try {
    res = await http(u.href, {
      accept: "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
    });
  } catch (e) {
    return fail(`Could not reach ${u.href}: ${why(e)}`);
  }
  if (!res.ok) return fail(`${u.href} returned HTTP ${res.status} ${res.statusText}`);

  const ctype = res.headers.get("content-type") ?? "";
  const body = await res.text();

  let title = u.hostname;
  let text = body;
  let links: string[] = [];

  const isHtml =
    ctype.includes("html") || ctype.includes("xml") || /^\s*<(!doctype|html)/i.test(body);

  if (isHtml) {
    const $ = cheerio.load(body);

    // 1. Drop the page chrome. None of it describes the vulnerability, and
    //    every nav link we feed the model is context we paid for and wasted.
    $("script, style, noscript, template, svg, iframe, form, nav, header, footer, aside").remove();

    // 2. Best-effort title: the <h1> is usually the advisory headline.
    title =
      ($("h1").first().text() || $("title").first().text() || title)
        .replace(/\s+/g, " ")
        .trim() || u.hostname;

    // 3. Collect content links before flattening. Advisories chain: the page
    //    says "see the changelog", and the agent may want to follow that.
    const seen = new Set<string>();
    $("a[href]").each((_, el) => {
      try {
        const href = new URL($(el).attr("href") as string, u.href);
        if (href.protocol === "http:" || href.protocol === "https:") {
          href.hash = "";
          seen.add(href.href);
        }
      } catch {
        /* skip mailto:, javascript:, and other junk hrefs */
      }
    });
    links = [...seen].slice(0, 25);

    // 4. Turn block structure into newlines. Without this, headings, list
    //    items and table cells run together into one wall of text and the
    //    model loses the shape that tells it what is a version list.
    $("br").replaceWith("\n");
    $("td, th").append("  ");
    $("p, li, h1, h2, h3, h4, h5, h6, tr, pre, blockquote, div, section, article").append("\n");

    text = $("body").length ? $("body").text() : $.root().text();
  }

  // 5. Normalise whitespace: collapse runs of spaces, trim each line, and
  //    cap blank runs at one, keeping paragraph breaks as the only structure.
  text = text
    .replace(/ /g, " ")
    .replace(/[ \t\f\v]+/g, " ")
    .replace(/[ \t]*\r?\n[ \t]*/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  const truncated = text.length > MAX_TEXT;
  if (truncated) text = `${text.slice(0, MAX_TEXT)}\n\n[truncated at ${MAX_TEXT} chars]`;

  if (text.length < 40) {
    return fail(
      `${u.href} fetched, but held almost no readable text (${text.length} chars). It probably renders with JavaScript.`,
    );
  }

  return {
    ok: true,
    url: u.href,
    title,
    text,
    chars: text.length,
    truncated,
    links,
    fetchedAt: new Date().toISOString(),
  };
}

/* ------------------------------------------------------------------ *
 * TOOL 2: fetch_cve
 * The structured path, for when NVD has caught up. Expected to come back
 * empty during the window this product is built for.
 * ------------------------------------------------------------------ */

type NvdCpe = {
  criteria: string;
  vulnerable?: boolean;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
};

type NvdMetric = {
  baseSeverity?: string;
  cvssData?: {
    version?: string;
    baseScore?: number;
    baseSeverity?: string;
    vectorString?: string;
  };
};

type NvdCve = {
  id: string;
  published?: string;
  lastModified?: string;
  vulnStatus?: string;
  descriptions?: { lang: string; value: string }[];
  metrics?: Record<string, NvdMetric[]>;
  references?: { url: string }[];
  weaknesses?: { description?: { lang: string; value: string }[] }[];
  configurations?: { nodes?: { cpeMatch?: NvdCpe[] }[] }[];
};

const CVE_ID = /^CVE-\d{4}-\d{4,19}$/;

function pickSeverity(metrics: NvdCve["metrics"]) {
  for (const key of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const m = metrics?.[key]?.[0];
    if (!m?.cvssData) continue;
    return {
      scale: `CVSS ${m.cvssData.version ?? key.replace("cvssMetric", "")}`,
      score: m.cvssData.baseScore ?? null,
      severity: m.cvssData.baseSeverity ?? m.baseSeverity ?? "unknown",
      vector: m.cvssData.vectorString ?? null,
    };
  }
  return null;
}

/** Flatten NVD's CPE match rules into readable "product: >= a and < b" lines. */
function affectedRanges(cve: NvdCve) {
  const out: { product: string; range: string }[] = [];
  for (const cfg of cve.configurations ?? []) {
    for (const node of cfg.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        if (m.vulnerable === false) continue;
        const p = m.criteria.split(":"); // cpe:2.3:a:vendor:product:version:...
        const bounds = [
          m.versionStartIncluding && `>= ${m.versionStartIncluding}`,
          m.versionStartExcluding && `> ${m.versionStartExcluding}`,
          m.versionEndIncluding && `<= ${m.versionEndIncluding}`,
          m.versionEndExcluding && `< ${m.versionEndExcluding}`,
        ].filter(Boolean) as string[];
        const pinned = p[5] && p[5] !== "*" && p[5] !== "-" ? `= ${p[5]}` : null;
        out.push({
          product: [p[3], p[4]].filter(Boolean).join("/"),
          range: bounds.length ? bounds.join(" and ") : (pinned ?? "all versions"),
        });
      }
    }
  }
  return out.slice(0, 40);
}

export type CveRecord =
  | {
      ok: true;
      found: true;
      id: string;
      published: string | null;
      lastModified: string | null;
      status: string | null;
      description: string | null;
      severity: ReturnType<typeof pickSeverity>;
      weaknesses: string[];
      affected: { product: string; range: string }[];
      references: string[];
    }
  | { ok: true; found: false; id: string; note: string };

export async function fetch_cve(id: string): Promise<CveRecord | Fail> {
  const cveId = String(id).trim().toUpperCase();
  if (!CVE_ID.test(cveId)) return fail(`"${id}" is not a CVE id. Expected the form CVE-2024-12345.`);

  const apiKey = process.env.NVD_API_KEY;
  let res: Response;
  try {
    res = await http(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`,
      { accept: "application/json", ...(apiKey ? { apiKey } : {}) },
    );
  } catch (e) {
    return fail(`Could not reach the NVD API: ${why(e)}`);
  }

  if (res.status === 403 || res.status === 429) {
    return fail(
      `NVD rate limited this request (HTTP ${res.status}). Read the vendor advisory with fetch_advisory instead.`,
    );
  }
  if (!res.ok) return fail(`NVD returned HTTP ${res.status} for ${cveId}`);

  let payload: { vulnerabilities?: { cve: NvdCve }[] };
  try {
    payload = await res.json();
  } catch (e) {
    return fail(`NVD returned a body that is not JSON: ${why(e)}`);
  }

  const cve = payload.vulnerabilities?.[0]?.cve;
  if (!cve) {
    return {
      ok: true,
      found: false,
      id: cveId,
      note: `NVD has no record of ${cveId} yet. This is normal in the first hours of a disclosure: read the vendor advisory with fetch_advisory and reason from its text.`,
    };
  }

  return {
    ok: true,
    found: true,
    id: cve.id ?? cveId,
    published: cve.published ?? null,
    lastModified: cve.lastModified ?? null,
    status: cve.vulnStatus ?? null,
    description: cve.descriptions?.find((d) => d.lang === "en")?.value ?? null,
    severity: pickSeverity(cve.metrics),
    weaknesses: (cve.weaknesses ?? [])
      .map((w) => w.description?.find((d) => d.lang === "en")?.value ?? "")
      .filter((v) => v && v !== "NVD-CWE-noinfo" && v !== "NVD-CWE-Other"),
    affected: affectedRanges(cve),
    references: (cve.references ?? []).map((r) => r.url).slice(0, 15),
  };
}

/* ------------------------------------------------------------------ *
 * TOOL 3: compare_versions
 * Plain code, no model involved. Same ordering rules PHP's own
 * version_compare uses, so "8.3.2" beats "8.3.2rc1" and loses to "8.3.2p1".
 * ------------------------------------------------------------------ */

// Ordering of non-numeric parts. Anything numeric sorts above all of these,
// and a plain release (no tag at all) sits at 0.
const TAG_RANK: Record<string, number> = {
  dev: -6,
  alpha: -5,
  a: -5,
  beta: -4,
  b: -4,
  rc: -3,
  c: -3,
  pl: 1,
  p: 1,
  patch: 1,
};
const RELEASE = ""; // the virtual "no tag here" part

/** "8.3.2-rc1" -> ["8","3","2","rc","1"] */
function parts(version: string): string[] {
  return String(version)
    .trim()
    .toLowerCase()
    .replace(/^v/, "")
    .replace(/^\d+:/, "") // Debian epoch, as in "1:8.1.2-1ubuntu7.1"
    .replace(/[-_+~]/g, ".")
    .replace(/(\d)([a-z])/g, "$1.$2")
    .replace(/([a-z])(\d)/g, "$1.$2")
    .split(".")
    .filter((p) => p.length > 0);
}

const isNum = (p: string) => /^\d+$/.test(p);

/**
 * Is this actually a version number? A string like "^8.1.0", "1.0 || 2.0" or
 * "sometime after 8.1" splits into parts happily and would then be compared as
 * garbage, which is how a tool returns a confident wrong answer. Require a
 * leading number and parts that are each all digits or all letters.
 */
function isVersionLike(v: string): boolean {
  const p = parts(v);
  return p.length > 0 && isNum(p[0]) && p.every((x) => isNum(x) || /^[a-z]+$/.test(x));
}
const rank = (p: string) => (isNum(p) ? 10 : p === RELEASE ? 0 : (TAG_RANK[p] ?? -2));

function cmp(a: string, b: string): -1 | 0 | 1 {
  const pa = parts(a);
  const pb = parts(b);

  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    // A missing part stands in as 0 next to a number, so 1.0 equals 1.0.0,
    // and as "release" next to a tag, so 8.3.2 outranks 8.3.2rc1.
    const x = pa[i] ?? (isNum(pb[i]) ? "0" : RELEASE);
    const y = pb[i] ?? (isNum(pa[i]) ? "0" : RELEASE);

    if (isNum(x) && isNum(y)) {
      const nx = Number(x);
      const ny = Number(y);
      if (nx !== ny) return nx > ny ? 1 : -1;
      continue;
    }
    const rx = rank(x);
    const ry = rank(y);
    if (rx !== ry) return rx > ry ? 1 : -1;
    if (rx === -2 && x !== y) return x > y ? 1 : -1; // two unknown tags: alphabetical
  }
  return 0;
}

export type Comparison = {
  ok: true;
  a: string;
  b: string;
  result: -1 | 0 | 1;
  relation: "older" | "same" | "newer";
  summary: string;
};

export function compare_versions(a: string, b: string): Comparison | Fail {
  if (!a || !b) return fail("compare_versions needs two version strings.");
  const unreadable = [a, b].filter((x) => !isVersionLike(x)).map((x) => `"${x}"`);
  if (unreadable.length) {
    return fail(`Could not read ${unreadable.join(" or ")} as a version number.`);
  }

  const result = cmp(a, b);
  const relation = result === 0 ? "same" : result < 0 ? "older" : "newer";
  const word = result === 0 ? "the same version as" : result < 0 ? "older than" : "newer than";

  return { ok: true, a, b, result, relation, summary: `${a} is ${word} ${b}.` };
}
/* ------------------------------------------------------------------ *
 * TOOL 4: check_eol
 * The "there is no patch coming" path. If the branch is dead, the fix plan
 * is not "update", it is "move branches or isolate the service".
 * ------------------------------------------------------------------ */

type Cycle = {
  cycle: string;
  releaseDate?: string;
  eol?: string | boolean;
  support?: string | boolean;
  latest?: string;
  lts?: boolean | string;
};

const DAY = 86_400_000;
const asDate = (v: unknown) => (typeof v === "string" && !Number.isNaN(Date.parse(v)) ? new Date(v) : null);
const past = (v: unknown) => v === true || (asDate(v)?.getTime() ?? Infinity) <= Date.now();

export type EolReport =
  | {
      ok: true;
      found: true;
      product: string;
      version: string;
      cycle: string;
      isEol: boolean;
      eol: string | boolean;
      daysPastEol: number | null;
      activeSupportEnded: boolean;
      latestInCycle: string | null;
      supportedCycles: string[];
      recommendation: string;
    }
  | { ok: true; found: false; product: string; version: string; note: string; cycles?: string[] };

export async function check_eol(product: string, version: string): Promise<EolReport | Fail> {
  const slug = String(product).trim().toLowerCase().replace(/\s+/g, "-");
  const v = String(version).trim().replace(/^v/i, "");
  if (!slug) return fail("check_eol needs a product name, for example \"php\".");
  if (!v) return fail(`check_eol needs a version for ${slug}, for example "8.1.27".`);

  let res: Response;
  try {
    res = await http(`https://endoflife.date/api/${encodeURIComponent(slug)}.json`, {
      accept: "application/json",
    });
  } catch (e) {
    return fail(`Could not reach endoflife.date: ${why(e)}`);
  }

  if (res.status === 404) {
    return {
      ok: true,
      found: false,
      product: slug,
      version: v,
      note: `endoflife.date has no product called "${slug}". Try its exact slug, for example "php", "nodejs", "ubuntu", "postgresql".`,
    };
  }
  if (!res.ok) return fail(`endoflife.date returned HTTP ${res.status} for "${slug}"`);

  let cycles: Cycle[];
  try {
    cycles = await res.json();
  } catch (e) {
    return fail(`endoflife.date returned a body that is not JSON: ${why(e)}`);
  }
  if (!Array.isArray(cycles) || !cycles.length) return fail(`No release cycles listed for "${slug}".`);

  // "8.1.27" belongs to cycle "8.1". Longest match first, so 8.1 wins over 8.
  const cycle = [...cycles]
    .sort((x, y) => String(y.cycle).length - String(x.cycle).length)
    .find((c) => v === String(c.cycle) || v.startsWith(`${c.cycle}.`));

  const supportedCycles = cycles.filter((c) => !past(c.eol)).map((c) => String(c.cycle));

  if (!cycle) {
    return {
      ok: true,
      found: false,
      product: slug,
      version: v,
      note: `Version ${v} does not match any listed ${slug} release cycle. It may be unreleased, custom built, or a distribution fork.`,
      cycles: cycles.map((c) => String(c.cycle)),
    };
  }

  const eol = cycle.eol ?? false;
  const isEol = past(eol);
  const eolDate = asDate(eol);
  const daysPastEol = isEol && eolDate ? Math.floor((Date.now() - eolDate.getTime()) / DAY) : null;

  const recommendation = isEol
    ? `${slug} ${cycle.cycle} is end of life${eolDate ? ` (since ${eolDate.toISOString().slice(0, 10)}, ${daysPastEol} days)` : ""}, so no patch will be released for ${v}. Move to a supported branch (${supportedCycles.join(", ") || "none listed"}) or isolate the service until you can.`
    : `${slug} ${cycle.cycle} is still supported${eolDate ? ` until ${eolDate.toISOString().slice(0, 10)}` : ""}. Patch inside the branch: the latest release is ${cycle.latest ?? "unknown"}.`;

  return {
    ok: true,
    found: true,
    product: slug,
    version: v,
    cycle: String(cycle.cycle),
    isEol,
    eol,
    daysPastEol,
    activeSupportEnded: past(cycle.support),
    latestInCycle: cycle.latest ?? null,
    supportedCycles,
    recommendation,
  };
}
/* ------------------------------------------------------------------ *
 * TOOL 5: version_in_range
 * The same arithmetic as compare_versions, applied to a range.
 *
 * This exists because advisories and CVE records state affected versions
 * as ranges (">= 8.1.0 and < 8.1.29"), and asking the model to reach that
 * verdict by chaining two compare_versions calls is exactly where it would
 * get a boundary wrong and announce "you are safe". The boundary is decided
 * here, in code. Note that it parses the same strings fetch_cve emits.
 * ------------------------------------------------------------------ */

const CLAUSE_SPLIT = /\s*(?:,|;|&&|\band\b)\s*/i;
const HYPHEN_RANGE = /^([^\s<>=!]+)\s*(?:-|–|\bto\b|\bthrough\b)\s*([^\s<>=!]+)$/i;
const OPEN_RANGE = /^(all versions?|all|any|\*|-)$/i;

/** true, false, or null when the clause is not something we can read. */
function satisfies(version: string, clause: string): boolean | null {
  const m = clause.trim().match(/^(>=|=>|<=|=<|==|!=|>|<|=)?\s*(.+)$/);
  if (!m) return null;
  const op = (m[1] ?? "=").replace("=>", ">=").replace("=<", "<=").replace("==", "=");
  const target = m[2].trim().replace(/^v/i, "");

  // "8.1.x" and "8.1.*" mean the whole 8.1 branch.
  if (/[x*]$/i.test(target)) {
    const prefix = target.replace(/[.\s]*[x*]$/i, "").trim();
    const hit = !prefix || version === prefix || version.startsWith(`${prefix}.`);
    return op === "!=" ? !hit : hit;
  }
  if (!isVersionLike(target)) return null;

  const c = cmp(version, target);
  switch (op) {
    case ">":
      return c > 0;
    case ">=":
      return c >= 0;
    case "<":
      return c < 0;
    case "<=":
      return c <= 0;
    case "!=":
      return c !== 0;
    case "=":
      return c === 0;
    default:
      return null;
  }
}

export type RangeCheck = {
  ok: true;
  version: string;
  range: string;
  inRange: boolean;
  clauses: { clause: string; satisfied: boolean }[];
  summary: string;
};

export function version_in_range(version: string, range: string): RangeCheck | Fail {
  const v = String(version ?? "").trim().replace(/^v/i, "");
  const r = String(range ?? "").trim();
  if (!isVersionLike(v)) return fail(`"${version}" is not a version number.`);
  if (DISTRO_VERSION.test(v)) {
    return fail(
      `"${version}" is a distro package version. Upstream ranges do not apply to it, because distributions backport fixes without changing the upstream number. Use check_distro_fix.`,
    );
  }
  if (!r) return fail('version_in_range needs a range, for example ">= 8.1.0, < 8.1.29".');

  const verdict = (clauses: { clause: string; satisfied: boolean }[]): RangeCheck => {
    const inRange = clauses.every((c) => c.satisfied);
    const missed = clauses.filter((c) => !c.satisfied).map((c) => c.clause);
    return {
      ok: true,
      version: v,
      range: r,
      inRange,
      clauses,
      summary: inRange
        ? `${v} is inside "${r}".`
        : `${v} is outside "${r}": it fails ${missed.join(" and ")}.`,
    };
  };

  if (OPEN_RANGE.test(r)) return verdict([{ clause: r, satisfied: true }]);

  // "8.2.0 - 8.2.34" is inclusive at both ends. Only read a string as a
  // hyphen range when it carries no comparators of its own, so that a
  // prerelease hyphen in "> 8.3.2-rc1" is not mistaken for a range.
  const hyphen = /[<>=]/.test(r) ? null : r.match(HYPHEN_RANGE);
  const raw = hyphen
    ? [`>= ${hyphen[1]}`, `<= ${hyphen[2]}`]
    : r.split(CLAUSE_SPLIT).filter((c) => c.trim().length > 0);
  if (!raw.length) return fail(`Could not read "${r}" as a range.`);

  const checked = raw.map((clause) => ({ clause: clause.trim(), satisfied: satisfies(v, clause) }));
  const unreadable = checked.filter((c) => c.satisfied === null).map((c) => `"${c.clause}"`);
  if (unreadable.length) {
    return fail(
      `Could not read ${unreadable.join(", ")} as a version constraint. Readable forms: ">= 8.1.0, < 8.1.29", "8.2.0 - 8.2.34", "<= 1.4.9", "8.1.x", "all versions". A range with "||" must be checked one alternative at a time.`,
    );
  }
  return verdict(checked as { clause: string; satisfied: boolean }[]);
}


/* ------------------------------------------------------------------ *
 * TOOL 6: parse_stack
 * Plain code, no model. A version scanner reads one version string.
 * This reads what is actually installed: every PHP package with its
 * exact distro version, the release it came from, the SAPI, and the ini
 * settings advisories name.
 *
 * It distinguishes runtime evidence (dpkg -l, php -v: what IS installed)
 * from build intent (a Dockerfile tag: what was asked for). Verdicts
 * depend on that difference, so every fact records which it is.
 * ------------------------------------------------------------------ */

export type Fact = {
  /** Dotted name, e.g. pkg.php8.3-fpm, php.sapi, os.ecosystem, ini.memory_limit. */
  field: string;
  value: string;
  /** runtime: observed on the running system. build: declared in a build file. */
  kind: "runtime" | "build";
  file: string;
  line: number;
  text: string;
};

export type StackFacts = {
  ok: true;
  summary: string;
  /** OSV ecosystem candidates, most specific first, or [] if undetermined. */
  ecosystems: string[];
  packages: { name: string; version: string; source: string | null; kind: "runtime" | "build"; where: string }[];
  facts: Fact[];
  hasRuntimeEvidence: boolean;
  unverified: string[];
  filesSeen: { name: string; kind: string; lines: number }[];
};

export type StackFiles = Record<string, string> | { name: string; content: string }[];

const SAPI_FROM_TAG: [RegExp, string][] = [
  [/frankenphp/i, "frankenphp"],
  [/litespeed|lsphp/i, "litespeed"],
  [/-fpm/i, "fpm"],
  [/-apache/i, "apache-mod_php"],
  [/-cgi\b/i, "cgi"],
  [/-cli\b/i, "cli"],
];

const SAPI_FROM_PACKAGE: [RegExp, string][] = [
  [/libapache2-mod-php|mod_php/i, "apache-mod_php"],
  [/php[\d.]*-fpm|php-fpm/i, "fpm"],
  [/php[\d.]*-cgi\b|php-cgi\b/i, "cgi"],
  [/php[\d.]*-cli\b|php-cli\b/i, "cli"],
];

const INI_OF_INTEREST =
  /^(memory_limit|post_max_size|upload_max_filesize|max_file_uploads|max_execution_time|enable_post_data_reading|auto_detect_line_endings|fatal_error_backtraces|display_errors|log_errors|error_reporting|zend\.assertions|session\.upload_progress\.[a-z_]+|session\.auto_start|opcache\.[a-z_]+)$/i;

/**
 * OSV indexes Debian and Ubuntu by SOURCE package. php8.3-fpm and
 * libapache2-mod-php8.3 both come from source php8.3, and querying the binary
 * name returns nothing at all, which must never be mistaken for "not affected".
 */
export function sourcePackageOf(binary: string): string | null {
  const n = binary.trim().toLowerCase();
  const embed = n.match(/^libphp(\d+\.\d+)(?:-embed)?$/);
  if (embed) return `php${embed[1]}`;
  const m = n.match(/^(?:libapache2-mod-)?(php\d+(?:\.\d+)?)(?:-[a-z0-9+.-]+)?$/);
  if (m) return m[1];
  return null; // unversioned (php-fpm, php-cli) or not a PHP package
}

/** Ubuntu LTS releases are even year .04; OSV spells them "Ubuntu:22.04:LTS". */
function ubuntuEcosystems(release: string): string[] {
  const lts = /^\d\d\.04$/.test(release) && Number(release.split(".")[0]) % 2 === 0;
  return lts
    ? [`Ubuntu:${release}:LTS`, `Ubuntu:Pro:${release}:LTS`, `Ubuntu:${release}`]
    : [`Ubuntu:${release}`, `Ubuntu:${release}:LTS`];
}

const DEBIAN_CODENAMES: Record<string, string> = {
  stretch: "9", buster: "10", bullseye: "11", bookworm: "12", trixie: "13", forky: "14",
};

function classify(name: string, content: string): string {
  const n = name.toLowerCase();
  if (/dockerfile/.test(n)) return "dockerfile";
  if (/docker-compose|compose\.ya?ml/.test(n)) return "compose";
  if (/os-release/.test(n)) return "os-release";
  if (/^ii\s+\S+\s+\S+/m.test(content) || /^Desired=|dpkg -l/m.test(content)) return "dpkg";
  if (/^PHP \d+\.\d+\.\d+/m.test(content) || /Zend Engine v/.test(content)) return "php-v";
  if (/\.ini$|^php\.ini|conf\.d/.test(n)) return "php.ini";
  if (/fastcgi_pass|server\s*\{/.test(content)) return "nginx";
  if (/<VirtualHost|LoadModule|php_admin_value|SetHandler/i.test(content)) return "apache";
  if (/^\s*\[www\]|pm\.max_children|pm\.max_requests/m.test(content)) return "php-fpm-pool";
  if (/^\s*[a-z_.]+\s*=/m.test(content)) return "php.ini";
  return "unknown";
}

export function parse_stack(files: StackFiles): StackFacts | Fail {
  let entries: { name: string; content: string }[];
  try {
    entries = Array.isArray(files)
      ? files.map((f) => ({ name: String(f?.name ?? "file"), content: String(f?.content ?? "") }))
      : Object.entries(files ?? {}).map(([name, content]) => ({ name, content: String(content ?? "") }));
  } catch (e) {
    return fail(`Could not read the uploaded files: ${why(e)}`);
  }
  if (!entries.length) return fail("parse_stack was given no files.");

  const facts: Fact[] = [];
  const packages: StackFacts["packages"] = [];
  const phpvSeen: { version: string; file: string; line: number; text: string }[] = [];
  const filesSeen: StackFacts["filesSeen"] = [];
  let distro: { id: string; release: string } | null = null;

  const add = (field: string, value: string, kind: Fact["kind"], file: string, line: number, text: string) =>
    facts.push({ field, value, kind, file, line, text: text.trim().slice(0, 240) });

  const addPackage = (name: string, version: string, kind: "runtime" | "build", file: string, line: number, text: string) => {
    const source = sourcePackageOf(name);
    const existing = packages.find((p) => p.name === name && p.version === version);
    if (!existing) {
      packages.push({ name, version, source, kind, where: `${file}:${line}` });
    } else if (kind === "runtime" && existing.kind === "build") {
      // Seen at runtime too: that is the stronger evidence, so it wins.
      existing.kind = "runtime";
      existing.where = `${file}:${line}`;
    }
    add(`pkg.${name}`, version, kind, file, line, text);
    if (!source) add(`pkg.${name}.unmapped`, "no source package could be derived from this name", kind, file, line, text);
  };

  for (const { name, content } of entries) {
    const lines = content.split("\n");
    let kind = "unknown";
    let inUlimits = false;
    try {
      kind = classify(name, content);

      lines.forEach((raw, idx) => {
        const line = raw.trim();
        const no = idx + 1;
        if (!line || line.startsWith("#") || line.startsWith(";")) return;

        // ---- runtime evidence: dpkg -l output ----
        // ii  php8.3-fpm  8.3.6-0ubuntu0.24.04.13  amd64  server-side ...
        const dpkg = line.match(/^(i[iHUFW]|hi|rc)\s+(\S+?)(?::\S+)?\s+(\S+)\s+(\S+)/);
        if (dpkg && /php/i.test(dpkg[2])) {
          addPackage(dpkg[2], dpkg[3], "runtime", name, no, line);
          const sapi = SAPI_FROM_PACKAGE.find(([re]) => re.test(dpkg[2]));
          if (sapi) add("php.sapi", sapi[1], "runtime", name, no, line);
        }

        // ---- runtime evidence: php -v ----
        const phpv = line.match(/^PHP\s+(\d+\.\d+\.\d+\S*)\s*(?:\(([^)]+)\))?/i);
        if (phpv) {
          add("php.version", phpv[1], "runtime", name, no, line);
          // Not a package. php -v describes the one binary it ran, usually the
          // CLI, and treating it as package evidence is the false-safety bug
          // this whole tool exists to avoid. It is promoted to a package below
          // only when no distro PHP package exists at all.
          phpvSeen.push({ version: phpv[1], file: name, line: no, text: line });
          if (phpv[2]) {
            const sapiName = phpv[2].toLowerCase();
            const mapped =
              sapiName.includes("fpm") ? "fpm"
              : sapiName.includes("cgi") ? "cgi"
              : sapiName.includes("apache") ? "apache-mod_php"
              : sapiName.includes("cli") ? "cli"
              : sapiName;
            add("php.sapi", mapped, "runtime", name, no, line);
          }
        }

        // ---- runtime evidence: /etc/os-release ----
        if (kind === "os-release") {
          const m = line.match(/^(ID|VERSION_ID|PRETTY_NAME|VERSION_CODENAME)=(.*)$/);
          if (m) {
            const value = m[2].replace(/^"|"$/g, "");
            add(`os.${m[1].toLowerCase()}`, value, "runtime", name, no, line);
            if (m[1] === "ID") distro = { id: value.toLowerCase(), release: distro?.release ?? "" };
            if (m[1] === "VERSION_ID") distro = { id: distro?.id ?? "", release: value };
            if (m[1] === "VERSION_CODENAME" && DEBIAN_CODENAMES[value.toLowerCase()]) {
              distro = { id: distro?.id || "debian", release: distro?.release || DEBIAN_CODENAMES[value.toLowerCase()] };
            }
          }
        }

        // ---- build intent: base image ----
        const from = line.match(/^FROM\s+(\S+)/i) ?? line.match(/^\s*image:\s*["']?([^\s"']+)/i);
        if (from) {
          const image = from[1];
          add("docker.base_image", image, "build", name, no, line);
          const upstream = image.match(/(?:^|\/)php:(\d+(?:\.\d+){0,2})/i);
          if (upstream) {
            add("php.version", upstream[1], "build", name, no, line);
            add("php.distribution", "upstream docker image", "build", name, no, line);
            addPackage("php", upstream[1], "build", name, no, line);
            if (upstream[1].split(".").length < 3) {
              add("php.version.floating_tag", upstream[1], "build", name, no, line);
            }
          }
          for (const [re, sapi] of SAPI_FROM_TAG) {
            if (re.test(image)) {
              add("php.sapi", sapi, "build", name, no, line);
              break;
            }
          }
          const base = image.match(/^(debian|ubuntu):([\w.]+)/i);
          if (base) {
            const rel = base[2].toLowerCase();
            const release = DEBIAN_CODENAMES[rel] ?? rel.replace(/-slim$/, "");
            distro = { id: base[1].toLowerCase(), release };
            add("os.distro", `${base[1].toLowerCase()} ${release}`, "build", name, no, line);
          }
          const tagged = image.match(/(bookworm|bullseye|trixie|forky|alpine)/i);
          if (tagged && !distro) {
            const t = tagged[1].toLowerCase();
            if (DEBIAN_CODENAMES[t]) distro = { id: "debian", release: DEBIAN_CODENAMES[t] };
            add("os.distro", t, "build", name, no, line);
          }
        }

        // ---- build intent: pinned apt installs ----
        const pins = line.matchAll(/\b((?:libapache2-mod-)?php[\d.]*[a-z0-9+-]*)\s*=\s*([\w.:+~-]+)/gi);
        for (const pin of pins) addPackage(pin[1], pin[2], "build", name, no, line);
        if (/\b(apt-get|apt|apk)\b.*\binstall\b/i.test(line)) {
          for (const [re, sapi] of SAPI_FROM_PACKAGE) {
            if (re.test(line)) {
              add("php.sapi", sapi, "build", name, no, line);
              break;
            }
          }
        }

        // ---- ini settings, wherever they are declared ----
        const ini = line.match(/^([a-z_][a-z0-9_.]*)\s*=\s*(.*?)\s*$/i);
        if (ini && INI_OF_INTEREST.test(ini[1])) {
          add(`ini.${ini[1].toLowerCase()}`, ini[2] || "(empty)", kind === "dpkg" ? "runtime" : "build", name, no, line);
        }
        const wrapped = line.match(/php_(?:admin_)?(?:value|flag)\s*\[?([a-z0-9_.]+)\]?\s*=?\s*(.*)/i);
        if (wrapped?.[1]) add(`ini.${wrapped[1].toLowerCase()}`, (wrapped[2] || "").trim() || "(empty)", "build", name, no, line);

        // ---- frontend ----
        const grab = (re: RegExp, field: string) => {
          const m = line.match(re);
          if (m) add(field, (m[1] ?? "").trim() || "yes", "build", name, no, line);
        };
        grab(/fastcgi_param\s+PHP_(?:ADMIN_)?VALUE\s*(.*)/i, "frontend.sends_php_value");
        grab(/fastcgi_pass\s+(\S+)/i, "frontend.fastcgi_pass");
        grab(/client_max_body_size\s+(\S+)/i, "frontend.client_max_body_size");
        grab(/^pm\.max_requests\s*=\s*(\S+)/i, "fpm.pm_max_requests");

        // ---- resource limits an advisory may warn against ----
        // RLIMIT_AS and RLIMIT_DATA make allocations fail, which is the very
        // failure CVE-2026-109618 needs. Record them so they can be flagged.
        const limit = (field: string, re: RegExp, as: Fact["kind"] = "build") => {
          const m = line.match(re);
          if (m && !/^unlimited$|^-1$/i.test(m[1])) add(field, m[1], as, name, no, line);
        };
        limit("limit.rlimit_as", /\bulimit\b[^#]*?\s-[a-z]*v\s+(\S+)/i);
        limit("limit.rlimit_data", /\bulimit\b[^#]*?\s-[a-z]*d\s+(\S+)/i);
        limit("limit.rlimit_as", /^LimitAS\s*=\s*(\S+)/i);
        limit("limit.rlimit_data", /^LimitDATA\s*=\s*(\S+)/i);
        limit("limit.rlimit_as", /--ulimit[ =]as=(\S+)/i);
        limit("limit.rlimit_data", /--ulimit[ =]data=(\S+)/i);
        limit("limit.rlimit_as", /\bprlimit\b.*--as=(\S+)/i);
        limit("limit.rlimit_data", /\bprlimit\b.*--data=(\S+)/i);
        // `ulimit -a` pasted from the running system is runtime evidence.
        limit("limit.rlimit_as", /virtual memory\s+\(kbytes,\s*-v\)\s+(\S+)/i, "runtime");
        limit("limit.rlimit_data", /data seg size\s+\(kbytes,\s*-d\)\s+(\S+)/i, "runtime");
        if (/^ulimits\s*:/i.test(line)) inUlimits = true;
        if (inUlimits) {
          limit("limit.rlimit_as", /^as\s*:\s*(\S+)/i);
          limit("limit.rlimit_data", /^data\s*:\s*(\S+)/i);
        }
      });
    } catch (e) {
      add("file.parse_error", why(e), "build", name, 1, `could not parse ${name}`);
    }
    filesSeen.push({ name, kind, lines: lines.length });
  }

  // ---- php -v as a last resort ----
  // An upstream source build (an official php: image, or ./configure) has no
  // distro package to ask OSV about, so php -v is the only installed-version
  // evidence that exists. Where distro packages ARE installed, their own
  // versions are authoritative and php -v adds nothing but confusion.
  if (!packages.some((pk) => pk.source)) {
    for (const v of phpvSeen) addPackage("php", v.version, "runtime", v.file, v.line, v.text);
  }

  // ---- ecosystem ----
  const ecosystems: string[] = [];
  if (distro) {
    const d = distro as { id: string; release: string };
    if (d.id === "ubuntu" && d.release) ecosystems.push(...ubuntuEcosystems(d.release));
    else if (d.id === "debian" && d.release) ecosystems.push(`Debian:${d.release}`);
    if (ecosystems.length) {
      const first = facts.find((f) => f.field.startsWith("os."));
      facts.push({
        field: "os.ecosystem",
        value: ecosystems[0],
        kind: first?.kind ?? "build",
        file: first?.file ?? "derived",
        line: first?.line ?? 0,
        text: `derived from ${d.id} ${d.release}`,
      });
    }
  }

  const hasRuntimeEvidence = facts.some((f) => f.kind === "runtime");
  // dpkg lists php8.3-cli before php8.3-fpm, so "first match" would report the
  // CLI. What serves traffic is what matters, so prefer that.
  const SAPI_PRIORITY = ["apache-mod_php", "fpm", "frankenphp", "litespeed", "cgi", "cli"];
  const sapiFacts = facts.filter((f) => f.field === "php.sapi");
  const sapi =
    SAPI_PRIORITY.map((want) => sapiFacts.find((f) => f.value === want)).find(Boolean) ?? sapiFacts[0];
  const runtimePkgs = packages.filter((p) => p.kind === "runtime");

  // ---- what the files do not answer ----
  const unverified: string[] = [];
  if (!hasRuntimeEvidence) {
    unverified.push(
      "Any runtime evidence. Nothing here shows what is actually installed, only what the build asked for. Paste the output of `dpkg -l 'php*' 'libapache2-mod-php*'`, `php -v` and `cat /etc/os-release`.",
    );
  }
  if (!runtimePkgs.length && packages.length) {
    unverified.push(
      "Installed package versions. The versions above come from build files, and a rebuilt image may differ. Paste `dpkg -l 'php*' 'libapache2-mod-php*'` from the running container.",
    );
  }
  if (!packages.length) {
    unverified.push("Any PHP package or version. Paste `dpkg -l 'php*'` or `php -v`.");
  }
  const floating = facts.find((f) => f.field === "php.version.floating_tag");
  if (floating) {
    unverified.push(
      `The exact patch version. "${floating.value}" is a floating image tag (${floating.file}:${floating.line}), which resolves to whatever was current at build time, so it cannot be matched against a range that splits inside that branch. Get it from \`php -v\`.`,
    );
  }
  if (!ecosystems.length && packages.some((p) => /[~+]|ubuntu|deb\d/i.test(p.version))) {
    unverified.push(
      "The distro release. Package versions look distro-built, but no release was identified, and the OSV ecosystem depends on it. Paste `cat /etc/os-release`.",
    );
  }
  if (!sapi) {
    unverified.push("Which SAPI serves requests. Get it from `php -i | grep 'Server API'`.");
  }
  for (const p of packages) {
    if (p.source) continue;
    if (/^(?:lib)?(?:apache2-mod-)?php[\d.-]/i.test(p.name)) {
      unverified.push(
        `Which source package ${p.name} comes from. OSV indexes Debian and Ubuntu by source package, and this name cannot be mapped. Use the exact binary package names from \`dpkg -l\`.`,
      );
    } else if (p.name === "php") {
      unverified.push(
        `Whether ${p.name} ${p.version} is a distro package at all. No distro PHP package is installed, which means this is an upstream build (an official php: image or a source build). Distro backports do not apply to it, so assess it against the upstream affected ranges and its branch's support status.`,
      );
    }
  }
  if (!facts.some((f) => f.field.startsWith("ini."))) {
    unverified.push("Effective php.ini values. Get them from `php -i` or `php --ini`.");
  }

  const summary = [
    packages.length ? `${packages.length} PHP package(s)` : "no PHP packages found",
    runtimePkgs.length ? `${runtimePkgs.length} from runtime evidence` : "none from runtime evidence",
    ecosystems[0] ?? "ecosystem unknown",
    sapi ? `SAPI ${sapi.value}` : "SAPI unknown",
    `${facts.filter((f) => f.field.startsWith("ini.")).length} ini settings`,
  ].join(", ");

  return { ok: true, summary, ecosystems, packages, facts, hasRuntimeEvidence, unverified: [...new Set(unverified)], filesSeen };
}

/* ------------------------------------------------------------------ *
 * TOOL 7: check_distro_fix
 * Ask OSV to evaluate an exact distro package version against a CVE.
 *
 * Two traps this exists to avoid:
 *
 * 1. OSV indexes Debian and Ubuntu by SOURCE package. Querying php8.1-fpm
 *    returns zero vulnerabilities, which looks exactly like "patched" and
 *    is not. So binary names are mapped to source names first.
 * 2. A clean query result only means something if OSV actually holds this
 *    CVE for this ecosystem and package. So that is checked first, and when
 *    it does not, the answer is "unknown", never "fixed".
 * ------------------------------------------------------------------ */

const OSV = "https://api.osv.dev/v1";

export type DistroFixStatus = "fixed" | "affected" | "unknown";

export type DistroFix = {
  ok: true;
  status: DistroFixStatus;
  cve: string;
  ecosystem: string;
  package: string;
  sourcePackage: string | null;
  version: string;
  /** The distro's own OSV record id, e.g. UBUNTU-CVE-2026-109618. */
  vulnId: string | null;
  /** The version the distro fixed it in, straight from the OSV record. */
  fixedVersion: string | null;
  /** USN / DSA / DLA and tracker URLs from the OSV record. */
  advisories: string[];
  evaluatedBy: string;
  summary: string;
};

/** Canonical OSV ecosystem, or null when it is not a distro we can ask about. */
function canonicalEcosystem(raw: string): { ecosystem: string; prefix: "UBUNTU" | "DEBIAN" } | null {
  const e = String(raw).trim().replace(/\s+/g, ":");
  const ubuntu = e.match(/^ubuntu(?::pro)?:?(\d\d\.\d\d)(?::lts)?$/i);
  if (ubuntu) {
    const release = ubuntu[1];
    const lts = /^\d\d\.04$/.test(release) && Number(release.split(".")[0]) % 2 === 0;
    const pro = /pro/i.test(e);
    return { ecosystem: `Ubuntu:${pro ? "Pro:" : ""}${release}${lts ? ":LTS" : ""}`, prefix: "UBUNTU" };
  }
  const debian = e.match(/^debian:?(\d+)$/i);
  if (debian) return { ecosystem: `Debian:${debian[1]}`, prefix: "DEBIAN" };
  const codename = e.match(/^debian:?([a-z]+)$/i);
  if (codename && DEBIAN_CODENAMES[codename[1].toLowerCase()]) {
    return { ecosystem: `Debian:${DEBIAN_CODENAMES[codename[1].toLowerCase()]}`, prefix: "DEBIAN" };
  }
  return null;
}

/** A distro package version carries a distro marker. An upstream version does not. */
const DISTRO_VERSION = /ubuntu|deb\d+|\+esm|~|\+dfsg|build\d/i;

export async function check_distro_fix(
  cve: string,
  ecosystem: string,
  pkg: string,
  version: string,
): Promise<DistroFix | Fail> {
  const cveId = String(cve).trim().toUpperCase();
  if (!CVE_ID.test(cveId)) {
    return fail(`"${cve}" is not a CVE id. check_distro_fix needs the CVE, not a USN, DSA or DLA id.`);
  }
  if (/^(DSA|DLA|USN)-/i.test(String(ecosystem)) || /^(DSA|DLA|USN)-/i.test(String(pkg))) {
    return fail("OSV cannot be queried by DSA, DLA or USN id. Pass the CVE plus the ecosystem, package and version.");
  }

  const eco = canonicalEcosystem(ecosystem);
  if (!eco) {
    return fail(
      `"${ecosystem}" is not an OSV distro ecosystem. Use the form Ubuntu:22.04:LTS, Ubuntu:24.04:LTS, Debian:12 or Debian:13.`,
    );
  }

  const name = String(pkg).trim();
  const v = String(version).trim();
  const source = sourcePackageOf(name);
  const base = {
    ok: true as const,
    cve: cveId,
    ecosystem: eco.ecosystem,
    package: name,
    sourcePackage: source,
    version: v,
    evaluatedBy: "OSV api.osv.dev",
  };

  if (!source) {
    return {
      ...base,
      status: "unknown",
      vulnId: null,
      fixedVersion: null,
      advisories: [],
      summary: `"${name}" carries no PHP branch, so it cannot be mapped to the source package OSV indexes. Use the exact binary package name from \`dpkg -l\`, for example php8.3-fpm.`,
    };
  }
  if (!DISTRO_VERSION.test(v)) {
    return {
      ...base,
      status: "unknown",
      vulnId: null,
      fixedVersion: null,
      advisories: [],
      summary: `"${v}" looks like an upstream version, not a ${eco.ecosystem} package version. A distro ecosystem can only evaluate a distro package version such as 8.1.2-1ubuntu2.28. Get it from \`dpkg -l\`.`,
    };
  }

  // 1. Does OSV hold this CVE for this distro at all?
  const vulnId = `${eco.prefix}-${cveId}`;
  let record: {
    message?: string;
    references?: { url?: string }[];
    affected?: {
      package?: { ecosystem?: string; name?: string };
      ranges?: { events?: Record<string, string>[] }[];
    }[];
  };
  try {
    const res = await http(`${OSV}/vulns/${vulnId}`, { accept: "application/json" });
    if (!res.ok && res.status !== 404) return fail(`OSV returned HTTP ${res.status} for ${vulnId}`);
    record = await res.json();
  } catch (e) {
    return fail(`Could not reach OSV: ${why(e)}`);
  }

  if (record.message || !record.affected) {
    return {
      ...base,
      status: "unknown",
      vulnId,
      fixedVersion: null,
      advisories: [],
      summary: `OSV has no ${eco.prefix} record for ${cveId} (${vulnId} not found), so a clean package query would prove nothing. Check the distro's own security tracker.`,
    };
  }

  const entry = record.affected.find(
    (a) =>
      a.package?.name === source &&
      String(a.package?.ecosystem ?? "").toLowerCase() === eco.ecosystem.toLowerCase(),
  );
  const advisories = (record.references ?? [])
    .map((r) => r.url ?? "")
    .filter((u) => /usn-|dsa-|dla-|security-tracker|ubuntu\.com\/security/i.test(u))
    .slice(0, 6);

  if (!entry) {
    const covered = record.affected
      .map((a) => `${a.package?.ecosystem ?? "?"}/${a.package?.name ?? "?"}`)
      .slice(0, 10);
    return {
      ...base,
      status: "unknown",
      vulnId,
      fixedVersion: null,
      advisories,
      summary: `${vulnId} does not cover source package ${source} in ${eco.ecosystem}. It covers: ${covered.join(", ")}. Absence from a package query therefore proves nothing here.`,
    };
  }

  const fixedVersion =
    entry.ranges?.flatMap((r) => r.events ?? []).find((e) => "fixed" in e)?.fixed ?? null;

  // 2. Now a clean result is meaningful: let OSV evaluate the exact version.
  let hit: boolean;
  try {
    const res = await fetch(`${OSV}/query`, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": UA },
      body: JSON.stringify({ package: { name: source, ecosystem: eco.ecosystem }, version: v }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return fail(`OSV query returned HTTP ${res.status} for ${source} ${v}`);
    const payload = (await res.json()) as { vulns?: { id?: string; aliases?: string[] }[] };
    const vulns = payload.vulns ?? [];
    hit = vulns.some((x) => x.id === vulnId || x.id === cveId || (x.aliases ?? []).includes(cveId));
  } catch (e) {
    return fail(`Could not query OSV for ${source} ${v}: ${why(e)}`);
  }

  return {
    ...base,
    status: hit ? "affected" : "fixed",
    vulnId,
    fixedVersion,
    advisories,
    summary: hit
      ? `OSV reports ${source} ${v} in ${eco.ecosystem} as still affected by ${cveId}. ${eco.prefix} fixed it in ${fixedVersion ?? "a later version"}, so upgrade the package.`
      : `OSV evaluated ${source} ${v} in ${eco.ecosystem} and ${cveId} does not apply: ${eco.prefix} fixed it in ${fixedVersion ?? "an earlier version"}, and this version is at or above that. The distro backported the fix, so the upstream version number alone is misleading here.`,
  };
}

/**
 * Compare quoted prose with source prose without tripping on formatting: the
 * words must match exactly, quote marks, backticks and whitespace need not.
 * Shared by the digest's quote check and the mitigation invariant, so both
 * judge "verbatim" the same way.
 */
export const normaliseProse = (t: string) =>
  t.replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/`/g, "").replace(/\s+/g, " ").trim();
