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
const MAX_TEXT = 20_000; // roughly 5k tokens, leaves plenty of context room

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
    .replace(/[-_+~]/g, ".")
    .replace(/(\d)([a-z])/g, "$1.$2")
    .replace(/([a-z])(\d)/g, "$1.$2")
    .split(".")
    .filter((p) => p.length > 0);
}

const isNum = (p: string) => /^\d+$/.test(p);
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
  if (!parts(a).length || !parts(b).length) {
    return fail(`Could not read "${a}" and "${b}" as version numbers.`);
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
