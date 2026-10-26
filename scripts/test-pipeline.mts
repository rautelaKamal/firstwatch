/**
 * Tests for the budgeted pipeline: request sizing and pacing, the digest's
 * quote checks, the code baseline, resource-limit warnings and citation
 * checks. No model and no network: fetch is stubbed where a test needs it.
 *
 *   npm test
 */

import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import {
  SYSTEM_PROMPT,
  TOOL_SCHEMAS,
  VERDICT_LABELS,
  annotate,
  compactHistory,
  emptyLedger,
  fitRequest,
  type FirstWatchReport,
  type Verdict,
} from "../lib/agent";
import { baselineVerdict, scannerVersion } from "../lib/baseline";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

import { chunkText, digestAdvisory, flattenDigest, focusOn, parseGhsa, renderDigest, verifyItems, type AdvisoryDigest } from "../lib/digest";
import { scoreDigest } from "../lib/recall";
import { callModel, chat, estimateRequest, llmConfig, planWait, resetBudget, type ChatMessage } from "../lib/llm";
import { parse_stack } from "../lib/tools";

const results: { name: string; error?: unknown }[] = [];
async function test(name: string, fn: () => void | Promise<void>) {
  try {
    await fn();
    results.push({ name });
  } catch (error) {
    results.push({ name, error });
  }
}

const cfg = () => llmConfig({ apiKey: "test-key", baseUrl: "https://llm.invalid/v1", model: "openai/gpt-oss-120b", tpm: 8000, rpm: 30, maxRequestTokens: 7000 })!;
const realFetch = globalThis.fetch;
function stubFetch(handler: (url: string, init?: RequestInit) => Response) {
  globalThis.fetch = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) =>
    handler(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, init)) as typeof fetch;
}
const completion = (total: number, content = "{}") =>
  new Response(JSON.stringify({ choices: [{ message: { content }, finish_reason: "stop" }], usage: { prompt_tokens: total - 100, completion_tokens: 100, total_tokens: total } }), { status: 200 });

/* ================================================================== *
 * Budget: sizing, compaction, pacing
 * ================================================================== */

await test("the fixed part of every request (prompt + tools) is small", () => {
  const fixed = estimateRequest([{ role: "system", content: SYSTEM_PROMPT }], TOOL_SCHEMAS);
  assert.ok(fixed < 1_800, `system prompt and tools estimate ${fixed} tokens`);
});

await test("compactHistory collapses results the model already answered after, keeps the latest batch", () => {
  const msgs: ChatMessage[] = [
    { role: "system", content: "s" },
    { role: "user", content: "u" },
    { role: "assistant", content: "", tool_calls: [{ id: "a", type: "function", function: { name: "x", arguments: "{}" } }] },
    { role: "tool", tool_call_id: "a", content: "A".repeat(500) },
    { role: "assistant", content: "", tool_calls: [{ id: "b", type: "function", function: { name: "x", arguments: "{}" } }] },
    { role: "tool", tool_call_id: "b", content: "B".repeat(500) },
  ];
  const lines = new Map([["a", "a-line"], ["b", "b-line"]]);
  const out = compactHistory(msgs, lines, new Set(), false);
  assert.equal((out[3] as { content: string }).content, "a-line", "seen result collapsed");
  assert.equal((out[5] as { content: string }).content, "B".repeat(500), "latest batch kept whole");
  assert.equal((compactHistory(msgs, lines, new Set(["a"]), false)[3] as { content: string }).content, "A".repeat(500), "keepFull respected");
  assert.equal((compactHistory(msgs, lines, new Set(), true)[5] as { content: string }).content, "b-line", "forced compaction collapses everything");
});

await test("fitRequest reserves output under the limit, and refuses what cannot fit", () => {
  const small: ChatMessage[] = [{ role: "system", content: SYSTEM_PROMPT }, { role: "user", content: "hello" }];
  const ok = fitRequest(small, TOOL_SCHEMAS, new Map(), new Set(), 7000);
  assert.ok(!("error" in ok));
  if (!("error" in ok)) {
    assert.ok(ok.estimated <= 7000, `estimated ${ok.estimated}`);
    assert.ok(ok.maxTokens >= 1000);
  }
  const huge: ChatMessage[] = [{ role: "system", content: SYSTEM_PROMPT }, { role: "user", content: "x".repeat(30_000) }];
  assert.ok("error" in fitRequest(huge, TOOL_SCHEMAS, new Map(), new Set(), 7000));
});

await test("callModel refuses an oversized request without sending it", async () => {
  let sent = false;
  stubFetch(() => {
    sent = true;
    return completion(10);
  });
  const it = callModel(cfg(), { messages: [{ role: "user", content: "x".repeat(25_000) }], maxTokens: 1000 });
  let step = await it.next();
  while (!step.done) step = await it.next();
  globalThis.fetch = realFetch;
  assert.equal(step.value.ok, false);
  assert.equal(sent, false);
});

await test("planWait makes the next request wait once the minute's tokens are spent", async () => {
  resetBudget();
  stubFetch(() => completion(6_500));
  const r = await chat(cfg(), { messages: [{ role: "user", content: "hi" }], maxTokens: 500 });
  globalThis.fetch = realFetch;
  assert.ok(r.ok);
  assert.ok(planWait(cfg(), 2_000).ms > 0, "6,500 + 2,000 exceeds 8,000 per minute");
  assert.equal(planWait(cfg(), 1_000).ms, 0, "6,500 + 1,000 fits");
  resetBudget();
});

await test("a 429 surfaces the provider's retry hint", async () => {
  stubFetch(() => new Response('{"error":{"message":"Rate limit reached. Please try again in 7.5s."}}', { status: 429 }));
  const r = await chat(cfg(), { messages: [{ role: "user", content: "hi" }], maxTokens: 100 });
  globalThis.fetch = realFetch;
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.retryAfterMs, 7_500);
});

await test("the client posts to {base}/chat/completions, not an SDK-mangled path", async () => {
  let url = "";
  stubFetch((u) => {
    url = u;
    return completion(10);
  });
  await chat(cfg(), { messages: [{ role: "user", content: "hi" }], maxTokens: 10 });
  globalThis.fetch = realFetch;
  resetBudget();
  assert.equal(url, "https://llm.invalid/v1/chat/completions");
});

/* ================================================================== *
 * Digest: only what can be quoted survives
 * ================================================================== */

const digestOf = (over: Partial<AdvisoryDigest>): AdvisoryDigest => ({
  url: "u", focus: [], title: "t", cve: null, ghsa: null, structured: null, items: [],
  dropped: 0, droppedQuotes: [], chunks: 1, resplits: 0, model: "m", ...over,
});

const PAGE = `Who is at risk: all PHP installations serving web requests. We consider the risk highest for mod_php, with a demonstrated exploit where an unauthenticated request can trigger the attack before any application code runs.

FPM is conditionally exposed when nginx, Apache mod_proxy_fcgi or another frontend sends PHP_VALUE/PHP_ADMIN_VALUE parameters.

Use a container or cgroup limit as an availability boundary. Do not substitute RLIMIT_AS or RLIMIT_DATA, as these can cause the vulnerable allocation failure.

Given the severity of these vulnerabilities, the PHP security team provided minimal source-backports for PHP 7.4, PHP 8.0, and PHP 8.1 to help people building from source.`;

await test("verifyItems keeps verbatim quotes and drops paraphrases", () => {
  const items = flattenDigest({
    sapi: [
      { sapi: "mod_php", wording: "demonstrated exploit", quote: "We consider the risk highest for mod_php, with a demonstrated exploit where an unauthenticated request can trigger the attack before any application code runs." },
      { sapi: "fpm", wording: "conditionally exposed", quote: "FPM is exposed only under some conditions." },
    ],
  });
  const { kept, dropped } = verifyItems(items, PAGE);
  assert.equal(kept.length, 1);
  assert.equal(kept[0].sapi, "mod_php");
  assert.equal(dropped, 1);
});

await test("SAPI wording must be the advisory's own words, inside its quote", () => {
  const items = flattenDigest({
    sapi: [{ sapi: "fpm", wording: "confirmed", quote: "FPM is conditionally exposed when nginx, Apache mod_proxy_fcgi or another frontend sends PHP_VALUE/PHP_ADMIN_VALUE parameters." }],
  });
  assert.equal(verifyItems(items, PAGE).kept.length, 0, "\"confirmed\" is not in that sentence");
  const fixed = flattenDigest({
    sapi: [{ sapi: "fpm", wording: "conditionally exposed", quote: "FPM is conditionally exposed when nginx, Apache mod_proxy_fcgi or another frontend sends PHP_VALUE/PHP_ADMIN_VALUE parameters." }],
  });
  assert.equal(verifyItems(fixed, PAGE).kept[0].wording, "conditionally exposed");
});

await test("anti-mitigations and backports are kept only when the quote names them", () => {
  const items = flattenDigest({
    anti_mitigations: [
      { setting: "RLIMIT_AS", quote: "Do not substitute RLIMIT_AS or RLIMIT_DATA, as these can cause the vulnerable allocation failure." },
      { setting: "RLIMIT_NOFILE", quote: "Do not substitute RLIMIT_AS or RLIMIT_DATA, as these can cause the vulnerable allocation failure." },
    ],
    backports: [
      { branches: ["7.4", "8.0", "8.1"], quote: "Given the severity of these vulnerabilities, the PHP security team provided minimal source-backports for PHP 7.4, PHP 8.0, and PHP 8.1 to help people building from source." },
      { branches: ["8.2"], quote: "Given the severity of these vulnerabilities, the PHP security team provided minimal source-backports for PHP 7.4, PHP 8.0, and PHP 8.1 to help people building from source." },
    ],
  });
  const { kept } = verifyItems(items, PAGE);
  // A sentence naming two limits becomes one item per limit, whatever the model labelled it.
  assert.deepEqual(kept.map((i) => i.setting ?? i.branches?.join()).sort(), ["7.4,8.0,8.1", "RLIMIT_AS", "RLIMIT_DATA"]);
  const unbacked = flattenDigest({ anti_mitigations: [{ setting: "RLIMIT_NOFILE", quote: "Use a container or cgroup limit as an availability boundary." }] });
  assert.equal(verifyItems(unbacked, PAGE).kept.length, 0, "a setting its quote does not name is dropped");
});

await test("a SAPI item whose quote does not name that SAPI is dropped", () => {
  const items = flattenDigest({
    sapi: [{ sapi: "cgi", wording: "conditionally exposed", quote: "FPM is conditionally exposed when nginx, Apache mod_proxy_fcgi or another frontend sends PHP_VALUE/PHP_ADMIN_VALUE parameters." }],
  });
  const { kept, droppedQuotes } = verifyItems(items, PAGE);
  assert.equal(kept.length, 0);
  assert.equal(droppedQuotes.length, 1, "dropped quotes are kept for inspection");
});

await test("focusOn narrows a news archive to the paragraphs about this CVE", () => {
  const archive = ["Unrelated: PHP 8.6.0 RC4 is out.", "Another unrelated entry.", "PHP 8.4.27 fixes CVE-2026-109618.", "Update now.", "Pad one.", "Pad two.", "Old news from June.", "Older news."].join("\n\n");
  const out = focusOn(archive, ["CVE-2026-109618"], 1);
  assert.ok(out.includes("CVE-2026-109618"));
  assert.ok(!out.includes("Old news from June"));
  assert.ok(!out.includes("Unrelated: PHP 8.6.0"));
});

await test("chunkText keeps every chunk within size", () => {
  const chunks = chunkText(Array.from({ length: 50 }, (_, i) => `Paragraph ${i} `.repeat(40)).join("\n\n"), 3_000);
  assert.ok(chunks.length > 1);
  assert.ok(chunks.every((c) => c.length <= 3_000));
});

await test("renderDigest never shortens a quote, and can omit notes or shared fields", () => {
  const long = "a".repeat(280);
  const d = digestOf({
    items: [
      { kind: "mitigation", origin: "prose", setting: "memory_limit", value: "-1", quote: long },
      { kind: "note", origin: "prose", point: "p", quote: "a note quote" },
      { kind: "affected", origin: "structured", range: "< 8.4.27", quote: "Affected versions < 8.4.27" },
    ],
  });
  assert.ok(renderDigest(d).includes(long));
  assert.ok(!renderDigest(d, { lean: true }).includes("a note quote"), "lean drops notes");
  assert.ok(!renderDigest(d, { omitStructured: true }).includes("Affected versions < 8.4.27"), "shared fields can be rendered once elsewhere");
});

/* ================================================================== *
 * The code baseline matches what each case records a scanner would say
 * ================================================================== */

const RANGES: Record<string, string[]> = {
  "CVE-2026-109618": [">= 7.3.0 and < 8.2.35", ">= 8.3.0 and < 8.3.36", ">= 8.4.0 and < 8.4.27", ">= 8.5.0 and < 8.5.12"],
  "CVE-2026-109619": [">= 5.4.0 and < 8.2.35", ">= 8.3.0 and < 8.3.36", ">= 8.4.0 and < 8.4.27", ">= 8.5.0 and < 8.5.12"],
};

for (const id of readdirSync("eval/cases").sort()) {
  await test(`baseline: ${id}`, () => {
    const dir = join("eval/cases", id);
    const spec = JSON.parse(readFileSync(join(dir, "case.json"), "utf8")) as { cve: string; baseline_expected: Verdict };
    const files = Object.fromEntries(readdirSync(dir).filter((f) => f !== "case.json").map((f) => [f, readFileSync(join(dir, f), "utf8")]));
    const parsed = parse_stack(files);
    assert.ok(parsed.ok);
    const { verdict } = baselineVerdict(scannerVersion(parsed.facts)?.version ?? null, RANGES[spec.cve]);
    assert.equal(verdict, spec.baseline_expected);
  });
}

/* ================================================================== *
 * Resource limits the advisory warns against
 * ================================================================== */

await test("parse_stack finds RLIMIT_AS and RLIMIT_DATA wherever they are set, and ignores unlimited", () => {
  const p = parse_stack({
    Dockerfile: "FROM php:8.4.12-fpm\nRUN ulimit -v 2097152 && php-fpm\nRUN ulimit -d unlimited",
    "php-fpm.service": "[Service]\nLimitDATA=1G",
    "docker-compose.yml": "services:\n  php:\n    ulimits:\n      as: 4294967296",
    "ulimit.txt": "virtual memory          (kbytes, -v) unlimited\ndata seg size           (kbytes, -d) 1048576",
  });
  assert.ok(p.ok);
  const limits = p.facts.filter((f) => f.field.startsWith("limit.")).map((f) => `${f.field}=${f.value}@${f.file}`);
  assert.deepEqual(limits.sort(), [
    "limit.rlimit_as=2097152@Dockerfile",
    "limit.rlimit_as=4294967296@docker-compose.yml",
    "limit.rlimit_data=1048576@ulimit.txt",
    "limit.rlimit_data=1G@php-fpm.service",
  ]);
});

const ANNOUNCE = "https://www.php.net/archive/2026.php";
const GHSA = "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w";
const RLIMIT_QUOTE = "Do not substitute RLIMIT_AS or RLIMIT_DATA, as these can cause the vulnerable allocation failure.";
const BACKPORT_QUOTE = "the PHP security team provided minimal source-backports for PHP 7.4, PHP 8.0, and PHP 8.1";

const reportWith = (citations: { claim: string; quote: string; source: string }[]): FirstWatchReport => ({
  schema_version: 2, cve: "CVE-2026-109618", target: GHSA, assessed_at: "now", overall: "AFFECTED", summary: "S.",
  findings: [{
    package: "php", installed_version: "8.1.33", version_source: "php -v", sapi: "fpm", verdict: "AFFECTED",
    decided_by: { method: "version_in_range", detail: "" }, exploitation_confidence: "presumed",
    severity: { cvss: null, score: null, note: "" }, citations, mitigations: [], eol: null, remediation: [], unverified: [],
  }],
});

await test("a stack that sets RLIMIT_AS gets a cited warning", () => {
  const p = parse_stack({ Dockerfile: "FROM php:8.1-fpm\nRUN ulimit -v 2097152" });
  assert.ok(p.ok);
  const ledger = emptyLedger(p.facts);
  const digest = digestOf({ url: ANNOUNCE, items: [{ kind: "anti_mitigation", origin: "prose", setting: "RLIMIT_AS", quote: RLIMIT_QUOTE }] });
  const out = annotate(reportWith([]), ledger, [digest]);
  assert.equal(out.warnings?.length, 1);
  assert.equal(out.warnings?.[0].setting, "RLIMIT_AS");
  assert.equal(out.warnings?.[0].quote, RLIMIT_QUOTE);
  assert.equal(out.warnings?.[0].source, ANNOUNCE);
  assert.equal(out.warnings?.[0].where, "Dockerfile:2");
  assert.ok(out.summary.includes("increases risk"));
  assert.equal(annotate(reportWith([]), ledger, []).warnings?.length, 0, "no cited source, no warning");
});

await test("a backport claim cited to the GHSA is flagged; the same quote cited to php.net is verified", () => {
  const ledger = emptyLedger();
  ledger.fetched.push({ source: GHSA, text: "Affected versions < 8.2.35 < 8.3.36 < 8.4.27 < 8.5.12" });
  ledger.fetched.push({ source: ANNOUNCE, text: `Given the severity of these vulnerabilities, ${BACKPORT_QUOTE} to help people building from source.` });
  const wrong = annotate(reportWith([{ claim: "8.1 has source backports", quote: BACKPORT_QUOTE, source: GHSA }]), ledger, []);
  assert.equal(wrong.findings[0].citations[0].verified, false);
  assert.equal(wrong.citation_issues?.length, 1);
  const right = annotate(reportWith([{ claim: "8.1 has source backports", quote: BACKPORT_QUOTE, source: ANNOUNCE }]), ledger, []);
  assert.equal(right.findings[0].citations[0].verified, true);
  assert.equal(right.citation_issues?.length, 0);
});

await test("AFFECTED_MITIGATED is shown as \"Affected, exposure reduced\"", () => {
  assert.equal(VERDICT_LABELS.AFFECTED_MITIGATED, "Affected, exposure reduced");
});

/* ================================================================== *
 * GHSA fields in code, and the digest end to end (stubbed page and model)
 * ================================================================== */

const GHSA_URL = "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w";
const PROSE = [
  "Summary of the issue. PHP uses longjmp() for out-of-memory errors to exit the current context and abort handling of the request, which can leave request memory reachable before it is initialized.",
  "Susceptibility. Apache mod_php unconditionally invokes the request shutdown procedure, even when request startup has failed. This makes mod_php the most exposed SAPI by a wide margin in every configuration we examined.",
  "FPM exits the child when request startup fails. Source analysis therefore supports FPM as a susceptible, though no complete FPM exploit has been demonstrated for this SAPI.",
  "Workarounds. Updating to a PHP release containing the patch to this vulnerability is the only complete mitigation. Setting and enforcing memory_limit=-1 administratively is the primary configuration mitigation.",
  "Do not use RLIMIT_AS or RLIMIT_DATA, as these will cause mmap() to fail once the memory limit is reached and push allocation failures into the vulnerable path.",
  "Further notes about multipart parsing, post_max_size and frontend limits follow here, padding the prose so that it is long enough to be split in half when a reply is cut off by the output cap.",
  "More padding text describing allocator behaviour, build differences, extension interactions and frontend behaviour so that the excerpt comfortably exceeds the minimum split size used by the digest.",
  "Final paragraph of prose with yet more detail on exploit portability, reliability and the conditions under which worker processes are recycled between requests in common deployments.",
  "Closing remarks: administrators should prioritise patching over configuration changes, and treat every configuration measure as a reduction of exposure rather than a fix.",
];
const GHSA_HTML = `<html><body>${[
  "RCE via OOM corruption", "Critical", "published", "GHSA-w8hw-w9fx-j79w", "Package", "php-src", "Affected versions",
  "&lt; 8.2.35", "&lt; 8.3.36", "&lt; 8.4.27", "&lt; 8.5.12", "Patched versions", "8.2.35", "8.3.36", "8.4.27", "8.5.12",
  "Description", ...PROSE, "Severity", "Critical", "9.2", "CVE ID", "CVE-2026-109618", "Weaknesses", "CWE-416",
].map((l) => `<p>${l}</p>`).join("")}</body></html>`;

await test("parseGhsa reads affected, patched and the CVE id from the page, and cuts the prose", async () => {
  const { fetch_advisory } = await import("../lib/tools");
  stubFetch(() => new Response(GHSA_HTML, { status: 200, headers: { "content-type": "text/html" } }));
  const page = await fetch_advisory(GHSA_URL);
  globalThis.fetch = realFetch;
  assert.ok(page.ok);
  const g = page.ok ? parseGhsa(page.text) : null;
  assert.ok(g);
  assert.deepEqual(g.affected, ["< 8.2.35", "< 8.3.36", "< 8.4.27", "< 8.5.12"]);
  assert.deepEqual(g.patched, ["8.2.35", "8.3.36", "8.4.27", "8.5.12"]);
  assert.equal(g.cve, "CVE-2026-109618");
  assert.equal(g.ghsa, "GHSA-w8hw-w9fx-j79w");
  assert.ok(g.prose.includes("Apache mod_php unconditionally") && !g.prose.includes("CWE-416"), "prose stops before Severity");
  assert.equal(parseGhsa("Just some page\nwith no advisory fields"), null);
});

await test("digest: fields in code, prose verified, a cut-off reply is split not enlarged, then cached", async () => {
  const cacheDir = mkdtempSync(join(tmpdir(), "fw-digest-"));
  process.env.FIRSTWATCH_CACHE_DIR = cacheDir;
  resetBudget();
  let modelCalls = 0;
  const caps: number[] = [];
  const reply = JSON.stringify({
    sapi: [
      { sapi: "mod_php", wording: "unconditionally invokes", quote: "Apache mod_php unconditionally invokes the request shutdown procedure, even when request startup has failed." },
      { sapi: "cgi", wording: "susceptible", quote: "Source analysis therefore supports FPM as a susceptible, though no complete FPM exploit has been demonstrated for this SAPI." },
    ],
    anti_mitigations: [{ setting: "RLIMIT_AS", quote: "Do not use RLIMIT_AS or RLIMIT_DATA, as these will cause mmap() to fail once the memory limit is reached and push allocation failures into the vulnerable path." }],
  });
  stubFetch((url, init) => {
    if (url.startsWith("https://github.com/")) return new Response(GHSA_HTML, { status: 200, headers: { "content-type": "text/html" } });
    modelCalls++;
    caps.push((JSON.parse(String(init?.body)) as { max_completion_tokens: number }).max_completion_tokens);
    const cut = modelCalls === 1;
    return new Response(JSON.stringify({
      choices: [{ message: { content: cut ? '{"sapi":[{"sapi":"mod' : reply }, finish_reason: cut ? "length" : "stop" }],
      usage: { prompt_tokens: 900, completion_tokens: 200, total_tokens: 1100 },
    }), { status: 200 });
  });
  try {
    const run = async () => {
      const it = digestAdvisory(cfg(), GHSA_URL);
      let step = await it.next();
      while (!step.done) step = await it.next();
      return step.value;
    };
    const first = await run();
    assert.ok(first.ok);
    if (!first.ok) return;
    const d = first.digest;
    assert.equal(d.resplits, 1, "the cut-off chunk was split once");
    assert.equal(modelCalls, 3, "one cut-off reply, then two halves");
    assert.ok(caps.every((c) => c === caps[0]), "the output cap never grew");
    assert.equal(d.cve, "CVE-2026-109618");
    assert.equal(d.items.filter((i) => i.kind === "fixed" && i.origin === "structured").length, 4);
    assert.equal(d.items.filter((i) => i.kind === "affected" && i.origin === "structured").length, 4);
    assert.deepEqual(d.items.filter((i) => i.kind === "sapi").map((i) => i.sapi), ["mod_php"], "the mislabelled cgi item is gone");
    assert.deepEqual(d.items.filter((i) => i.kind === "anti_mitigation").map((i) => i.setting).sort(), ["RLIMIT_AS", "RLIMIT_DATA"]);
    const again = await run();
    assert.ok(again.ok && again.cached, "second read comes from the cache");
    assert.equal(modelCalls, 3, "and costs nothing");
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.FIRSTWATCH_CACHE_DIR;
    rmSync(cacheDir, { recursive: true, force: true });
    resetBudget();
  }
});

await test("scoreDigest counts what survived and flags not-stated facts", () => {
  const d = digestOf({
    url: GHSA_URL, cve: "CVE-2026-109618",
    items: [
      { kind: "affected", origin: "structured", range: "< 8.4.27", quote: "Affected versions < 8.4.27" },
      { kind: "fixed", origin: "structured", fixed_version: "8.4.27", quote: "Patched versions 8.4.27" },
      { kind: "sapi", origin: "prose", sapi: "fpm", wording: "susceptible", quote: "Source analysis therefore supports FPM as a susceptible, though no complete FPM exploit has been demonstrated for this SAPI." },
      { kind: "anti_mitigation", origin: "prose", setting: "RLIMIT_AS", quote: "Do not use RLIMIT_AS or RLIMIT_DATA, as these will cause mmap() to fail" },
      { kind: "note", origin: "prose", point: "8.1 gets backports", quote: "Updating is the only complete mitigation." },
    ],
  });
  const r = scoreDigest(d, {
    cve: "CVE-2026-109618", ranges: ["< 8.2.35", "< 8.4.27"], fixed: ["8.4.27"],
    sapi: { fpm: "no complete FPM exploit has been demonstrated", mod_php: "Apache mod_php unconditionally invokes" },
    anti_mitigations: ["RLIMIT_AS", "RLIMIT_DATA"], not_stated: ["8.1", "backport"],
  });
  assert.deepEqual(r.byCategory.ranges, { found: 1, total: 2 });
  assert.deepEqual(r.byCategory.sapi, { found: 1, total: 2 });
  assert.deepEqual(r.byCategory.anti_mitigations, { found: 2, total: 2 }, "both limits are named in the one quote");
  assert.equal(r.violations.length, 2, "the note attributes 8.1 and backports to a GHSA");
});

await test("annotate states, with a citation to each, that both CVEs share their patched versions", () => {
  const ghsa = (cve: string, url: string, id: string) =>
    digestOf({
      url, cve, ghsa: id,
      structured: { ghsa: id, cve, title: "", affected: ["< 8.4.27"], patched: ["8.2.35", "8.3.36", "8.4.27", "8.5.12"], affectedQuote: "Affected versions < 8.4.27", patchedQuote: "Patched versions 8.2.35 8.3.36 8.4.27 8.5.12", cveQuote: `CVE ID ${cve}` },
    });
  const out = annotate(reportWith([]), emptyLedger(), [
    ghsa("CVE-2026-109618", GHSA, "GHSA-w8hw-w9fx-j79w"),
    ghsa("CVE-2026-109619", "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp", "GHSA-6wmf-4rv5-p3rp"),
  ]);
  assert.equal(out.fixed_versions_identical, true);
  assert.equal(out.fixed_versions?.length, 2);
  assert.deepEqual(out.fixed_versions?.map((f) => f.source.split("/").pop()), ["GHSA-w8hw-w9fx-j79w", "GHSA-6wmf-4rv5-p3rp"]);
  assert.ok(out.fixed_versions?.every((f) => f.quote === "Patched versions 8.2.35 8.3.36 8.4.27 8.5.12"));
  assert.match(out.summary, /CVE-2026-109618 \(GHSA-w8hw-w9fx-j79w\) and CVE-2026-109619 \(GHSA-6wmf-4rv5-p3rp\) list identical patched versions/);
});

/* --- report ------------------------------------------------------- */
let failed = 0;
for (const r of results) {
  if (r.error) {
    failed++;
    console.log(`FAIL ${r.name}\n     ${r.error instanceof Error ? r.error.message.split("\n")[0] : String(r.error)}`);
  } else console.log(`ok   ${r.name}`);
}
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
