/**
 * Run FirstWatch over eval/cases and print its scorecard next to a version
 * scanner's on the same cases.
 *
 *   npm run eval -- --dry          fixtures and the code baseline only: no model, free
 *   npm run eval -- --case a       one case
 *   npm run eval                   every case
 *   npm run eval -- --verbose      show each request, wait and tool call
 *
 * The baseline is deterministic code (lib/baseline.ts) and costs nothing.
 * Expected verdicts come from eval/ground-truth.md, verified against OSV;
 * re-check with `npm run verify-truth` before trusting a run.
 */

import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { VERDICT_LABELS, runAgent, type FirstWatchReport, type TokenUsage, type Verdict } from "../lib/agent";
import { runBaseline } from "../lib/baseline";
import { cachedDigests, formatRecall, reportViolations, scoreDigest, type AnswerKey } from "../lib/recall";
import { emptyUsage, mergeUsage } from "../lib/llm";
import { parse_stack } from "../lib/tools";
import { loadEnv } from "./env.mjs";

loadEnv();

const CASES_DIR = "eval/cases";
const OUT_DIR = "eval/out";

type CaseSpec = {
  id: string;
  description: string;
  stack: string;
  cve: string;
  cves?: string[];
  target: string;
  sources?: string[];
  ground_truth: string;
  expect: { verdict: Verdict; also_acceptable?: Verdict[]; must_mention?: string; must_remediate?: string[] };
  baseline_expected?: Verdict;
  why: string;
};
type Loaded = CaseSpec & { files: Record<string, string> };

const argv = process.argv.slice(2);
const flag = (...n: string[]) => {
  const i = argv.findIndex((a) => n.includes(a));
  return i >= 0 ? argv[i + 1] : undefined;
};
const has = (...n: string[]) => argv.some((a) => n.includes(a));
const only = flag("--case", "-c");
const model = flag("--model", "-m");
const max = flag("--max", "-n");
const dry = has("--dry");
const verbose = has("--verbose", "-v");

const plain = Boolean(process.env.NO_COLOR) || !process.stdout.isTTY;
const c = (code: string) => (s: string | number) => (plain ? String(s) : `\u001b[${code}m${s}\u001b[0m`);
const [dim, bold, red, green, yellow, blue] = ["2", "1", "31", "32", "33", "36"].map(c);
const ms = (n: number) => (n < 1000 ? `${n}ms` : `${(n / 1000).toFixed(1)}s`);
const n = (x: number) => x.toLocaleString();
const label = (v: Verdict | "none") => (v === "none" ? "none" : VERDICT_LABELS[v]);

/** How reassuring a verdict is. Saying something safer than the truth is the dangerous error. */
const KEY_PATH = "eval/digest-answer-key.json";
const answerKey = (): AnswerKey | null => {
  try {
    return JSON.parse(readFileSync(KEY_PATH, "utf8")) as AnswerKey;
  } catch {
    return null;
  }
};

/** Score every cached digest that the answer key covers. */
function printRecall(): number {
  const key = answerKey();
  if (!key) return 0;
  console.log(`\n${bold("digest recall")}  ${dim(`against ${KEY_PATH}`)}`);
  const digests = cachedDigests();
  let violations = 0;
  for (const [url, entry] of Object.entries(key.advisories)) {
    const d = digests.find((x) => x.url === url);
    if (!d) {
      console.log(`  ${yellow("not digested yet")} ${url}`);
      continue;
    }
    const r = scoreDigest(d, entry);
    const pct = r.found / Math.max(1, r.total);
    console.log(`  ${(pct === 1 ? green : pct >= 0.8 ? yellow : red)(formatRecall(r).padEnd(10))}  ${url}`);
    for (const c of r.checks.filter((x) => !x.found)) console.log(`      ${dim(`missing ${c.category}: ${c.expected.slice(0, 100)}`)}`);
    for (const v of r.violations) console.log(`      ${red(v)}`);
    violations += r.violations.length;
  }
  return violations;
}

const REASSURANCE: Record<Verdict, number> = { NOT_AFFECTED: 3, AFFECTED_MITIGATED: 2, UNVERIFIED: 1, AFFECTED: 0 };

function loadCases(): Loaded[] {
  return readdirSync(CASES_DIR)
    .filter((d) => statSync(join(CASES_DIR, d)).isDirectory())
    .sort()
    // "--case a" means case a, not every id containing the letter a. "--case a,f,h" picks several.
    .filter((d) => !only || only.split(",").some((o) => d === o.trim() || d.startsWith(`${o.trim()}-`)))
    .map((d) => {
      const dir = join(CASES_DIR, d);
      const spec = JSON.parse(readFileSync(join(dir, "case.json"), "utf8")) as CaseSpec;
      const files: Record<string, string> = {};
      for (const f of readdirSync(dir)) if (f !== "case.json") files[f] = readFileSync(join(dir, f), "utf8");
      return { ...spec, files };
    });
}

function grade(want: Verdict, acceptable: Verdict[], got: Verdict | "none") {
  if (got === "none") return { status: "err" as const, unsafe: false };
  if (got === want) return { status: "pass" as const, unsafe: false };
  if (acceptable.includes(got)) return { status: "soft" as const, unsafe: false };
  return { status: "fail" as const, unsafe: REASSURANCE[got] > REASSURANCE[want] };
}
type Grade = ReturnType<typeof grade>;
const mark = (g: Grade) =>
  g.status === "pass" ? green("PASS") : g.status === "soft" ? yellow("SOFT") : g.status === "err" ? red("ERR ") : red("FAIL");

/* --- dry run: fixtures and the code baseline, no model -------------- */
async function dryRun(cases: Loaded[]): Promise<number> {
  let problems = 0;
  for (const k of cases) {
    const parsed = parse_stack(k.files);
    const base = await runBaseline({ files: k.files, cve: k.cve, cves: k.cves, target: k.target });
    const baseOk = !k.baseline_expected || base.report.overall === k.baseline_expected;
    console.log(`\n${bold(k.id)} ${dim(`expects ${k.expect.verdict}`)}`);
    if (!parsed.ok) {
      console.log(`  ${red("parse_stack failed")} ${parsed.error}`);
      problems++;
      continue;
    }
    console.log(`  ${dim("stack    ")} ${parsed.summary}`);
    console.log(`  ${dim("baseline ")} ${base.report.overall} from "${base.version ?? "nothing"}" ${baseOk ? green("(as recorded)") : red(`(case.json says ${k.baseline_expected})`)}`);
    if (!baseOk) problems++;
  }
  console.log(`\n${problems ? red(`${problems} problems`) : green("fixtures and baseline consistent")} ${dim("(no model calls made)")}`);
  return problems + printRecall();
}

/* --- live run ----------------------------------------------------- */
type Result = { verdict: Verdict | "none"; report: FirstWatchReport | null; toolCalls: number; ms: number; note: string; usage: TokenUsage; digest: TokenUsage; downgrades: number };

async function runFirstWatch(k: Loaded): Promise<Result> {
  const started = Date.now();
  const out: Result = { verdict: "none", report: null, toolCalls: 0, ms: 0, note: "", usage: emptyUsage(), digest: emptyUsage(), downgrades: 0 };
  for await (const e of runAgent({ stack: k.stack, files: k.files, target: k.target, cve: k.cve, cves: k.cves, sources: k.sources, model, maxIterations: max ? Number(max) : undefined })) {
    if (e.type === "digest") console.log(`    ${dim("digest")} ${e.url} ${e.error ? red(e.error.slice(0, 160)) : e.cached ? dim(`cached, ${e.items} items`) : `${e.items} items kept, ${e.dropped} dropped, ${e.chunks} part(s), ${n(e.tokens)} tokens`}`);
    if (e.type === "digest_request" && verbose) console.log(`    ${dim("digest request")} part ${e.index} of ${e.of}, ~${n(e.estimated)} tokens estimated`);
    if (e.type === "nvd") console.log(`    ${dim("nvd   ")} ${e.id}: ${e.ranges} php ranges${e.note ? ` (${e.note})` : ""}`);
    if (e.type === "waiting") console.log(`    ${yellow("wait  ")} ${ms(e.ms)}: ${e.reason}`);
    if (e.type === "compacted") console.log(`    ${yellow("compact")} ${e.note}`);
    if (e.type === "request" && verbose) console.log(`    ${dim("request")} ${e.label}: ${n(e.total)} tokens (${n(e.prompt)} in, ${n(e.completion)} out; estimated ${n(e.estimated)}) ${e.finish === "length" ? red("cut off") : ""}`);
    if (e.type === "tool_call" && verbose) console.log(`    ${blue(e.tool)} ${dim(JSON.stringify(e.args).slice(0, 150))}`);
    if (e.type === "tool_result" && verbose) console.log(`      ${e.ok ? green("ok") : red("failed")} ${e.summary.slice(0, 170)}`);
    if (e.type === "repair") console.log(`    ${yellow("repair")} ${e.errors.join("; ").slice(0, 160)}`);
    if (e.type === "enforced") {
      out.downgrades = e.downgrades.length;
      for (const d of e.downgrades) console.log(`    ${yellow(`${d.invariant}`)} ${d.package}: ${d.from} -> ${d.to} ${dim(d.why.slice(0, 130))}`);
    }
    if (e.type === "error") {
      out.note = e.message;
      if (e.usage) out.usage = e.usage;
      if (e.digestUsage) out.digest = e.digestUsage;
    }
    if (e.type === "final") {
      out.report = e.report;
      out.verdict = e.report?.overall ?? "none";
      out.toolCalls = e.toolCalls;
      out.usage = e.usage;
      out.digest = e.digestUsage;
      if (!e.report) out.note = e.reportError ?? "no valid report";
      writeFileSync(join(OUT_DIR, `${k.id}.firstwatch.json`), JSON.stringify({ case: k.id, report: e.report, raw: e.report ? undefined : e.text, usage: e.usage, digestUsage: e.digestUsage }, null, 2));
    }
  }
  out.ms = Date.now() - started;
  return out;
}

async function liveRun(cases: Loaded[]) {
  mkdirSync(OUT_DIR, { recursive: true });
  const rows: { k: Loaded; fw: Result; base: Verdict; fwG: Grade; baseG: Grade; mentioned: boolean }[] = [];

  for (const k of cases) {
    console.log(`\n${bold(k.id)} ${dim(`expects ${label(k.expect.verdict)}`)}`);
    console.log(`  ${dim(k.why)}`);
    const fw = await runFirstWatch(k);
    const base = (await runBaseline({ files: k.files, cve: k.cve, cves: k.cves, target: k.target })).report.overall;
    const acceptable = k.expect.also_acceptable ?? [];
    const fwG = grade(k.expect.verdict, acceptable, fw.verdict);
    const baseG = grade(k.expect.verdict, acceptable, base);
    const mention = (k.expect.must_mention ?? "").toLowerCase();
    // Remediation is checked by its type field, on every affected finding, not by searching the text.
    const affectedFindings = (fw.report?.findings ?? []).filter((f) => f.verdict === "AFFECTED" || f.verdict === "AFFECTED_MITIGATED");
    const missingTypes = (k.expect.must_remediate ?? []).filter(
      (t) => !affectedFindings.length || affectedFindings.some((f) => !(f.remediation ?? []).some((r) => r.type === t)),
    );
    const mentioned = (!mention || JSON.stringify(fw.report ?? {}).toLowerCase().includes(mention)) && !missingTypes.length;
    rows.push({ k, fw, base, fwG, baseG, mentioned });

    const both = mergeUsage(fw.usage, fw.digest);
    console.log(`  ${mark(fwG)} firstwatch: ${label(fw.verdict)}${fwG.unsafe ? red("  UNSAFE") : ""} ${dim(`${fw.toolCalls} tool calls, ${ms(fw.ms)}, ${fw.downgrades} downgrades`)}`);
    console.log(`  ${mark(baseG)} scanner:    ${label(base)}${baseG.unsafe ? red("  UNSAFE") : ""} ${dim("deterministic code, 0 tokens")}`);
    console.log(`  ${dim("tokens")} agent ${n(fw.usage.total)} in ${fw.usage.requests} requests; digests ${n(fw.digest.total)} in ${fw.digest.requests}; largest request ${n(both.maxRequest)}`);
    for (const r of both.perRequest) console.log(`    ${dim(r.label.padEnd(12))} ${n(r.total).padStart(6)} tokens  ${dim(`(${n(r.prompt)} in, ${n(r.completion)} out, estimated ${n(r.estimated)})`)}`);
    if (fw.report?.summary) console.log(`  ${dim(fw.report.summary.slice(0, 300))}`);
    if (fw.report?.warnings?.length) for (const w of fw.report.warnings) console.log(`  ${yellow("warning")} ${w.why}`);
    for (const c of fw.report?.corrections ?? []) console.log(`  ${dim("corrected")} ${c}`);
    if (fw.report?.citation_issues?.length) console.log(`  ${yellow(`${fw.report.citation_issues.length} citation(s) not found in the source they name`)}`);
    const key = answerKey();
    for (const v of fw.report && key ? reportViolations(fw.report, key) : []) console.log(`  ${red("not stated by that advisory:")} ${v}`);
    if (fw.report) {
      const byPkg = new Map<string, string[]>();
      for (const f of fw.report.findings) byPkg.set(f.package, [...(byPkg.get(f.package) ?? []), `${f.cve ?? "?"}: ${label(f.verdict)}`]);
      for (const [pkg, vs] of byPkg) console.log(`    ${dim(pkg.padEnd(24))} ${vs.join("; ")}`);
    }
    if (!mentioned) console.log(`  ${yellow("missing")} ${missingTypes.length ? `a remediation of type ${missingTypes.join(", ")} on every affected finding` : `"${k.expect.must_mention}" in the report`}`);
    if (fw.note) console.log(`  ${red("note")} ${fw.note.slice(0, 300)}`);
  }

  console.log(`\n${bold("scorecard")}  ${dim("FirstWatch vs a version scanner, same cases")}`);
  console.log(dim(`  ${"case".padEnd(32)}${"expected".padEnd(28)}${"firstwatch".padEnd(28)}scanner`));
  const cell = (g: Grade, v: Verdict | "none") => {
    const t = `${label(v)}${g.unsafe ? " !" : ""}`.padEnd(28);
    return g.status === "pass" ? green(t) : g.status === "soft" ? yellow(t) : red(t);
  };
  for (const r of rows) console.log(`  ${r.k.id.padEnd(32)}${label(r.k.expect.verdict).padEnd(28)}${cell(r.fwG, r.fw.verdict)}${cell(r.baseG, r.base)}`);

  const tally = (gs: Grade[]) => ({ pass: gs.filter((g) => g.status === "pass").length, soft: gs.filter((g) => g.status === "soft").length, unsafe: gs.filter((g) => g.unsafe).length });
  const fwT = tally(rows.map((r) => r.fwG));
  const bT = tally(rows.map((r) => r.baseG));
  console.log(`\n  firstwatch  ${fwT.pass}/${rows.length} exact, ${fwT.soft} acceptable, ${fwT.unsafe ? red(`${fwT.unsafe} unsafe`) : green("0 unsafe")}`);
  console.log(`  scanner     ${bT.pass}/${rows.length} exact, ${bT.soft} acceptable, ${bT.unsafe ? red(`${bT.unsafe} unsafe`) : green("0 unsafe")}`);

  const agent = rows.reduce((a, r) => mergeUsage(a, r.fw.usage), emptyUsage());
  const digest = rows.reduce((a, r) => mergeUsage(a, r.fw.digest), emptyUsage());
  const all = mergeUsage(agent, digest);
  console.log(`\n  ${bold("tokens")}  agent ${n(agent.total)}, digests ${n(digest.total)}, ${bold(`total ${n(all.total)}`)} in ${all.requests} requests, largest ${n(all.maxRequest)}`);
  if (rows.length) {
    const perCase = agent.total / rows.length;
    console.log(dim(`  projected for all 9 cases: about ${n(Math.round(perCase * 9))} agent tokens, plus digests, which are cached after their first run`));
  }
  const violations = printRecall();
  console.log(dim(`  reports written to ${OUT_DIR}/`));
  return rows.length - fwT.pass - fwT.soft + fwT.unsafe + violations;
}

const cases = loadCases();
if (!cases.length) {
  console.error(`No cases in ${CASES_DIR}${only ? ` matching "${only}"` : ""}`);
  process.exit(1);
}
console.log(`${bold("FirstWatch eval")} ${cases.length} case${cases.length > 1 ? "s" : ""}${dry ? dim(" (dry run)") : ""}`);
process.exit(dry ? ((await dryRun(cases)) ? 1 : 0) : await liveRun(cases));
