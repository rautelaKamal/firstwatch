/**
 * Run the agent over eval/cases and print a scorecard, next to the scorecard
 * an NVD-only version scanner gets on the same cases.
 *
 *   npm run eval -- --dry       parse fixtures only, no model calls, free
 *   npm run eval                FirstWatch and the baseline, side by side
 *   npm run eval -- --no-baseline
 *   npm run eval -- --case e --verbose
 *
 * Expected verdicts come from eval/ground-truth.md, verified against OSV.
 * Re-verify with `npm run verify-truth` before trusting a run.
 */

import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { runAgent, type AgentMode, type FirstWatchReport, type TokenUsage, type Verdict } from "../lib/agent";
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
  target: string;
  ground_truth: string;
  expect: { verdict: Verdict; also_acceptable?: Verdict[]; must_mention?: string };
  baseline_expected?: Verdict;
  why: string;
};
type Loaded = CaseSpec & { dir: string; files: Record<string, string> };

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
const withBaseline = !has("--no-baseline");

const plain = Boolean(process.env.NO_COLOR) || !process.stdout.isTTY;
const c = (code: string) => (s: string | number) => (plain ? String(s) : `\u001b[${code}m${s}\u001b[0m`);
const dim = c("2");
const bold = c("1");
const red = c("31");
const green = c("32");
const yellow = c("33");
const blue = c("36");
const ms = (n: number) => (n < 1000 ? `${n}ms` : `${(n / 1000).toFixed(1)}s`);

/** How reassuring a verdict is. Saying something safer than the truth is the dangerous error. */
const REASSURANCE: Record<Verdict, number> = { NOT_AFFECTED: 3, AFFECTED_MITIGATED: 2, UNVERIFIED: 1, AFFECTED: 0 };

function loadCases(): Loaded[] {
  return readdirSync(CASES_DIR)
    .filter((d) => statSync(join(CASES_DIR, d)).isDirectory())
    .sort()
    .filter((d) => !only || d.includes(only))
    .map((d) => {
      const dir = join(CASES_DIR, d);
      const spec = JSON.parse(readFileSync(join(dir, "case.json"), "utf8")) as CaseSpec;
      const files: Record<string, string> = {};
      for (const f of readdirSync(dir)) {
        if (f !== "case.json") files[f] = readFileSync(join(dir, f), "utf8");
      }
      return { ...spec, dir, files };
    });
}

/* --- dry run: fixtures only, no tokens spent --------------------- */
function dryRun(cases: Loaded[]): number {
  let problems = 0;
  for (const k of cases) {
    const parsed = parse_stack(k.files);
    console.log(`\n${bold(k.id)} ${dim(`expects ${k.expect.verdict}, scanner would say ${k.baseline_expected ?? "?"}`)}`);
    console.log(`  ${dim("files    ")} ${Object.keys(k.files).join(", ")}`);
    if (!parsed.ok) {
      console.log(`  ${red("parse_stack failed")} ${parsed.error}`);
      problems++;
      continue;
    }
    console.log(`  ${dim("summary  ")} ${parsed.summary}`);
    console.log(`  ${dim("ecosystem")} ${parsed.ecosystems.join(", ") || red("none")}`);
    console.log(`  ${dim("runtime  ")} ${parsed.hasRuntimeEvidence ? green("yes") : yellow("no")}`);
    for (const p of parsed.packages) {
      console.log(`      ${blue(p.name.padEnd(24))} ${p.version.padEnd(26)} src=${String(p.source).padEnd(8)} ${p.kind === "runtime" ? green(p.kind) : yellow(p.kind)} ${dim(p.where)}`);
    }
    for (const u of parsed.unverified) console.log(`      ${yellow("unverified")} ${u.slice(0, 150)}`);

    // Sanity: a case that expects a decided verdict needs an ecosystem and runtime evidence.
    const needsDistro = k.expect.verdict === "NOT_AFFECTED";
    if (needsDistro && !parsed.ecosystems.length) {
      console.log(`  ${red("fixture problem")} expects NOT_AFFECTED but no OSV ecosystem could be derived`);
      problems++;
    }
    if (needsDistro && !parsed.hasRuntimeEvidence) {
      console.log(`  ${red("fixture problem")} expects NOT_AFFECTED but carries no runtime evidence, so invariant I3 would force UNVERIFIED`);
      problems++;
    }
    if (k.expect.verdict === "UNVERIFIED" && parsed.hasRuntimeEvidence && parsed.packages.some((p) => p.kind === "runtime")) {
      console.log(`  ${yellow("check")} expects UNVERIFIED but runtime package evidence is present`);
    }
  }
  console.log(`\n${problems ? red(`${problems} fixture problems`) : green("fixtures consistent with the invariants")} ${dim("(no model calls made)")}`);
  return problems;
}

/* --- one run ------------------------------------------------------ */
type Result = {
  verdict: Verdict | "none";
  report: FirstWatchReport | null;
  toolCalls: number;
  ms: number;
  note: string;
  downgrades: number;
  usage: TokenUsage;
};

const noUsage = (): TokenUsage => ({ prompt: 0, completion: 0, total: 0, requests: 0 });
const tokens = (u: TokenUsage) => `${u.total.toLocaleString()} tokens (${u.prompt.toLocaleString()} in, ${u.completion.toLocaleString()} out, ${u.requests} requests)`;

async function runOne(k: Loaded, mode: AgentMode): Promise<Result> {
  const started = Date.now();
  let report: FirstWatchReport | null = null;
  let toolCalls = 0;
  let note = "";
  let downgrades = 0;
  let usage = noUsage();
  try {
    for await (const e of runAgent({
      stack: k.stack,
      files: k.files,
      target: k.target,
      cve: k.cve,
      mode,
      model,
      maxIterations: max ? Number(max) : undefined,
    })) {
      if (verbose && e.type === "tool_call") console.log(`    ${blue(e.tool)} ${dim(JSON.stringify(e.args).slice(0, 150))}`);
      if (verbose && e.type === "tool_result") console.log(`      ${e.ok ? green("ok") : red("failed")} ${dim(ms(e.ms))} ${e.summary.slice(0, 150)}`);
      if (e.type === "facts") console.log(`    ${dim("facts")} ${e.summary}`);
      if (e.type === "repair") console.log(`    ${yellow("repair")} ${e.errors.join("; ").slice(0, 160)}`);
      if (e.type === "enforced") {
        downgrades = e.downgrades.length;
        for (const d of e.downgrades) console.log(`    ${yellow(`${d.invariant} downgrade`)} ${d.package}: ${d.from} -> ${d.to}  ${dim(d.why.slice(0, 140))}`);
      }
      if (e.type === "error") note = e.message;
      if (e.type === "final") {
        report = e.report;
        toolCalls = e.toolCalls;
        usage = e.usage;
        if (!e.report) note = e.reportError ?? "no valid report";
        writeFileSync(join(OUT_DIR, `${k.id}.${mode}.json`), JSON.stringify({ case: k.id, mode, report: e.report, raw: e.report ? undefined : e.text }, null, 2));
      }
    }
  } catch (e) {
    note = e instanceof Error ? e.message : String(e);
  }
  return { verdict: report?.overall ?? "none", report, toolCalls, ms: Date.now() - started, note, downgrades, usage };
}

function grade(want: Verdict, acceptable: Verdict[], got: Verdict | "none") {
  if (got === "none") return { status: "err" as const, unsafe: false };
  if (got === want) return { status: "pass" as const, unsafe: false };
  if (acceptable.includes(got)) return { status: "soft" as const, unsafe: false };
  return { status: "fail" as const, unsafe: REASSURANCE[got] > REASSURANCE[want] };
}

async function liveRun(cases: Loaded[]) {
  mkdirSync(OUT_DIR, { recursive: true });
  const rows: {
    id: string; want: Verdict; fw: Result; base: Result | null;
    fwGrade: ReturnType<typeof grade>; baseGrade: ReturnType<typeof grade> | null; mentioned: boolean;
  }[] = [];

  for (const k of cases) {
    console.log(`\n${bold(k.id)} ${dim(`want ${k.expect.verdict}`)}`);
    console.log(`  ${dim(k.why)}`);
    console.log(`  ${dim("firstwatch")}`);
    const fw = await runOne(k, "firstwatch");
    let base: Result | null = null;
    if (withBaseline) {
      console.log(`  ${dim("nvd-only baseline")}`);
      base = await runOne(k, "nvd-baseline");
    }

    const acceptable = k.expect.also_acceptable ?? [];
    const fwGrade = grade(k.expect.verdict, acceptable, fw.verdict);
    const baseGrade = base ? grade(k.expect.verdict, acceptable, base.verdict) : null;
    const mention = (k.expect.must_mention ?? "").toLowerCase();
    const mentioned = !mention || JSON.stringify(fw.report ?? {}).toLowerCase().includes(mention);

    rows.push({ id: k.id, want: k.expect.verdict, fw, base, fwGrade, baseGrade, mentioned });

    const mark = (g: ReturnType<typeof grade>) =>
      g.status === "pass" ? green("PASS") : g.status === "soft" ? yellow("SOFT") : g.status === "err" ? red("ERR ") : red("FAIL");
    console.log(`  ${mark(fwGrade)} firstwatch: ${fw.verdict}${fwGrade.unsafe ? red("  UNSAFE") : ""} ${dim(`${fw.toolCalls} calls, ${ms(fw.ms)}${fw.downgrades ? `, ${fw.downgrades} downgraded` : ""}, ${tokens(fw.usage)}`)}`);
    if (base && baseGrade) console.log(`  ${mark(baseGrade)} baseline:   ${base.verdict}${baseGrade.unsafe ? red("  UNSAFE") : ""} ${dim(`${base.toolCalls} calls, ${ms(base.ms)}, ${tokens(base.usage)}`)}`);
    if (fw.report?.summary) console.log(`  ${dim(fw.report.summary.slice(0, 240))}`);
    if (!mentioned) console.log(`  ${yellow("missing")} expected "${k.expect.must_mention}" in the report`);
    if (fw.note) console.log(`  ${red("note")} ${fw.note.slice(0, 200)}`);
  }

  /* --- side by side ------------------------------------------------ */
  console.log(`\n${bold("scorecard")}  ${dim("FirstWatch vs an NVD-only version scanner, same cases")}`);
  console.log(dim("  case                            expected              firstwatch            nvd-only"));
  const cell = (g: ReturnType<typeof grade> | null, v: Verdict | "none" | undefined) => {
    if (!g) return "".padEnd(22);
    const t = `${v}${g.unsafe ? " !" : ""}`.padEnd(22);
    return g.status === "pass" ? green(t) : g.status === "soft" ? yellow(t) : red(t);
  };
  for (const r of rows) {
    console.log(`  ${r.id.padEnd(30)} ${r.want.padEnd(21)} ${cell(r.fwGrade, r.fw.verdict)} ${cell(r.baseGrade, r.base?.verdict)}`);
  }

  const tally = (pick: (r: typeof rows[number]) => ReturnType<typeof grade> | null) => {
    const gs = rows.map(pick).filter(Boolean) as ReturnType<typeof grade>[];
    return {
      pass: gs.filter((g) => g.status === "pass").length,
      soft: gs.filter((g) => g.status === "soft").length,
      unsafe: gs.filter((g) => g.unsafe).length,
      total: gs.length,
    };
  };
  const fwT = tally((r) => r.fwGrade);
  const baseT = tally((r) => r.baseGrade);

  console.log(`\n  firstwatch  ${fwT.pass}/${fwT.total} exact, ${fwT.soft} acceptable, ${fwT.unsafe ? red(`${fwT.unsafe} unsafe`) : green("0 unsafe")}`);
  if (baseT.total) {
    console.log(`  nvd-only    ${baseT.pass}/${baseT.total} exact, ${baseT.soft} acceptable, ${baseT.unsafe ? red(`${baseT.unsafe} unsafe`) : green("0 unsafe")}`);
  }
  const sum = (pick: (r: (typeof rows)[number]) => TokenUsage | undefined) =>
    rows.reduce((acc, r) => {
      const u = pick(r);
      if (!u) return acc;
      return { prompt: acc.prompt + u.prompt, completion: acc.completion + u.completion, total: acc.total + u.total, requests: acc.requests + u.requests };
    }, noUsage());
  const fwTokens = sum((r) => r.fw.usage);
  const baseTokens = sum((r) => r.base?.usage);
  console.log(`\n  ${bold("tokens")}`);
  console.log(`  firstwatch  ${tokens(fwTokens)}`);
  if (baseT.total) console.log(`  nvd-only    ${tokens(baseTokens)}`);
  const all = sum((r) => r.fw.usage).total + sum((r) => r.base?.usage).total;
  console.log(`  ${bold(`total       ${all.toLocaleString()} tokens across ${rows.length} case${rows.length > 1 ? "s" : ""}`)}`);
  if (rows.length) console.log(dim(`  at this rate, all 9 cases would be roughly ${Math.round((all / rows.length) * 9).toLocaleString()} tokens`));

  const gaps = rows.filter((r) => !r.mentioned).length;
  if (gaps) console.log(`  ${yellow(`${gaps} reports missing expected content`)}`);
  console.log(dim(`  reports written to ${OUT_DIR}/`));

  return fwT.total - fwT.pass - fwT.soft + fwT.unsafe;
}

const cases = loadCases();
if (!cases.length) {
  console.error(`No cases in ${CASES_DIR}${only ? ` matching "${only}"` : ""}`);
  process.exit(1);
}
console.log(`${bold("FirstWatch eval")} ${cases.length} case${cases.length > 1 ? "s" : ""}${dry ? dim(" (dry run)") : ""}`);
process.exit(dry ? (dryRun(cases) ? 1 : 0) : await liveRun(cases));
