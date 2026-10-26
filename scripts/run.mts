/**
 * Manual harness: run FirstWatch once, end to end, no UI.
 *
 *   npm run agent -- --files eval/cases/g-split-cli-patched-fpm-stale
 *   npm run agent -- --files <dir> --cve CVE-2026-109618 --target <advisory url> --source <companion url>
 *
 * With --files pointing at an eval case, its case.json supplies the CVE, target
 * and sources unless flags override them. --baseline prints the scanner's
 * verdict as well. --json prints the report only.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { MAX_ITERATIONS, VERDICT_LABELS, runAgent, type AgentEvent } from "../lib/agent";
import { runBaseline } from "../lib/baseline";
import { mergeUsage } from "../lib/llm";
import { loadEnv } from "./env.mjs";

loadEnv();

const argv = process.argv.slice(2);
const flag = (...n: string[]) => {
  const i = argv.findIndex((a) => n.includes(a));
  return i >= 0 ? argv[i + 1] : undefined;
};
const flags = (name: string) => argv.flatMap((a, i) => (a === name && argv[i + 1] ? [argv[i + 1]] : []));
const has = (...n: string[]) => argv.some((a) => n.includes(a));

const dir = flag("--files", "-f");
const files = dir
  ? Object.fromEntries(readdirSync(dir).filter((f) => f !== "case.json" && statSync(join(dir, f)).isFile()).map((f) => [f, readFileSync(join(dir, f), "utf8")]))
  : undefined;
const spec = dir && existsSync(join(dir, "case.json"))
  ? (JSON.parse(readFileSync(join(dir, "case.json"), "utf8")) as { stack?: string; cve?: string; target?: string; sources?: string[] })
  : {};

const stack = flag("--stack", "-s") ?? spec.stack ?? "";
const target = flag("--target", "-t") ?? spec.target;
const cve = flag("--cve") ?? spec.cve;
const sources = flags("--source").length ? flags("--source") : (spec.sources ?? []);
const model = flag("--model", "-m");
const max = Number(flag("--max", "-n") ?? MAX_ITERATIONS);
const asJson = has("--json");

if (!target || (!stack && !files)) {
  console.error("Usage: npm run agent -- --files <case dir>   (or --files <dir> --cve <id> --target <url> [--source <url>])");
  process.exit(1);
}

const plain = Boolean(process.env.NO_COLOR) || !process.stdout.isTTY;
const c = (code: string) => (s: string | number) => (plain ? String(s) : `\u001b[${code}m${s}\u001b[0m`);
const [dim, bold, red, green, yellow, blue] = ["2", "1", "31", "32", "33", "36"].map(c);
const ms = (x: number) => (x < 1000 ? `${x}ms` : `${(x / 1000).toFixed(1)}s`);
const n = (x: number) => x.toLocaleString();
const rule = (t = "") => console.log(dim(`--- ${t} ${"-".repeat(Math.max(0, 66 - t.length))}`));
const colour = (v: string) => (v === "AFFECTED" ? red : v === "NOT_AFFECTED" ? green : yellow);

function show(e: AgentEvent) {
  if (asJson && e.type !== "final") return;
  switch (e.type) {
    case "start":
      console.log(`${bold("FirstWatch")} ${dim(`${e.model} via ${e.baseUrl}; budget ${n(e.budget.tpm)} tokens/min, ${e.budget.rpm} requests/min, ${n(e.budget.maxRequestTokens)} per request`)}`);
      console.log(`${dim("target")} ${e.target}`);
      break;
    case "facts":
      console.log(`${dim("stack ")} ${e.summary}`);
      break;
    case "nvd":
      console.log(`${dim("nvd   ")} ${e.id}: ${e.ranges} php ranges${e.note ? ` (${e.note})` : ""}`);
      break;
    case "digest_request":
      console.log(`${dim("digest")} part ${e.index} of ${e.of}, ~${n(e.estimated)} tokens`);
      break;
    case "digest":
      console.log(`${dim("digest")} ${e.url}: ${e.error ? red(e.error) : e.cached ? `cached, ${e.items} items` : `${e.items} verified items, ${e.dropped} discarded, ${n(e.tokens)} tokens`}`);
      break;
    case "waiting":
      console.log(`${yellow("wait  ")} ${ms(e.ms)}: ${e.reason}`);
      break;
    case "compacted":
      console.log(`${yellow("compact")} ${e.note} (~${n(e.estimated)} tokens)`);
      break;
    case "request":
      console.log(`${dim(`${e.label}: ${n(e.total)} tokens (${n(e.prompt)} in, ${n(e.completion)} out, estimated ${n(e.estimated)})`)}${e.finish === "length" ? red(" cut off") : ""}`);
      break;
    case "thinking":
      console.log(`${dim("thinking")} ${e.text}`);
      break;
    case "tool_call":
      console.log(`${blue(e.tool)} ${dim(Object.entries(e.args).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(" "))}`);
      break;
    case "tool_result":
      console.log(`  ${e.ok ? green("ok") : red("failed")} ${dim(ms(e.ms))} ${e.summary}`);
      break;
    case "repair":
      console.log(`${yellow("repair")} ${e.errors.join("; ")}`);
      break;
    case "capped":
      console.log(`${yellow("cap")} ${e.note}`);
      break;
    case "enforced":
      rule("invariants");
      for (const d of e.downgrades) console.log(`${yellow(d.invariant)} ${bold(d.package)}: ${d.from} -> ${d.to}\n   ${dim(d.why)}`);
      break;
    case "final": {
      if (asJson) {
        console.log(JSON.stringify(e.report, null, 2));
        break;
      }
      rule("report");
      if (!e.report) {
        console.log(`${red("no valid report")}: ${e.reportError}`);
        console.log(e.text);
      } else {
        const r = e.report;
        console.log(`${colour(r.overall)(bold(VERDICT_LABELS[r.overall]))}  ${r.summary}`);
        for (const f of r.findings) {
          console.log(`\n${bold(f.package)} ${f.installed_version} ${dim(`(${f.version_source})`)}  ${colour(f.verdict)(VERDICT_LABELS[f.verdict])}`);
          console.log(`  ${dim(`decided by ${f.decided_by?.method}: ${f.decided_by?.detail ?? ""}`)}`);
          if (f.allow_reason) console.log(`  ${dim(`allowed: ${f.allow_reason}`)}`);
          for (const en of f.enforcement ?? []) console.log(`  ${yellow(`downgraded by ${en.invariant}`)} ${en.from} -> ${en.to}: ${dim(en.why)}`);
          for (const cit of f.citations ?? []) console.log(`  ${cit.verified === false ? red("cite?") : dim("cite ")} ${cit.claim} ${dim(`"${cit.quote}" (${cit.source})`)}`);
          for (const rem of (f.remediation ?? []).slice().sort((a, b) => a.priority - b.priority)) console.log(`  ${rem.priority}. [${rem.type}] ${rem.action}`);
          for (const u of f.unverified ?? []) console.log(`  ${yellow("need")} ${u.missing} ${dim(`-> ${u.how_to_get_it}`)}`);
        }
        for (const w of r.warnings ?? []) console.log(`\n${yellow("warning")} ${w.why}\n  ${dim(`${w.where}: ${w.stack_text}`)}\n  ${dim(`"${w.quote}" (${w.source})`)}`);
      }
      const all = mergeUsage(e.usage, e.digestUsage);
      rule();
      console.log(dim(`${e.toolCalls} tool calls, ${ms(e.ms)}; tokens: agent ${n(e.usage.total)}, digests ${n(e.digestUsage.total)}, total ${n(all.total)} in ${all.requests} requests, largest ${n(all.maxRequest)}`));
      break;
    }
    case "error":
      console.error(`\n${red("error")} ${e.message}`);
      break;
  }
}

let failed = false;
for await (const event of runAgent({ stack, files, target, cve, sources, model, maxIterations: max })) {
  show(event);
  if (event.type === "error") failed = true;
}
if (has("--baseline") && cve) {
  const b = await runBaseline({ files, cve, target });
  console.log(`\n${dim("scanner baseline:")} ${VERDICT_LABELS[b.report.overall]} ${dim(`from "${b.version ?? "nothing"}"`)}`);
}
process.exit(failed ? 1 : 0);
