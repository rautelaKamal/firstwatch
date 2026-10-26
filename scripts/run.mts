/**
 * Manual harness: run the agent once against a stack, end to end, no UI.
 *
 *   npm run agent -- --files eval/cases/g-split-cli-patched-fpm-stale \
 *                    --cve CVE-2026-109618 \
 *                    --target https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
 *
 * Flags: --files <dir> --stack <text> --target <url|cve> --cve <id>
 *        --mode firstwatch|nvd-baseline --model --max --json --full
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { MAX_ITERATIONS, runAgent, type AgentEvent, type AgentMode } from "../lib/agent";
import { loadEnv } from "./env.mjs";

loadEnv();

const argv = process.argv.slice(2);
const flag = (...n: string[]) => {
  const i = argv.findIndex((a) => n.includes(a));
  return i >= 0 ? argv[i + 1] : undefined;
};
const has = (...n: string[]) => argv.some((a) => n.includes(a));

const filesDir = flag("--files", "-f");
const files = filesDir
  ? Object.fromEntries(
      readdirSync(filesDir)
        .filter((f) => f !== "case.json" && statSync(join(filesDir, f)).isFile())
        .map((f) => [f, readFileSync(join(filesDir, f), "utf8")]),
    )
  : undefined;

const stack = flag("--stack", "-s") ?? "";
const target = flag("--target", "-t");
const cve = flag("--cve");
const mode = (flag("--mode") ?? "firstwatch") as AgentMode;
const model = flag("--model", "-m");
const max = Number(flag("--max", "-n") ?? MAX_ITERATIONS);
const full = has("--full");
const asJson = has("--json");

if (!target || (!stack && !files)) {
  console.error(
    "Usage: npm run agent -- --files <case dir> --cve CVE-2026-109618 --target <advisory url or CVE id>\n" +
      "       npm run agent -- --stack \"Ubuntu 22.04, php8.1-fpm\" --target <url>\n" +
      "       flags: --files --stack --target --cve --mode --model --max --full --json",
  );
  process.exit(1);
}

const plain = Boolean(process.env.NO_COLOR) || !process.stdout.isTTY;
const c = (code: string) => (s: string | number) => (plain ? String(s) : `\u001b[${code}m${s}\u001b[0m`);
const dim = c("2");
const bold = c("1");
const red = c("31");
const green = c("32");
const yellow = c("33");
const blue = c("36");
const magenta = c("35");
const ms = (n: number) => (n < 1000 ? `${n}ms` : `${(n / 1000).toFixed(1)}s`);
const rule = (label = "") => console.log(dim(`---${label ? ` ${label} ` : "-"}${"-".repeat(Math.max(0, 68 - label.length))}`));

let step = 0;

function show(e: AgentEvent) {
  if (asJson && e.type !== "final") return;
  switch (e.type) {
    case "start":
      console.log(`${bold("FirstWatch")} ${dim(`${e.model} via ${e.baseUrl}`)} ${e.mode === "nvd-baseline" ? yellow("[nvd-only baseline]") : ""}`);
      console.log(`${dim("target")} ${e.target}`);
      rule();
      break;
    case "facts":
      console.log(`${dim("facts ")} ${e.summary}`);
      console.log(`${dim("osv   ")} ${e.ecosystems.join(", ") || red("no ecosystem derived")}  ${e.runtimeEvidence ? green("runtime evidence present") : yellow("build intent only")}`);
      for (const u of e.unverified) console.log(`        ${yellow("unverified")} ${u}`);
      rule();
      break;
    case "thinking":
      console.log(`${dim(`[${e.iteration}]`)} ${magenta("thinking")} ${e.text}`);
      break;
    case "tool_call": {
      step++;
      console.log(`${dim(`[${e.iteration}]`)} ${blue(`${step}. ${e.tool}`)} ${dim(Object.entries(e.args).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(" "))}`);
      break;
    }
    case "tool_result":
      console.log(`      ${e.ok ? green("ok") : red("failed")} ${dim(ms(e.ms))} ${e.summary}`);
      if (full) console.log(dim(JSON.stringify(e.result, null, 2).replace(/^/gm, "      ")));
      break;
    case "repair":
      console.log(`${yellow("repair")} the reply did not match the schema: ${e.errors.join("; ")}`);
      break;
    case "capped":
      console.log(`${yellow("cap")} ${e.note}`);
      break;
    case "enforced":
      rule("invariants");
      for (const d of e.downgrades) {
        console.log(`${yellow(d.invariant)} ${bold(d.package)}: ${d.from} ${dim("->")} ${red(d.to)}`);
        console.log(`   ${dim(d.why)}`);
      }
      break;
    case "final": {
      if (asJson || full) {
        console.log(JSON.stringify(e.report, null, 2));
        break;
      }
      rule("report");
      if (!e.report) {
        console.log(`${red("no valid report")}: ${e.reportError ?? "unknown"}`);
        console.log(e.text);
      } else {
        const r = e.report;
        const colour = r.overall === "AFFECTED" ? red : r.overall === "NOT_AFFECTED" ? green : yellow;
        console.log(`${colour(bold(r.overall))}  ${r.summary}`);
        for (const f of r.findings) {
          const fc = f.verdict === "AFFECTED" ? red : f.verdict === "NOT_AFFECTED" ? green : yellow;
          console.log(`\n${bold(f.package)} ${f.installed_version} ${dim(`(${f.version_source})`)}  ${fc(f.verdict)}`);
          console.log(`  ${dim(`decided by ${f.decided_by?.method}: ${f.decided_by?.detail ?? ""}`)}`);
          console.log(`  ${dim(`exploitation: ${f.exploitation_confidence}, severity ${f.severity?.cvss ?? "?"} ${f.severity?.score ?? ""}`)}`);
          for (const cit of f.citations ?? []) console.log(`  ${dim("cite")} ${cit.claim}\n       ${dim(`"${cit.quote}"`)}\n       ${dim(cit.source)}`);
          for (const m of f.mitigations ?? []) console.log(`  ${yellow("mitigation")} ${m.setting}=${m.value} ${dim(`"${m.quote}"`)}`);
          if (f.eol) console.log(`  ${dim(`eol: ${f.eol.branch} is_eol=${f.eol.is_eol} upstream_release=${f.eol.upstream_release_exists} ${f.eol.note}`)}`);
          for (const rem of (f.remediation ?? []).slice().sort((a, b) => a.priority - b.priority)) {
            console.log(`  ${rem.priority}. [${rem.type}] ${rem.action}\n       ${dim(rem.detail)}`);
          }
          for (const u of f.unverified ?? []) console.log(`  ${yellow("need")} ${u.missing} ${dim(`-> ${u.how_to_get_it}`)}`);
          for (const en of f.enforcement ?? []) console.log(`  ${yellow(`downgraded by ${en.invariant}`)} ${en.from} -> ${en.to} ${dim(en.why)}`);
        }
      }
      rule();
      console.log(dim(`${e.iteration} iterations, ${e.toolCalls} tool calls, ${ms(e.ms)} total, ${e.usage.total.toLocaleString()} tokens (${e.usage.prompt.toLocaleString()} in, ${e.usage.completion.toLocaleString()} out, ${e.usage.requests} requests)`));
      break;
    }
    case "error":
      console.error(`\n${red("error")} ${e.message}`);
      break;
  }
}

let failed = false;
for await (const event of runAgent({ stack, files, target, cve, mode, model, maxIterations: max })) {
  show(event);
  if (event.type === "error") failed = true;
}
process.exit(failed ? 1 : 0);
