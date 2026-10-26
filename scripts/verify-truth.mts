/**
 * Re-verify eval/ground-truth.md against the live OSV API.
 * Run this before trusting any expected verdict in eval/cases.
 *   npm run verify-truth
 */
import { check_distro_fix } from "../lib/tools";

const CVE = process.argv[2] ?? "CVE-2026-109618";

const ROWS: [string, string, string, "fixed" | "affected" | "unknown"][] = [
  ["Ubuntu:22.04:LTS", "php8.1", "8.1.2-1ubuntu2.28", "fixed"],
  ["Ubuntu:22.04:LTS", "php8.1-fpm", "8.1.2-1ubuntu2.28", "fixed"],
  ["Ubuntu:22.04:LTS", "libapache2-mod-php8.1", "8.1.2-1ubuntu2.28", "fixed"],
  ["Ubuntu:22.04:LTS", "php8.1-fpm", "8.1.2-1ubuntu2.21", "affected"],
  ["Ubuntu:24.04:LTS", "php8.3-fpm", "8.3.6-0ubuntu0.24.04.13", "fixed"],
  ["Ubuntu:24.04:LTS", "php8.3-fpm", "8.3.6-0ubuntu0.24.04.5", "affected"],
  ["Debian:12", "php8.2-fpm", "8.2.35-1~deb12u1", "fixed"],
  ["Debian:12", "php8.2-fpm", "8.2.32-1~deb12u1", "affected"],
  ["Debian:13", "php8.4-cli", "8.4.27-1~deb13u1", "fixed"],
  ["Debian:13", "php8.4-fpm", "8.4.16-1~deb13u1", "affected"],
  // traps: none of these may ever come back "fixed"
  ["Ubuntu:22.04:LTS", "php-fpm", "8.1.2-1ubuntu2.28", "unknown"],
  ["Ubuntu:22.04:LTS", "php8.1-fpm", "8.1.33", "unknown"],
  ["Ubuntu:99.04", "php8.1-fpm", "8.1.2-1ubuntu2.28", "unknown"],
];

let bad = 0;
for (const [ecosystem, pkg, version, want] of ROWS) {
  const r = await check_distro_fix(CVE, ecosystem, pkg, version);
  const got = r.ok ? r.status : "ERROR";
  const pass = got === want;
  if (!pass) bad++;
  console.log(
    `${pass ? "ok  " : "FAIL"} ${ecosystem.padEnd(17)} ${pkg.padEnd(22)} ${version.padEnd(26)} ${String(got).padEnd(8)} (want ${want})` +
      (r.ok && r.fixedVersion ? `  fixed_in=${r.fixedVersion}` : ""),
  );
  if (!pass) console.log(`     ${r.ok ? r.summary : r.error}`);
}
console.log(`\n${bad ? `${bad}/${ROWS.length} rows DISAGREE with OSV: update eval/ground-truth.md and the cases` : `all ${ROWS.length} rows match OSV`}`);
process.exit(bad ? 1 : 0);
