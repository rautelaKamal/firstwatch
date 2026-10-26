/**
 * Copy the local cache into data/cache, the committed seed a deploy reads.
 * Only the current digest version, NVD records and the advisory pages they
 * quote are copied. Nothing here contains credentials.
 *
 *   npm run seed-cache
 */

import { copyFileSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

const from = join(process.cwd(), ".cache", "firstwatch");
const to = join(process.cwd(), "data", "cache");
const KEEP = /^(digest-v3-|nvd-|advisory-).*\.json$/;

if (!existsSync(from)) {
  console.error(`No local cache at ${from}. Run the eval first.`);
  process.exit(1);
}
rmSync(to, { recursive: true, force: true });
mkdirSync(to, { recursive: true });
const files = readdirSync(from).filter((f) => KEEP.test(f));
for (const f of files) copyFileSync(join(from, f), join(to, f));
console.log(`Seeded ${files.length} files into data/cache:\n${files.map((f) => `  ${f}`).join("\n")}`);
