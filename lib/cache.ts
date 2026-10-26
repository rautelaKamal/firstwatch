/**
 * Disk cache for things that are expensive to fetch or expensive to compute:
 * advisory pages, NVD records, and the model-built advisory digests.
 *
 * Every function here swallows its own errors. A read-only filesystem (a
 * serverless deploy, say) just means nothing is cached.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { fetch_advisory, fetch_cve, type Advisory, type CveRecord, type Fail } from "./tools";

const dir = () => process.env.FIRSTWATCH_CACHE_DIR ?? join(process.cwd(), ".cache", "firstwatch");
const DAY = 24 * 60 * 60 * 1000;

export const hash = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 16);

export function cacheGet<T>(key: string, maxAgeMs = Infinity): T | null {
  try {
    const path = join(dir(), `${key}.json`);
    if (!existsSync(path)) return null;
    const entry = JSON.parse(readFileSync(path, "utf8")) as { savedAt: number; value: T };
    return Date.now() - entry.savedAt > maxAgeMs ? null : entry.value;
  } catch {
    return null;
  }
}

export function cachePut<T>(key: string, value: T): void {
  try {
    mkdirSync(dir(), { recursive: true });
    writeFileSync(join(dir(), `${key}.json`), JSON.stringify({ savedAt: Date.now(), value }));
  } catch {
    /* no cache, no harm */
  }
}

/** The raw advisory page, fetched once a day at most. */
export async function cachedAdvisory(url: string): Promise<(Advisory & { cached: boolean }) | Fail> {
  const key = `advisory-${hash(url)}`;
  const hit = cacheGet<Advisory>(key, DAY);
  if (hit) return { ...hit, cached: true };
  const page = await fetch_advisory(url);
  if (page.ok) cachePut(key, page);
  return page.ok ? { ...page, cached: false } : page;
}

/** The NVD record, fetched once a day at most. NVD rate-limits keyless clients hard. */
export async function cachedCve(id: string): Promise<(CveRecord & { cached: boolean }) | Fail> {
  const key = `nvd-${id.toUpperCase()}`;
  const hit = cacheGet<CveRecord>(key, DAY);
  if (hit) return { ...hit, cached: true };
  const rec = await fetch_cve(id);
  if (rec.ok) cachePut(key, rec);
  return rec.ok ? { ...rec, cached: false } : rec;
}
