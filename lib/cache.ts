/**
 * Disk cache for things that are expensive to fetch or expensive to compute:
 * advisory pages, NVD records, and the model-built advisory digests.
 *
 * Every function here swallows its own errors. A read-only filesystem (a
 * serverless deploy, say) just means nothing is cached.
 *
 * Two places are read: the writable cache (.cache/firstwatch locally,
 * /tmp/firstwatch on Vercel, where the deployment is read-only), then the seed
 * in data/cache, which is committed so a deploy starts with digests that took
 * tokens to build. `npm run seed-cache` refreshes the seed from the local cache.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { fetch_advisory, fetch_cve, type Advisory, type CveRecord, type Fail } from "./tools";

// Paths here come from environment variables, which file tracing cannot follow,
// so the fs calls are marked turbopackIgnore and the seed is included explicitly
// through outputFileTracingIncludes in next.config.ts.
const dir = () =>
  process.env.FIRSTWATCH_CACHE_DIR ?? (process.env.VERCEL ? "/tmp/firstwatch" : join(/*turbopackIgnore: true*/ process.cwd(), ".cache", "firstwatch"));
export const seedDir = () => process.env.FIRSTWATCH_SEED_DIR ?? join(process.cwd(), "data", "cache");
const DAY = 24 * 60 * 60 * 1000;

export const hash = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 16);

function readEntry<T>(base: string, key: string): { savedAt: number; value: T } | null {
  try {
    const path = join(base, `${key}.json`);
    return existsSync(/*turbopackIgnore: true*/ path) ? (JSON.parse(readFileSync(/*turbopackIgnore: true*/ path, "utf8")) as { savedAt: number; value: T }) : null;
  } catch {
    return null;
  }
}

/** The freshest entry for this key, from the writable cache or the seed, if within maxAgeMs. */
export function cacheGet<T>(key: string, maxAgeMs = Infinity): T | null {
  for (const base of [dir(), seedDir()]) {
    const entry = readEntry<T>(base, key);
    if (entry && Date.now() - entry.savedAt <= maxAgeMs) return entry.value;
  }
  return null;
}

/** Any entry for this key, however old: the fallback when a live fetch fails. */
function cacheGetStale<T>(key: string): T | null {
  return readEntry<T>(dir(), key)?.value ?? readEntry<T>(seedDir(), key)?.value ?? null;
}

export function cachePut<T>(key: string, value: T): void {
  try {
    mkdirSync(/*turbopackIgnore: true*/ dir(), { recursive: true });
    writeFileSync(/*turbopackIgnore: true*/ join(dir(), `${key}.json`), JSON.stringify({ savedAt: Date.now(), value }));
  } catch {
    /* no cache, no harm */
  }
}

/** Every cached value whose key starts with `prefix`. */
export function cacheEntries<T>(prefix: string): T[] {
  const out: T[] = [];
  for (const base of [dir(), seedDir()]) {
    try {
      for (const f of readdirSync(/*turbopackIgnore: true*/ base).filter((x) => x.startsWith(prefix) && x.endsWith(".json"))) {
        out.push((JSON.parse(readFileSync(join(/*turbopackIgnore: true*/ base, f), "utf8")) as { value: T }).value);
      }
    } catch {
      /* a missing directory is an empty one */
    }
  }
  return out;
}

/** The raw advisory page, fetched once a day at most. */
export async function cachedAdvisory(url: string): Promise<(Advisory & { cached: boolean }) | Fail> {
  const key = `advisory-${hash(url)}`;
  const hit = cacheGet<Advisory>(key, DAY);
  if (hit) return { ...hit, cached: true };
  const page = await fetch_advisory(url);
  if (page.ok) cachePut(key, page);
  if (page.ok) return { ...page, cached: false };
  const stale = cacheGetStale<Advisory>(key);
  return stale ? { ...stale, cached: true } : page;
}

/** The NVD record, fetched once a day at most. NVD rate-limits keyless clients hard. */
export async function cachedCve(id: string): Promise<(CveRecord & { cached: boolean }) | Fail> {
  const key = `nvd-${id.toUpperCase()}`;
  const hit = cacheGet<CveRecord>(key, DAY);
  if (hit) return { ...hit, cached: true };
  const rec = await fetch_cve(id);
  if (rec.ok) cachePut(key, rec);
  if (rec.ok) return { ...rec, cached: false };
  // NVD rate-limits keyless clients hard, and shared hosting IPs harder.
  const stale = cacheGetStale<CveRecord>(key);
  return stale ? { ...stale, cached: true } : rec;
}
