/**
 * Who may start a live run on a deployed site. Live runs spend real API
 * tokens, so they are off unless LIVE_ENABLED=true, capped per day across all
 * visitors, and limited to one per visitor per window. Replay, the scanner
 * baseline and stack parsing are code and are never limited.
 *
 * With Upstash Redis configured (KV_REST_API_URL and KV_REST_API_TOKEN, as
 * Vercel's Upstash integration sets them, or the UPSTASH_REDIS_REST_* pair),
 * the counts are global. Without it they live in this instance's memory: a
 * best effort, since serverless instances do not share memory.
 */

export type LiveDecision =
  | { ok: true; store: "redis" | "memory" }
  | { ok: false; reason: "disabled" | "no_key" | "ip_window" | "daily_cap" | "store_error"; message: string };

const cap = () => Number(process.env.LIVE_DAILY_CAP ?? 10);
const windowMinutes = () => Number(process.env.LIVE_IP_WINDOW_MINUTES ?? 10);
const today = () => new Date().toISOString().slice(0, 10);
export const FALLBACK = "Showing the saved run instead.";

const redis = () => {
  const url = process.env.KV_REST_API_URL ?? process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN ?? process.env.UPSTASH_REDIS_REST_TOKEN;
  return url && token ? { url: url.replace(/\/+$/, ""), token } : null;
};

/* --- memory, per instance ------------------------------------------ */
const lastRunByIp = new Map<string, number>();
let day = { date: "", count: 0 };

export function resetLimits() {
  lastRunByIp.clear();
  day = { date: "", count: 0 };
}

/** The visitor's address as the platform reports it. */
export function clientIp(req: Request): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || req.headers.get("x-real-ip") || "unknown";
}

export async function allowLiveRun(ip: string): Promise<LiveDecision> {
  if (process.env.LIVE_ENABLED !== "true") {
    return { ok: false, reason: "disabled", message: `Live runs are switched off on this deployment. ${FALLBACK}` };
  }
  if (!process.env.LLM_API_KEY && !process.env.GROQ_API_KEY) {
    return { ok: false, reason: "no_key", message: `Live runs are not configured on this deployment. ${FALLBACK}` };
  }
  const windowSec = windowMinutes() * 60;
  const ipLimited = { ok: false as const, reason: "ip_window" as const, message: `One live run per visitor every ${windowMinutes()} minutes. ${FALLBACK}` };
  const dayLimited = { ok: false as const, reason: "daily_cap" as const, message: `Today's ${cap()} live runs are used up. ${FALLBACK}` };

  const r = redis();
  if (r) {
    try {
      // SET NX: only the first run in the window gets the lock. INCR: the day's count.
      const res = await fetch(`${r.url}/pipeline`, {
        method: "POST",
        headers: { authorization: `Bearer ${r.token}`, "content-type": "application/json" },
        body: JSON.stringify([
          ["SET", `fw:live:ip:${ip}`, "1", "NX", "EX", String(windowSec)],
          ["INCR", `fw:live:day:${today()}`],
          ["EXPIRE", `fw:live:day:${today()}`, String(2 * 24 * 3600)],
        ]),
        signal: AbortSignal.timeout(5_000),
      });
      const [lock, count] = (await res.json()) as { result: unknown }[];
      if (lock?.result !== "OK") return ipLimited;
      if (Number(count?.result) > cap()) return dayLimited;
      return { ok: true, store: "redis" };
    } catch {
      // If the limiter cannot be reached, fail closed: live runs cost money.
      return { ok: false, reason: "store_error", message: `Live runs are unavailable right now. ${FALLBACK}` };
    }
  }

  const now = Date.now();
  const last = lastRunByIp.get(ip);
  if (last && now - last < windowSec * 1000) return ipLimited;
  if (day.date !== today()) day = { date: today(), count: 0 };
  if (day.count >= cap()) return dayLimited;
  lastRunByIp.set(ip, now);
  day.count++;
  return { ok: true, store: "memory" };
}
