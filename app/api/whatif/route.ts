/**
 * POST /api/whatif: re-evaluate a recorded example with edited config, in
 * code only. The safety engine runs on the recording's saved ledger; no model
 * is called, so the same inputs always give the same answer.
 *
 * Body: { exampleId: string, files: { [name]: text } }
 */

import { savedLedger, savedRun } from "@/lib/examples";
import type { FirstWatchReport } from "@/lib/agent";
import { reevaluate } from "@/lib/whatif";

const MAX_FILES = 12;
const MAX_FILE_CHARS = 200_000;

export async function POST(req: Request) {
  let body: { exampleId?: unknown; files?: unknown };
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "Send JSON: { exampleId, files }" }, { status: 400 });
  }
  const exampleId = typeof body.exampleId === "string" ? body.exampleId : undefined;
  const run = savedRun(exampleId);
  const ledger = savedLedger(exampleId);
  if (!run || !ledger) return Response.json({ error: "There is no saved run with a ledger for this example." }, { status: 404 });

  const files: Record<string, string> = {};
  for (const [name, text] of Object.entries((body.files ?? {}) as Record<string, unknown>).slice(0, MAX_FILES)) {
    if (typeof text === "string" && text.trim()) files[name.slice(0, 100)] = text.slice(0, MAX_FILE_CHARS);
  }
  const { report, changes } = reevaluate(run.report as FirstWatchReport, ledger, files);
  return Response.json({ report, changes, label: "Re-evaluated by the safety engine · no model call" });
}
