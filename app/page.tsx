import { FIELDS, loadExamples } from "@/lib/examples";

import Triage from "./triage";

export default function Page() {
  // Examples are read from disk here, at build time, so the browser gets them as data.
  const examples = loadExamples();
  return (
    <main className="mx-auto w-full max-w-3xl px-4 py-8 sm:py-12">
      <header className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight">FirstWatch</h1>
        <p className="mt-2 text-sm leading-6 text-neutral-600 dark:text-neutral-400">
          Scanners read one version string. FirstWatch reads what is actually installed, checks every engine package against the
          distribution&apos;s own fix records, and shows why each verdict stands. Disclosure: PHP2Shell, CVE-2026-109618 and
          CVE-2026-109619.
        </p>
      </header>
      <Triage examples={examples} fields={FIELDS.map((f) => ({ ...f }))} liveEnabled={process.env.LIVE_ENABLED === "true"} />
    </main>
  );
}
