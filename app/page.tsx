import { DEFAULT_EXAMPLE, loadExamples } from "@/lib/examples";

import Triage from "./triage";

export default function Page() {
  // Examples are read from disk here, at build time, so the browser gets them as data.
  const examples = loadExamples();
  return (
    <main className="mx-auto w-full max-w-3xl px-4 py-8 sm:py-12">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">FirstWatch</h1>
        <p className="mt-2 text-sm leading-6 text-neutral-600 dark:text-neutral-400">
          Version scanners read one version string. FirstWatch reads what is actually installed, checks each PHP package against
          the distribution&apos;s own fix records for PHP2Shell (CVE-2026-109618 and CVE-2026-109619), and shows why every
          verdict stands.
        </p>
        <p className="mt-3 rounded-lg bg-neutral-100 px-3 py-2 text-sm text-neutral-800 dark:bg-neutral-900 dark:text-neutral-200">
          <span className="font-medium">How it works:</span> pick an example below, then see what a version scanner says next to
          what FirstWatch finds, and why.
        </p>
      </header>
      <Triage examples={examples} defaultExampleId={DEFAULT_EXAMPLE} liveEnabled={process.env.LIVE_ENABLED === "true"} />
    </main>
  );
}
