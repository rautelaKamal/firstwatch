import { DEFAULT_EXAMPLE, initialRun, loadExamples, SAMPLE_EXAMPLE } from "@/lib/examples";

import Triage from "./triage";

export default function Page() {
  // Examples are read from disk here, at build time, so the browser gets them as data.
  const examples = loadExamples();
  return (
    <main className="mx-auto w-full max-w-3xl px-4 py-8 sm:py-12">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">FirstWatch</h1>
        <p className="mt-2 text-base leading-7 text-neutral-800 dark:text-neutral-200">
          Package scanners tell you what to upgrade. FirstWatch reads the advisory and tells you why you&apos;re exposed, what partially protects you,
          and proves every claim.
        </p>
        <p className="mt-2 text-sm leading-6 text-neutral-600 dark:text-neutral-400">
          Every verdict is capped by what the evidence can prove. It can&apos;t be talked into reassuring you.
        </p>
        <p className="mt-3 text-sm font-medium text-neutral-800 dark:text-neutral-200">
          FirstWatch tells you whether you&apos;re exposed, not whether you&apos;ve already been attacked.
        </p>
      </header>
      <Triage
        examples={examples}
        defaultExampleId={DEFAULT_EXAMPLE}
        sampleExampleId={SAMPLE_EXAMPLE}
        liveEnabled={process.env.LIVE_ENABLED === "true"}
        ipWindowMinutes={Number(process.env.LIVE_IP_WINDOW_MINUTES ?? 10)}
        initialRun={initialRun(DEFAULT_EXAMPLE)}
      />
    </main>
  );
}
