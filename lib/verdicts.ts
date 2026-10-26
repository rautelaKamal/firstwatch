/**
 * Verdicts and how they are shown. Kept free of server-only imports so the
 * browser bundle can use it.
 */

export const VERDICTS = ["AFFECTED", "AFFECTED_MITIGATED", "NOT_AFFECTED", "UNVERIFIED"] as const;
export type Verdict = (typeof VERDICTS)[number];

/** How each verdict is shown to people. Both advisories are explicit that no
 *  configuration is a complete fix, so a mitigated package is still affected. */
export const VERDICT_LABELS: Record<Verdict, string> = {
  AFFECTED: "Affected",
  AFFECTED_MITIGATED: "Affected, exposure reduced",
  NOT_AFFECTED: "Not affected",
  UNVERIFIED: "Unverified",
};

/** How reassuring each verdict is; the least reassuring finding is the overall verdict. */
export const REASSURANCE: Record<Verdict, number> = {
  NOT_AFFECTED: 3,
  AFFECTED_MITIGATED: 2,
  UNVERIFIED: 1,
  AFFECTED: 0,
};

/** The checks every verdict passes through after the model answers. Enforced in lib/agent.ts. */
export const INVARIANTS = {
  I1: "NOT_AFFECTED requires an OSV-confirmed fix for this exact installed version in this stack's own ecosystem, or a code-computed out-of-range result.",
  I2: "AFFECTED_MITIGATED requires sourced evidence that the package is affected, plus a mitigation.",
  I3: "A verdict more reassuring than UNVERIFIED requires runtime evidence of this package's own installed version.",
  I4: "An inexact version cannot decide a range that splits inside its own branch.",
  I5: "A package's verdict must rest on that package's own installed version, never on another package's.",
  I6: "Every engine-carrying PHP package in the stack needs a verdict for every CVE under assessment.",
  I7: "A range may only clear a package if its boundary versions appear in something actually fetched this run.",
  I8: "A range clears a version only if no range places it inside, and the clearing range covers the version's own branch.",
  I9: "A finding must name a package that is in the parsed inventory.",
  I10: "A mitigation counts only if its quote appears in a fetched advisory, names the setting, and the stack actually sets it.",
  I11: "A finding must be about one of the CVEs under assessment, and evidence for one CVE never clears another.",
} as const;
