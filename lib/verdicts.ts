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
