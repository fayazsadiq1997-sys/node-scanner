/**
 * Core data model shared by every check and reporter.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Ordered weakest → strongest, used for --fail-on threshold comparisons. */
export const SEVERITY_ORDER: Severity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
];

export type Category = "secret" | "dependency" | "misconfig";

export interface Finding {
  /** Stable identifier for the rule that produced this finding, e.g. "secret.aws-access-key". */
  ruleId: string;
  category: Category;
  severity: Severity;
  /** Short human-readable summary. */
  title: string;
  /** File the finding was found in, relative to the scan root. */
  file: string;
  /** 1-based line number, when applicable. */
  line?: number;
  /** The matched snippet, redacted where it could leak a secret. */
  excerpt?: string;
  /** Actionable guidance on how to fix it. */
  remediation: string;
}

export interface ScanResult {
  root: string;
  startedAt: string;
  finishedAt: string;
  filesScanned: number;
  findings: Finding[];
}

/** Returns true if `severity` is at or above `threshold` in SEVERITY_ORDER. */
export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER.indexOf(severity) >= SEVERITY_ORDER.indexOf(threshold);
}
