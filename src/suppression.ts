import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Finding, SuppressedFinding } from "./types";

/**
 * Suppression support — two mechanisms:
 *
 * 1. .scannerignore file (file or rule level):
 *      src/legacy/file.ts                  suppress all findings in that file
 *      src/legacy/file.ts secret.aws-key   suppress one rule in that file
 *      * misconfig.insecure-http           suppress a rule globally (all files)
 *
 * 2. Inline comments (line level):
 *      const k = "AKIA..." // scanner-ignore: secret.aws-access-key
 *      // scanner-ignore: misconfig.eval
 *      eval(input)          <- this line is also suppressed (preceding-line form)
 *      // scanner-ignore    (no ruleId = suppress ALL rules on the next / same line)
 */

interface IgnoreRule {
  /** Relative file path, or null for the "*" wildcard (all files). */
  filePath: string | null;
  /** Rule to suppress, or null meaning all rules for the matched file(s). */
  ruleId: string | null;
}

// ---------------------------------------------------------------------------
// .scannerignore parser
// ---------------------------------------------------------------------------

/**
 * Loads and parses the .scannerignore file from the scan root.
 * Returns an empty array if the file does not exist.
 */
export async function loadIgnoreFile(root: string): Promise<IgnoreRule[]> {
  const ignoreFilePath = path.join(root, ".scannerignore");
  let content: string;
  try {
    content = await readFile(ignoreFilePath, "utf8");
  } catch {
    return [];
  }

  const rules: IgnoreRule[] = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const parts = line.split(/\s+/);
    const filePart = parts[0];
    const rulePart = parts[1] ?? null;

    rules.push({
      filePath: filePart === "*" ? null : filePart,
      ruleId: rulePart,
    });
  }

  return rules;
}

// ---------------------------------------------------------------------------
// File-level matching
// ---------------------------------------------------------------------------

/**
 * Returns true if a finding's file path matches the ignore rule's path.
 * Supports:
 *   null        — wildcard, matches all files
 *   exact       — "src/config/db.ts"
 *   directory   — "src/legacy" or "src/legacy/" matches any file under that dir
 */
function fileMatches(findingFile: string, rulePath: string | null): boolean {
  if (rulePath === null) return true;
  if (findingFile === rulePath) return true;
  const prefix = rulePath.endsWith("/") ? rulePath : rulePath + "/";
  return findingFile.startsWith(prefix);
}

function isFileSuppressed(finding: Finding, rules: IgnoreRule[]): boolean {
  for (const rule of rules) {
    if (!fileMatches(finding.file, rule.filePath)) continue;
    if (rule.ruleId === null || rule.ruleId === finding.ruleId) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Inline comment matching
// ---------------------------------------------------------------------------

/**
 * Parses a scanner-ignore comment from a source line.
 * Returns:
 *   null              — no scanner-ignore comment on this line
 *   []                — scanner-ignore with no ruleId (suppress all rules)
 *   ["rule.id", ...]  — one or more specific rules to suppress
 */
function parseInlineIgnore(lineContent: string): string[] | null {
  const match = /\/\/\s*scanner-ignore(?::\s*(.+))?/i.exec(lineContent);
  if (!match) return null;
  if (!match[1]) return [];
  return match[1]
    .split(",")
    .map((r) => r.trim())
    .filter(Boolean);
}

/**
 * Returns true if the finding is suppressed by an inline comment.
 * Supports two placements:
 *   - Trailing:       const x = badValue; // scanner-ignore: rule.id
 *   - Preceding-line: // scanner-ignore: rule.id
 *                     const x = badValue;
 */
function isInlineSuppressed(finding: Finding, lines: string[]): boolean {
  if (!finding.line) return false;
  const lineIdx = finding.line - 1;

  // Same-line trailing comment
  const sameLine = parseInlineIgnore(lines[lineIdx] ?? "");
  if (sameLine !== null) {
    if (sameLine.length === 0 || sameLine.includes(finding.ruleId)) return true;
  }

  // Preceding-line comment (next-line suppression)
  if (lineIdx > 0) {
    const prevLine = parseInlineIgnore(lines[lineIdx - 1] ?? "");
    if (prevLine !== null) {
      if (prevLine.length === 0 || prevLine.includes(finding.ruleId)) return true;
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface SuppressionResult {
  kept: Finding[];
  suppressedFindings: SuppressedFinding[];
}

/**
 * Filters out suppressed findings and returns them tagged with their mechanism.
 *
 * @param findings  all raw findings from every checker
 * @param ignoreRules  parsed .scannerignore rules (may be empty)
 * @param fileLines  map of relPath → split lines, used for inline comment checks
 */
export function applySuppressions(
  findings: Finding[],
  ignoreRules: IgnoreRule[],
  fileLines: Map<string, string[]>,
): SuppressionResult {
  const kept: Finding[] = [];
  const suppressedFindings: SuppressedFinding[] = [];

  for (const finding of findings) {
    if (isFileSuppressed(finding, ignoreRules)) {
      suppressedFindings.push({ ...finding, suppressionKind: "external" });
      continue;
    }

    const lines = fileLines.get(finding.file);
    if (lines && isInlineSuppressed(finding, lines)) {
      suppressedFindings.push({ ...finding, suppressionKind: "inSource" });
      continue;
    }

    kept.push(finding);
  }

  return { kept, suppressedFindings };
}
