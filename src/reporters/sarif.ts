import { writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import type { Finding, ScanResult, Severity, SuppressionKind } from "../types";

/**
 * Emit the scan result as SARIF 2.1.0 — the format GitHub Code Scanning ingests
 * to render findings inline in a repo's Security tab.
 *
 * Rule metadata (description, remediation, severity) is derived from the first
 * finding seen for each ruleId, so no separate rule catalog is needed.
 */

const SARIF_SCHEMA =
  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const TOOL_NAME = "node-sec-scanner";
const TOOL_VERSION = "0.1.0";
const TOOL_URI = "https://github.com/fayazsadiq1997-sys/node-scanner";

/** SARIF only defines three result levels; map our five severities onto them. */
function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}

/**
 * GitHub keys its alert severity off this numeric (0.0–10.0) string, not the
 * SARIF level, so populate it to get accurate severities in the Security tab.
 */
function securitySeverity(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "9.5";
    case "high":
      return "8.0";
    case "medium":
      return "5.5";
    case "low":
      return "3.0";
    default:
      return "1.0";
  }
}

/** SARIF URIs use forward slashes regardless of host OS. */
function toUri(file: string): string {
  return file.replace(/\\/g, "/");
}

/** Normalize an excerpt for stable hashing: trim + collapse internal whitespace. */
function normalizeExcerpt(excerpt: string | undefined): string {
  return (excerpt ?? "").trim().replace(/\s+/g, " ");
}

/** sha256 over ruleId + file + normalized excerpt, truncated to 16 hex chars. */
function hashFingerprint(f: Finding): string {
  return createHash("sha256")
    .update(`${f.ruleId}\0${f.file}\0${normalizeExcerpt(f.excerpt)}`)
    .digest("hex")
    .slice(0, 16);
}

/**
 * Compute a partialFingerprint per finding.
 * Collisions (same hash for two distinct findings) get a ":<index>" suffix
 * so GitHub Code Scanning can track each one independently.
 */
function computeFingerprints(findings: Finding[]): string[] {
  const hashes = findings.map(hashFingerprint);

  // Count occurrences of each hash to detect collisions.
  const counts = new Map<string, number>();
  for (const h of hashes) counts.set(h, (counts.get(h) ?? 0) + 1);

  // Assign per-hash occurrence indices only where there is a collision.
  const indices = new Map<string, number>();
  return hashes.map((h) => {
    if (counts.get(h)! === 1) return h;
    const idx = indices.get(h) ?? 0;
    indices.set(h, idx + 1);
    return `${h}:${idx}`;
  });
}

/** Builds a single SARIF result object, shared by active and suppressed findings. */
function buildResult(
  f: Finding,
  fingerprint: string,
  suppression?: { kind: SuppressionKind },
) {
  return {
    ruleId: f.ruleId,
    level: sarifLevel(f.severity),
    message: { text: f.excerpt ? `${f.title}: ${f.excerpt}` : f.title },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: toUri(f.file) },
          ...(f.line ? { region: { startLine: f.line } } : {}),
        },
      },
    ],
    partialFingerprints: { "snippetSha256/v1": fingerprint },
    ...(suppression
      ? { suppressions: [{ kind: suppression.kind, status: "accepted" }] }
      : {}),
  };
}

function buildSarif(result: ScanResult): unknown {
  const allFindings = [...result.findings, ...(result.suppressedFindings ?? [])];

  // One rule per distinct ruleId, populated from the first finding that uses it.
  const rules = new Map<string, Finding>();
  for (const f of allFindings) {
    if (!rules.has(f.ruleId)) rules.set(f.ruleId, f);
  }

  const driverRules = [...rules.values()].map((f) => ({
    id: f.ruleId,
    name: f.ruleId,
    shortDescription: { text: f.title },
    fullDescription: { text: f.remediation },
    help: { text: f.remediation },
    defaultConfiguration: { level: sarifLevel(f.severity) },
    properties: {
      category: f.category,
      "security-severity": securitySeverity(f.severity),
      tags: ["security", f.category],
    },
  }));

  // Compute fingerprints across all findings (active + suppressed) together so
  // the collision counter is consistent regardless of suppression state.
  const fingerprints = computeFingerprints(allFindings);
  const activeCount = result.findings.length;

  const activeResults = result.findings.map((f, i) =>
    buildResult(f, fingerprints[i]),
  );

  const suppressedResults = (result.suppressedFindings ?? []).map((f, i) =>
    buildResult(f, fingerprints[activeCount + i], { kind: f.suppressionKind }),
  );

  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: TOOL_URI,
            rules: driverRules,
          },
        },
        results: [...activeResults, ...suppressedResults],
      },
    ],
  };
}

export async function reportSarif(
  result: ScanResult,
  outputPath?: string,
): Promise<void> {
  const json = JSON.stringify(buildSarif(result), null, 2);
  if (outputPath) {
    await writeFile(outputPath, json, "utf8");
    console.error(`SARIF report written to ${outputPath}`);
  } else {
    console.log(json);
  }
}
