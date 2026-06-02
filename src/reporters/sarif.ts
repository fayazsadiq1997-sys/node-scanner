import { writeFile } from "node:fs/promises";
import type { Finding, ScanResult, Severity } from "../types";

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

function buildSarif(result: ScanResult): unknown {
  // One rule per distinct ruleId, populated from the first finding that uses it.
  const rules = new Map<string, Finding>();
  for (const f of result.findings) {
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

  const results = result.findings.map((f) => ({
    ruleId: f.ruleId,
    level: sarifLevel(f.severity),
    message: { text: f.excerpt ? `${f.title}: ${f.excerpt}` : f.title },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: toUri(f.file) },
          // Region is omitted entirely when there's no line, rather than
          // emitting an invalid startLine.
          ...(f.line ? { region: { startLine: f.line } } : {}),
        },
      },
    ],
  }));

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
        results,
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
