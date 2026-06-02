import { test } from "node:test";
import assert from "node:assert/strict";
import type { ScanResult } from "../src/types";

// Reach into the reporter's builder by capturing console output, since
// reportSarif writes to stdout when no output path is given.
import { reportSarif } from "../src/reporters/sarif";

function makeResult(): ScanResult {
  return {
    root: "/proj",
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    filesScanned: 2,
    findings: [
      {
        ruleId: "secret.aws-access-key",
        category: "secret",
        severity: "critical",
        title: "AWS access key ID",
        file: "src\\config.js",
        line: 5,
        excerpt: "AKIA****MPLE",
        remediation: "Rotate the key.",
      },
      {
        ruleId: "misconfig.cors-wildcard",
        category: "misconfig",
        severity: "medium",
        title: "Permissive CORS origin '*'",
        file: "src/app.ts",
        line: 12,
        remediation: "Use an allowlist.",
      },
    ],
  };
}

/** Capture whatever reportSarif logs to stdout and parse it back to JSON. */
async function captureSarif(result: ScanResult): Promise<any> {
  const original = console.log;
  let captured = "";
  console.log = (msg?: unknown) => {
    captured += String(msg);
  };
  try {
    await reportSarif(result);
  } finally {
    console.log = original;
  }
  return JSON.parse(captured);
}

test("emits valid SARIF 2.1.0 envelope", async () => {
  const sarif = await captureSarif(makeResult());
  assert.equal(sarif.version, "2.1.0");
  assert.ok(sarif["$schema"], "should set $schema");
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].tool.driver.name, "node-sec-scanner");
});

test("derives one rule per distinct ruleId", async () => {
  const sarif = await captureSarif(makeResult());
  const rules = sarif.runs[0].tool.driver.rules;
  assert.equal(rules.length, 2);
  const ids = rules.map((r: any) => r.id);
  assert.ok(ids.includes("secret.aws-access-key"));
  assert.ok(ids.includes("misconfig.cors-wildcard"));
});

test("maps severity onto SARIF levels and security-severity", async () => {
  const sarif = await captureSarif(makeResult());
  const rules = sarif.runs[0].tool.driver.rules;
  const aws = rules.find((r: any) => r.id === "secret.aws-access-key");
  const cors = rules.find((r: any) => r.id === "misconfig.cors-wildcard");
  assert.equal(aws.defaultConfiguration.level, "error");
  assert.equal(aws.properties["security-severity"], "9.5");
  assert.equal(cors.defaultConfiguration.level, "warning");
});

test("normalises file paths to forward-slash URIs", async () => {
  const sarif = await captureSarif(makeResult());
  const uris = sarif.runs[0].results.map(
    (r: any) => r.locations[0].physicalLocation.artifactLocation.uri,
  );
  assert.ok(
    uris.every((u: string) => !u.includes("\\")),
    "no backslashes in URIs",
  );
  assert.ok(uris.includes("src/config.js"));
});

test("every result references a defined rule", async () => {
  const sarif = await captureSarif(makeResult());
  const run = sarif.runs[0];
  const ruleIds = new Set(run.tool.driver.rules.map((r: any) => r.id));
  assert.ok(
    run.results.every((r: any) => ruleIds.has(r.ruleId)),
    "all results map to a rule",
  );
});
