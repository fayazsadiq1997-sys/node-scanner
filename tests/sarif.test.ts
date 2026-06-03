import { test } from "node:test";
import assert from "node:assert/strict";
import type { ScanResult, SuppressedFinding } from "../src/types";

// Reach into the reporter's builder by capturing console output, since
// reportSarif writes to stdout when no output path is given.
import { reportSarif } from "../src/reporters/sarif";

function makeResult(): ScanResult {
  return {
    root: "/proj",
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    filesScanned: 2,
    suppressedFindings: [],
    suppressedCount: 0,
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

function makeResultWithSuppressed(): ScanResult {
  const suppressed: SuppressedFinding[] = [
    {
      ruleId: "misconfig.eval",
      category: "misconfig",
      severity: "high",
      title: "Use of eval()",
      file: "src/legacy.ts",
      line: 7,
      excerpt: "eval(input)",
      remediation: "Avoid eval().",
      suppressionKind: "external",
    },
    {
      ruleId: "misconfig.insecure-http",
      category: "misconfig",
      severity: "low",
      title: "Insecure HTTP URL",
      file: "src/client.ts",
      line: 3,
      excerpt: "http://internal",
      remediation: "Use HTTPS.",
      suppressionKind: "inSource",
    },
  ];
  return {
    root: "/proj",
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    filesScanned: 3,
    findings: makeResult().findings,
    suppressedFindings: suppressed,
    suppressedCount: suppressed.length,
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

test("partialFingerprints: every result has a snippetSha256/v1 key", async () => {
  const sarif = await captureSarif(makeResult());
  for (const r of sarif.runs[0].results) {
    assert.ok(r.partialFingerprints, "partialFingerprints present");
    const fp = r.partialFingerprints["snippetSha256/v1"];
    assert.ok(typeof fp === "string" && fp.length > 0, "fingerprint is a non-empty string");
  }
});

test("partialFingerprints: fingerprint is 16 hex chars when no collision", async () => {
  const sarif = await captureSarif(makeResult());
  // The two findings in makeResult() have different ruleIds → no collision.
  for (const r of sarif.runs[0].results) {
    const fp = r.partialFingerprints["snippetSha256/v1"];
    assert.match(fp, /^[0-9a-f]{16}$/, "16 hex chars, no suffix");
  }
});

test("partialFingerprints: stable across line drift", async () => {
  const base = makeResult();
  const shifted = makeResult();
  shifted.findings[0].line = 99; // move the finding to a different line

  const sarifBase = await captureSarif(base);
  const sarifShifted = await captureSarif(shifted);

  const fpBase = sarifBase.runs[0].results[0].partialFingerprints["snippetSha256/v1"];
  const fpShifted = sarifShifted.runs[0].results[0].partialFingerprints["snippetSha256/v1"];
  assert.equal(fpBase, fpShifted, "fingerprint unchanged when only line number differs");
});

test("partialFingerprints: collision suffix applied when ruleId+file+excerpt match", async () => {
  // Two identical findings → same hash → should get :0 and :1 suffixes.
  const result: ScanResult = {
    root: "/proj",
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    filesScanned: 1,
    suppressedCount: 0,
    suppressedFindings: [],
    findings: [
      {
        ruleId: "secret.aws-access-key",
        category: "secret",
        severity: "critical",
        title: "AWS access key ID",
        file: "src/config.js",
        line: 5,
        excerpt: "AKIA****MPLE",
        remediation: "Rotate the key.",
      },
      {
        ruleId: "secret.aws-access-key",
        category: "secret",
        severity: "critical",
        title: "AWS access key ID",
        file: "src/config.js",
        line: 20,
        excerpt: "AKIA****MPLE",
        remediation: "Rotate the key.",
      },
    ],
  };
  const sarif = await captureSarif(result);
  const [fp0, fp1] = sarif.runs[0].results.map(
    (r: any) => r.partialFingerprints["snippetSha256/v1"],
  );
  assert.match(fp0, /^[0-9a-f]{16}:0$/, "first collision gets :0");
  assert.match(fp1, /^[0-9a-f]{16}:1$/, "second collision gets :1");
  assert.equal(fp0.slice(0, 16), fp1.slice(0, 16), "same base hash");
});

// ---------------------------------------------------------------------------
// SARIF suppressions array (2b)
// ---------------------------------------------------------------------------

test("suppressions: suppressed findings appear in SARIF results", async () => {
  const sarif = await captureSarif(makeResultWithSuppressed());
  const results = sarif.runs[0].results;
  // 2 active + 2 suppressed
  assert.equal(results.length, 4);
});

test("suppressions: active findings have no suppressions array", async () => {
  const sarif = await captureSarif(makeResultWithSuppressed());
  const active = sarif.runs[0].results.slice(0, 2);
  for (const r of active) {
    assert.equal(r.suppressions, undefined, "active result should not have suppressions");
  }
});

test("suppressions: external suppression emits kind=external + status=accepted", async () => {
  const sarif = await captureSarif(makeResultWithSuppressed());
  // Third result is the first suppressed finding (external via .scannerignore)
  const suppressed = sarif.runs[0].results[2];
  assert.ok(Array.isArray(suppressed.suppressions), "suppressions should be an array");
  assert.equal(suppressed.suppressions.length, 1);
  assert.equal(suppressed.suppressions[0].kind, "external");
  assert.equal(suppressed.suppressions[0].status, "accepted");
});

test("suppressions: inSource suppression emits kind=inSource + status=accepted", async () => {
  const sarif = await captureSarif(makeResultWithSuppressed());
  // Fourth result is the second suppressed finding (inSource via inline comment)
  const suppressed = sarif.runs[0].results[3];
  assert.equal(suppressed.suppressions[0].kind, "inSource");
  assert.equal(suppressed.suppressions[0].status, "accepted");
});

test("suppressions: suppressed findings have partialFingerprints", async () => {
  const sarif = await captureSarif(makeResultWithSuppressed());
  for (const r of sarif.runs[0].results) {
    assert.ok(r.partialFingerprints?.["snippetSha256/v1"], "fingerprint present on all results");
  }
});

test("suppressions: rules derived from suppressed findings are included in driver.rules", async () => {
  const sarif = await captureSarif(makeResultWithSuppressed());
  const ruleIds = new Set(sarif.runs[0].tool.driver.rules.map((r: any) => r.id));
  assert.ok(ruleIds.has("misconfig.eval"), "rule from suppressed finding should be registered");
  assert.ok(ruleIds.has("misconfig.insecure-http"), "rule from suppressed finding should be registered");
});
