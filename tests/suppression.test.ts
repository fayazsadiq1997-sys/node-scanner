import { test } from "node:test";
import assert from "node:assert/strict";
import { applySuppressions } from "../src/suppression";
import type { Finding } from "../src/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: "secret.aws-access-key",
    category: "secret",
    severity: "critical",
    title: "AWS access key ID",
    file: "src/config.ts",
    line: 5,
    excerpt: "AKIA****",
    remediation: "Rotate the key.",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// .scannerignore rules
// ---------------------------------------------------------------------------

test("keeps findings when no ignore rules exist", () => {
  const finding = makeFinding();
  const { kept, suppressedCount } = applySuppressions(
    [finding],
    [],
    new Map(),
  );
  assert.equal(kept.length, 1);
  assert.equal(suppressedCount, 0);
});

test("suppresses all findings in a file (no ruleId in rule)", () => {
  const finding = makeFinding({ file: "src/legacy/old.ts", line: 10 });
  const { kept, suppressedCount } = applySuppressions(
    [finding],
    [{ filePath: "src/legacy/old.ts", ruleId: null }],
    new Map(),
  );
  assert.equal(kept.length, 0);
  assert.equal(suppressedCount, 1);
});

test("suppresses specific ruleId in a file", () => {
  const awsFinding = makeFinding({ ruleId: "secret.aws-access-key" });
  const jwtFinding = makeFinding({ ruleId: "secret.jwt-secret" });
  const { kept, suppressedCount } = applySuppressions(
    [awsFinding, jwtFinding],
    [{ filePath: "src/config.ts", ruleId: "secret.aws-access-key" }],
    new Map(),
  );
  assert.equal(kept.length, 1);
  assert.equal(kept[0].ruleId, "secret.jwt-secret");
  assert.equal(suppressedCount, 1);
});

test("wildcard file path suppresses rule across all files", () => {
  const finding1 = makeFinding({ file: "src/a.ts", ruleId: "misconfig.eval" });
  const finding2 = makeFinding({ file: "src/b.ts", ruleId: "misconfig.eval" });
  const kept1 = makeFinding({ file: "src/a.ts", ruleId: "secret.jwt-secret" });
  const { kept, suppressedCount } = applySuppressions(
    [finding1, finding2, kept1],
    [{ filePath: null, ruleId: "misconfig.eval" }],
    new Map(),
  );
  assert.equal(kept.length, 1);
  assert.equal(kept[0].ruleId, "secret.jwt-secret");
  assert.equal(suppressedCount, 2);
});

test("directory prefix match suppresses all files under that path", () => {
  const finding = makeFinding({ file: "src/legacy/deep/file.ts" });
  const { kept, suppressedCount } = applySuppressions(
    [finding],
    [{ filePath: "src/legacy", ruleId: null }],
    new Map(),
  );
  assert.equal(kept.length, 0);
  assert.equal(suppressedCount, 1);
});

test("does not suppress findings in a different file", () => {
  const finding = makeFinding({ file: "src/other.ts" });
  const { kept } = applySuppressions(
    [finding],
    [{ filePath: "src/config.ts", ruleId: null }],
    new Map(),
  );
  assert.equal(kept.length, 1);
});

// ---------------------------------------------------------------------------
// Inline scanner-ignore comments
// ---------------------------------------------------------------------------

test("suppresses finding via trailing same-line comment (all rules)", () => {
  const finding = makeFinding({ line: 3 });
  const lines = [
    "const a = 1;",
    "const b = 2;",
    'const key = "AKIAIOSFODNN7EXAMPLE"; // scanner-ignore',
  ];
  const { kept, suppressedCount } = applySuppressions(
    [finding],
    [],
    new Map([["src/config.ts", lines]]),
  );
  assert.equal(kept.length, 0);
  assert.equal(suppressedCount, 1);
});

test("suppresses finding via trailing same-line comment (specific ruleId)", () => {
  const awsFinding = makeFinding({ ruleId: "secret.aws-access-key", line: 3 });
  const jwtFinding = makeFinding({ ruleId: "secret.jwt-secret", line: 3 });
  const lines = [
    "const a = 1;",
    "const b = 2;",
    'const key = "AKIAIOSFODNN7EXAMPLE"; // scanner-ignore: secret.aws-access-key',
  ];
  const fileLines = new Map([["src/config.ts", lines]]);
  const { kept, suppressedCount } = applySuppressions(
    [awsFinding, jwtFinding],
    [],
    fileLines,
  );
  // Only the AWS key finding is suppressed; jwt is kept
  assert.equal(kept.length, 1);
  assert.equal(kept[0].ruleId, "secret.jwt-secret");
  assert.equal(suppressedCount, 1);
});

test("suppresses finding via preceding-line comment (next-line suppression)", () => {
  const finding = makeFinding({ line: 4 });
  const lines = [
    "const a = 1;",
    "const b = 2;",
    "// scanner-ignore: secret.aws-access-key",
    'const key = "AKIAIOSFODNN7EXAMPLE";',
  ];
  const { kept, suppressedCount } = applySuppressions(
    [finding],
    [],
    new Map([["src/config.ts", lines]]),
  );
  assert.equal(kept.length, 0);
  assert.equal(suppressedCount, 1);
});

test("does not suppress when comment targets a different rule", () => {
  const finding = makeFinding({ ruleId: "secret.aws-access-key", line: 3 });
  const lines = [
    "const a = 1;",
    "const b = 2;",
    'const key = "AKIAIOSFODNN7EXAMPLE"; // scanner-ignore: misconfig.eval',
  ];
  const { kept } = applySuppressions(
    [finding],
    [],
    new Map([["src/config.ts", lines]]),
  );
  assert.equal(kept.length, 1);
});

test("inline comment does not affect findings without a line number", () => {
  const finding = makeFinding({ line: undefined });
  const lines = ["// scanner-ignore", "anything"];
  const { kept } = applySuppressions(
    [finding],
    [],
    new Map([["src/config.ts", lines]]),
  );
  assert.equal(kept.length, 1);
});

test("multiple ruleIds in one inline comment", () => {
  const finding1 = makeFinding({ ruleId: "misconfig.eval", line: 2 });
  const finding2 = makeFinding({ ruleId: "misconfig.new-function", line: 2 });
  const finding3 = makeFinding({ ruleId: "secret.aws-access-key", line: 2 });
  const lines = [
    "// scanner-ignore: misconfig.eval, misconfig.new-function",
    "const bad = eval(x) || new Function(y);",
  ];
  const fileLines = new Map([["src/config.ts", lines]]);
  const { kept, suppressedCount } = applySuppressions(
    [finding1, finding2, finding3],
    [],
    fileLines,
  );
  assert.equal(kept.length, 1);
  assert.equal(kept[0].ruleId, "secret.aws-access-key");
  assert.equal(suppressedCount, 2);
});

// ---------------------------------------------------------------------------
// Combined: .scannerignore + inline
// ---------------------------------------------------------------------------

test("counts suppressions from both mechanisms", () => {
  const fileIgnored = makeFinding({ file: "src/legacy.ts", line: 1 });
  const inlineIgnored = makeFinding({ file: "src/config.ts", line: 2 });
  const kept = makeFinding({ file: "src/config.ts", ruleId: "secret.jwt-secret", line: 3 });

  const lines = [
    "anything",
    'const key = "AKIAIOSFODNN7EXAMPLE"; // scanner-ignore: secret.aws-access-key',
    'const jwt = "supersecret";',
  ];

  const { kept: result, suppressedCount } = applySuppressions(
    [fileIgnored, inlineIgnored, kept],
    [{ filePath: "src/legacy.ts", ruleId: null }],
    new Map([
      ["src/legacy.ts", []],
      ["src/config.ts", lines],
    ]),
  );

  assert.equal(result.length, 1);
  assert.equal(result[0].ruleId, "secret.jwt-secret");
  assert.equal(suppressedCount, 2);
});
