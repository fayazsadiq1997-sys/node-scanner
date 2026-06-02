import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { scan } from "../src/scanner";

const FIXTURE = path.join(__dirname, "fixtures", "vulnerable-app");

test("detects planted secrets in the fixture", async () => {
  const result = await scan(FIXTURE, { skipDependencies: true });
  const ruleIds = result.findings.map((f) => f.ruleId);

  assert.ok(ruleIds.includes("secret.aws-access-key"), "should find AWS key");
  assert.ok(ruleIds.includes("secret.jwt-secret"), "should find JWT secret");
  assert.ok(ruleIds.includes("secret.hardcoded-password"), "should find password");
});

test("detects planted misconfigurations in the fixture", async () => {
  const result = await scan(FIXTURE, { skipDependencies: true });
  const ruleIds = result.findings.map((f) => f.ruleId);

  assert.ok(ruleIds.includes("misconfig.eval"), "should find eval()");
  assert.ok(
    ruleIds.includes("misconfig.child-process-exec"),
    "should find command injection",
  );
  assert.ok(
    ruleIds.includes("misconfig.tls-reject-disabled"),
    "should find disabled TLS verification",
  );
});

test("redacts secret values in output", async () => {
  const result = await scan(FIXTURE, { skipDependencies: true });
  const awsFinding = result.findings.find(
    (f) => f.ruleId === "secret.aws-access-key",
  );
  assert.ok(awsFinding);
  assert.ok(awsFinding.excerpt?.includes("*"), "excerpt should be redacted");
});
