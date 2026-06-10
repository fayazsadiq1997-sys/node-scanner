import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { scan } from "../src/scanner";
import { scanMisconfigs } from "../src/checks/misconfigs";
import { scanSecrets } from "../src/checks/secrets";

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

test("detects exec bound via require-then-member form (DVNA pattern)", () => {
  // const exec = require('child_process').exec — the init is a MemberExpression over the
  // require() call, not a CallExpression. Regression for the DVNA command-injection miss.
  const src = [
    "const exec = require('child_process').exec;",
    "exec('ping -c 2 ' + req.body.address, (err, stdout) => {});",
  ].join("\n");
  const ruleIds = scanMisconfigs("app.js", src).map((f) => f.ruleId);
  assert.ok(
    ruleIds.includes("misconfig.child-process-exec"),
    "should flag exec() bound via require('child_process').exec",
  );
});

test("detects bracket-notation NODE_TLS_REJECT_UNAUTHORIZED assignment", () => {
  // process.env["..."] is a computed Literal property, not an Identifier —
  // regression for the AST check only handling the dot form.
  const src = 'process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";\n';
  const ruleIds = scanMisconfigs("app.js", src).map((f) => f.ruleId);
  assert.ok(
    ruleIds.includes("misconfig.tls-reject-disabled"),
    "bracket-notation env assignment should be flagged",
  );
});

test("two secrets on one line yield two findings", () => {
  const line = 'const a = "AKIAABCDEFGHIJKLMNOP", b = "AKIAQRSTUVWXYZABCDEF";\n';
  const findings = scanSecrets("config.js", line).filter(
    (f) => f.ruleId === "secret.aws-access-key",
  );
  assert.equal(findings.length, 2, "every occurrence on a line must be reported");
});

test("redacts secret values in output", async () => {
  const result = await scan(FIXTURE, { skipDependencies: true });
  const awsFinding = result.findings.find(
    (f) => f.ruleId === "secret.aws-access-key",
  );
  assert.ok(awsFinding);
  assert.ok(awsFinding.excerpt?.includes("*"), "excerpt should be redacted");
});

test("scanning a file path throws instead of reporting a clean scan", async () => {
  // A file root used to walk nothing and exit 0 with filesScanned: 0 — a
  // false all-clear in CI.
  await assert.rejects(
    scan(path.join(FIXTURE, "server.js"), { skipDependencies: true }),
    /not a directory/,
  );
});

test("scanning a nonexistent path throws", async () => {
  await assert.rejects(
    scan(path.join(FIXTURE, "no-such-dir"), { skipDependencies: true }),
    /does not exist/,
  );
});
