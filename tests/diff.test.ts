import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, writeFile, rm, mkdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../src/scanner";

/** A secret that the secrets check reliably flags. */
const AWS_KEY = 'const k = "AKIAIOSFODNN7EXAMPLE";\n';

function git(cwd: string, ...args: string[]): void {
  execFileSync("git", args, { cwd, stdio: "ignore" });
}

async function makeRepo(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "scanner-diff-"));
  git(dir, "init");
  git(dir, "config", "user.email", "test@example.com");
  git(dir, "config", "user.name", "Test");
  git(dir, "commit", "--allow-empty", "-m", "root");
  return dir;
}

test("--diff scans only changed files, skipping committed clean ones", async () => {
  const dir = await makeRepo();
  try {
    // Baseline: a clean tracked file with no findings.
    await writeFile(path.join(dir, "old.js"), "const ok = 1;\n");
    git(dir, "add", "-A");
    git(dir, "commit", "-m", "baseline");

    // An unrelated committed file that contains a secret but did NOT change.
    await writeFile(path.join(dir, "committed-secret.js"), AWS_KEY);
    git(dir, "add", "-A");
    git(dir, "commit", "-m", "add secret");

    // Now an uncommitted change introduces a new secret file.
    await writeFile(path.join(dir, "new.js"), AWS_KEY);

    const result = await scan(dir, { skipDependencies: true, diff: {} });

    const files = result.findings.map((f) => f.file);
    assert.ok(files.includes("new.js"), "should scan the uncommitted changed file");
    assert.ok(
      !files.includes("committed-secret.js"),
      "should NOT scan an unchanged committed file",
    );
    assert.equal(result.filesScanned, 1, "only the changed file is scanned");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("--diff <ref> includes files changed since the ref", async () => {
  const dir = await makeRepo();
  try {
    await writeFile(path.join(dir, "old.js"), "const ok = 1;\n");
    git(dir, "add", "-A");
    git(dir, "commit", "-m", "baseline");

    // Commit a secret on top of the baseline; diff vs the baseline commit
    // should surface it even though it is fully committed.
    const base = execFileSync("git", ["rev-parse", "HEAD"], { cwd: dir })
      .toString()
      .trim();
    await writeFile(path.join(dir, "feature.js"), AWS_KEY);
    git(dir, "add", "-A");
    git(dir, "commit", "-m", "feature");

    const result = await scan(dir, { skipDependencies: true, diff: { base } });
    const files = result.findings.map((f) => f.file);
    assert.ok(files.includes("feature.js"), "committed change vs ref is scanned");
    assert.ok(!files.includes("old.js"), "unchanged baseline file is skipped");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("--diff skips the committed-env check when no .env file changed", async () => {
  const dir = await makeRepo();
  try {
    // A committed .env exists from before — unrelated to the current diff.
    await writeFile(path.join(dir, ".env"), "SECRET=abc\n");
    git(dir, "add", "-A");
    git(dir, "commit", "-m", "baseline with env");

    // Change only a source file.
    await writeFile(path.join(dir, "app.js"), "const ok = 1;\n");

    const result = await scan(dir, { skipDependencies: true, diff: {} });
    assert.ok(
      result.findings.every((f) => f.ruleId !== "misconfig.committed-env-file"),
      "pre-existing committed .env must not leak into an unrelated diff",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("--diff runs the committed-env check when a .env file changed", async () => {
  const dir = await makeRepo();
  try {
    // Commit a .env then modify it — the change puts .env in the diff set.
    await writeFile(path.join(dir, ".env"), "SECRET=abc\n");
    git(dir, "add", "-A");
    git(dir, "commit", "-m", "add env");
    await writeFile(path.join(dir, ".env"), "SECRET=xyz\n");

    const result = await scan(dir, { skipDependencies: true, diff: {} });
    assert.ok(
      result.findings.some((f) => f.ruleId === "misconfig.committed-env-file"),
      "a changed tracked .env must be reported in diff mode",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("--diff skips the dependency check when no manifest changed", async () => {
  const dir = await makeRepo();
  try {
    // A package.json with a known-vulnerable dependency exists but is committed
    // and unchanged, so diff mode must not query it.
    await writeFile(
      path.join(dir, "package.json"),
      JSON.stringify({ dependencies: { lodash: "4.17.4" } }),
    );
    git(dir, "add", "-A");
    git(dir, "commit", "-m", "manifest");

    // Change only a source file.
    await writeFile(path.join(dir, "app.js"), "const ok = 1;\n");

    const result = await scan(dir, { diff: {} });
    assert.ok(
      result.findings.every((f) => f.category !== "dependency"),
      "no dependency findings when the manifest did not change",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
