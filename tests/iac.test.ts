import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, writeFile, rm, mkdir } from "node:fs/promises";
import os from "node:os";
import { scanDockerfile, scanGitHubActions } from "../src/checks/iac";
import path from "node:path";
import { scan } from "../src/scanner";

function git(cwd: string, ...args: string[]): void {
  execFileSync("git", args, { cwd, stdio: "ignore" });
}

async function makeRepo(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "scanner-iac-"));
  git(dir, "init");
  git(dir, "config", "user.email", "test@example.com");
  git(dir, "config", "user.name", "Test");
  git(dir, "commit", "--allow-empty", "-m", "root");
  return dir;
}

test("committed .env file is flagged", async () => {
  const dir = await makeRepo();
  try {
    await writeFile(path.join(dir, ".env"), "DATABASE_URL=postgres://localhost/prod\n");
    git(dir, "add", ".env");
    git(dir, "commit", "-m", "add env");

    const result = await scan(dir, { skipDependencies: true });
    const findings = result.findings.filter((f) => f.ruleId === "misconfig.committed-env-file");

    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, ".env");
    assert.equal(findings[0].severity, "high");
    assert.equal(findings[0].category, "misconfig");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("committed .env.local and .env.production are both flagged", async () => {
  const dir = await makeRepo();
  try {
    await writeFile(path.join(dir, ".env.local"), "SECRET=abc\n");
    await writeFile(path.join(dir, ".env.production"), "SECRET=xyz\n");
    git(dir, "add", ".env.local", ".env.production");
    git(dir, "commit", "-m", "add env variants");

    const result = await scan(dir, { skipDependencies: true });
    const files = result.findings
      .filter((f) => f.ruleId === "misconfig.committed-env-file")
      .map((f) => f.file)
      .sort();

    assert.deepEqual(files, [".env.local", ".env.production"]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("gitignored .env file is not flagged", async () => {
  const dir = await makeRepo();
  try {
    await writeFile(path.join(dir, ".gitignore"), ".env\n");
    await writeFile(path.join(dir, ".env"), "SECRET=abc\n");
    git(dir, "add", ".gitignore");
    git(dir, "commit", "-m", "gitignore");
    // .env is present on disk but not tracked — should produce no finding.

    const result = await scan(dir, { skipDependencies: true });
    const findings = result.findings.filter((f) => f.ruleId === "misconfig.committed-env-file");

    assert.equal(findings.length, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("non-git directory produces no committed-env-file finding", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "scanner-iac-nogit-"));
  try {
    await writeFile(path.join(dir, ".env"), "SECRET=abc\n");

    const result = await scan(dir, { skipDependencies: true });
    const findings = result.findings.filter((f) => f.ruleId === "misconfig.committed-env-file");

    assert.equal(findings.length, 0, "graceful no-op outside a git repo");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ── scanDockerfile ────────────────────────────────────────────────────────────

test("dockerfile: flags FROM with no tag", () => {
  const findings = scanDockerfile("Dockerfile", "FROM ubuntu\nRUN apt-get update\nUSER 1001\n");
  const f = findings.filter((x) => x.ruleId === "misconfig.dockerfile-latest-tag");
  assert.equal(f.length, 1);
  assert.equal(f[0].line, 1);
  assert.match(f[0].excerpt ?? "", /FROM ubuntu/);
});

test("dockerfile: flags FROM with :latest tag", () => {
  const findings = scanDockerfile("Dockerfile", "FROM node:latest\nUSER 1001\n");
  const f = findings.filter((x) => x.ruleId === "misconfig.dockerfile-latest-tag");
  assert.equal(f.length, 1);
});

test("dockerfile: does not flag FROM with a version tag", () => {
  const findings = scanDockerfile("Dockerfile", "FROM node:20.11-alpine\nUSER 1001\n");
  const f = findings.filter((x) => x.ruleId === "misconfig.dockerfile-latest-tag");
  assert.equal(f.length, 0);
});

test("dockerfile: does not flag FROM pinned by digest", () => {
  const findings = scanDockerfile(
    "Dockerfile",
    "FROM ubuntu@sha256:abc123def456\nUSER 1001\n",
  );
  const f = findings.filter((x) => x.ruleId === "misconfig.dockerfile-latest-tag");
  assert.equal(f.length, 0);
});

test("dockerfile: does not flag FROM scratch", () => {
  const findings = scanDockerfile("Dockerfile", "FROM scratch\nUSER 1001\n");
  const f = findings.filter((x) => x.ruleId === "misconfig.dockerfile-latest-tag");
  assert.equal(f.length, 0);
});

test("dockerfile: flags missing USER instruction", () => {
  const findings = scanDockerfile("Dockerfile", "FROM node:20\nRUN apt-get update\n");
  const f = findings.filter((x) => x.ruleId === "misconfig.dockerfile-root-user");
  assert.equal(f.length, 1);
});

test("dockerfile: flags explicit USER root", () => {
  const findings = scanDockerfile("Dockerfile", "FROM node:20\nUSER root\n");
  const f = findings.filter((x) => x.ruleId === "misconfig.dockerfile-root-user");
  assert.equal(f.length, 1);
});

test("dockerfile: does not flag when non-root USER is set", () => {
  const findings = scanDockerfile("Dockerfile", "FROM node:20\nUSER 1001\n");
  const f = findings.filter((x) => x.ruleId === "misconfig.dockerfile-root-user");
  assert.equal(f.length, 0);
});

test("dockerfile: flags ENV with secret key and real value (new form)", () => {
  const findings = scanDockerfile(
    "Dockerfile",
    "FROM node:20\nUSER 1001\nENV API_KEY=s3cr3t\n",
  );
  const f = findings.filter((x) => x.ruleId === "misconfig.dockerfile-env-secret");
  assert.equal(f.length, 1);
  assert.equal(f[0].line, 3);
  assert.match(f[0].excerpt ?? "", /\*\*\*/);
});

test("dockerfile: flags ENV with secret key and real value (old form)", () => {
  const findings = scanDockerfile(
    "Dockerfile",
    "FROM node:20\nUSER 1001\nENV SECRET_TOKEN mysecretvalue\n",
  );
  const f = findings.filter((x) => x.ruleId === "misconfig.dockerfile-env-secret");
  assert.equal(f.length, 1);
});

test("dockerfile: does not flag ENV with variable reference value", () => {
  const findings = scanDockerfile(
    "Dockerfile",
    "FROM node:20\nUSER 1001\nENV API_KEY=$API_KEY\n",
  );
  const f = findings.filter((x) => x.ruleId === "misconfig.dockerfile-env-secret");
  assert.equal(f.length, 0);
});

test("dockerfile: does not flag ENV with non-secret key name", () => {
  const findings = scanDockerfile(
    "Dockerfile",
    "FROM node:20\nUSER 1001\nENV PORT=3000\n",
  );
  const f = findings.filter((x) => x.ruleId === "misconfig.dockerfile-env-secret");
  assert.equal(f.length, 0);
});

// ── scanGitHubActions ─────────────────────────────────────────────────────────

const GHA_PATH = ".github/workflows/ci.yml";

test("gha: flags action pinned to a tag", () => {
  const content = "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n";
  const f = scanGitHubActions(GHA_PATH, content).filter((x) => x.ruleId === "misconfig.gha-unpinned-action");
  assert.equal(f.length, 1);
  assert.match(f[0].excerpt ?? "", /actions\/checkout@v4/);
});

test("gha: flags action pinned to a branch name", () => {
  const content = "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@main\n";
  const f = scanGitHubActions(GHA_PATH, content).filter((x) => x.ruleId === "misconfig.gha-unpinned-action");
  assert.equal(f.length, 1);
});

test("gha: does not flag action pinned to a full SHA", () => {
  const content = "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n";
  const f = scanGitHubActions(GHA_PATH, content).filter((x) => x.ruleId === "misconfig.gha-unpinned-action");
  assert.equal(f.length, 0);
});

test("gha: flags multiple unpinned actions in one workflow", () => {
  const content = [
    "on: [push]",
    "jobs:",
    "  build:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "      - uses: actions/setup-node@v4",
    "      - uses: github/codeql-action/upload-sarif@v3",
  ].join("\n");
  const f = scanGitHubActions(GHA_PATH, content).filter((x) => x.ruleId === "misconfig.gha-unpinned-action");
  assert.equal(f.length, 3);
});

test("gha: flags pull_request_target combined with actions/checkout", () => {
  const content = [
    "on:",
    "  pull_request_target:",
    "    types: [opened]",
    "jobs:",
    "  build:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
  ].join("\n");
  const f = scanGitHubActions(GHA_PATH, content).filter((x) => x.ruleId === "misconfig.gha-pwn-request");
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, "high");
});

test("gha: does not flag pull_request (non-target) with checkout", () => {
  const content = [
    "on:",
    "  pull_request:",
    "    branches: [main]",
    "jobs:",
    "  build:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
  ].join("\n");
  const f = scanGitHubActions(GHA_PATH, content).filter((x) => x.ruleId === "misconfig.gha-pwn-request");
  assert.equal(f.length, 0);
});

test("gha: does not flag pull_request_target without checkout", () => {
  const content = [
    "on:",
    "  pull_request_target:",
    "    types: [labeled]",
    "jobs:",
    "  triage:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - name: Label",
    "        run: echo labeling",
  ].join("\n");
  const f = scanGitHubActions(GHA_PATH, content).filter((x) => x.ruleId === "misconfig.gha-pwn-request");
  assert.equal(f.length, 0);
});
