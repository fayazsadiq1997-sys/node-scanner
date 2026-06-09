// Tests for the dependency check's pure parts: CVSS v3 base-score computation
// and lockfile resolution. No network — queryOsv/scanDependencies are not
// exercised here (OSV.dev calls are skipped throughout the suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { cvssBaseScoreV3, resolveDependencies } from "../src/checks/dependencies";

// ── cvssBaseScoreV3 ───────────────────────────────────────────────────────────

test("cvss: computes 9.8 for a classic network-RCE vector", () => {
  // Scores cross-checked against the FIRST.org CVSS v3.1 calculator.
  assert.equal(cvssBaseScoreV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
});

test("cvss: computes 6.1 for a typical reflected-XSS vector (changed scope)", () => {
  assert.equal(cvssBaseScoreV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
});

test("cvss: computes 5.5 for a local medium vector", () => {
  assert.equal(cvssBaseScoreV3("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"), 5.5);
});

test("cvss: zero-impact vector scores 0", () => {
  assert.equal(cvssBaseScoreV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0);
});

test("cvss: accepts CVSS 3.0 vectors", () => {
  assert.equal(cvssBaseScoreV3("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
});

test("cvss: returns null for v2/v4 vectors and garbage", () => {
  assert.equal(cvssBaseScoreV3("AV:N/AC:L/Au:N/C:P/I:P/A:P"), null); // v2
  assert.equal(cvssBaseScoreV3("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"), null);
  assert.equal(cvssBaseScoreV3("CVSS:3.1/AV:N/AC:L"), null); // missing metrics
  assert.equal(cvssBaseScoreV3("7.5"), null); // plain number, not a vector
});

// ── resolveDependencies ───────────────────────────────────────────────────────

async function makeProject(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "scanner-deps-"));
  for (const [name, content] of Object.entries(files)) {
    await writeFile(path.join(dir, name), content);
  }
  return dir;
}

test("resolves transitive dependencies from the lockfile, not just declared ones", async () => {
  const dir = await makeProject({
    "package.json": JSON.stringify({
      name: "fixture",
      dependencies: { express: "^4.17.0" },
    }),
    "package-lock.json": JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "fixture" },
        "node_modules/express": { version: "4.17.1" },
        // Transitive dep of express — never declared in package.json.
        "node_modules/qs": { version: "6.7.0" },
        // Nested copy at a different version must be kept as a separate entry.
        "node_modules/express/node_modules/qs": { version: "6.5.2" },
        // Scoped transitive dep.
        "node_modules/@types/node": { version: "18.0.0" },
      },
    }),
  });
  try {
    const deps = await resolveDependencies(dir);
    const ids = deps.map((d) => `${d.name}@${d.version}`).sort();
    assert.deepEqual(ids, [
      "@types/node@18.0.0",
      "express@4.17.1",
      "qs@6.5.2",
      "qs@6.7.0",
    ]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("deduplicates identical name@version pairs across nested paths", async () => {
  const dir = await makeProject({
    "package-lock.json": JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/ms": { version: "2.1.3" },
        "node_modules/debug/node_modules/ms": { version: "2.1.3" },
      },
    }),
  });
  try {
    const deps = await resolveDependencies(dir);
    assert.deepEqual(deps, [{ name: "ms", version: "2.1.3" }]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("falls back to declared dependencies when there is no lockfile", async () => {
  const dir = await makeProject({
    "package.json": JSON.stringify({
      name: "fixture",
      dependencies: { lodash: "^4.17.20" },
      devDependencies: { typescript: "~5.0.0" },
    }),
  });
  try {
    const deps = await resolveDependencies(dir);
    const ids = deps.map((d) => `${d.name}@${d.version}`).sort();
    assert.deepEqual(ids, ["lodash@4.17.20", "typescript@5.0.0"]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
