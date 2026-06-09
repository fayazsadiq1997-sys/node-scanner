import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import type { Finding, ScanResult } from "./types";
import { scanSecrets } from "./checks/secrets";
import { scanMisconfigs } from "./checks/misconfigs";
import { scanDependencies } from "./checks/dependencies";
import { scanTrackedEnvFiles, scanDockerfile, scanGitHubActions } from "./checks/iac";
import { loadIgnoreFile, applySuppressions } from "./suppression";
import { getChangedFiles } from "./git";

/** Directories never worth scanning — build output, tooling, etc. */
const IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
  ".cache",
]);

/**
 * Non-production directories excluded by default to reduce false positives.
 * Findings in test/example code are almost always false positives — hardcoded
 * credentials in fixtures, eval() in test payloads, http:// in demo scripts.
 * Users can opt back in with --include-test-dirs.
 */
const NON_PRODUCTION_DIRS = new Set([
  "test",
  "tests",
  "__tests__",
  "spec",
  "specs",
  "examples",
  "example",
  "demo",
  "demos",
  "sample",
  "samples",
  "fixtures",
  "__mocks__",
  "mocks",
  "stubs",
  "e2e",
]);

/** File extensions we read for content-based checks. */
const SCANNABLE_EXT = new Set([
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
  ".json",
  ".env",
  ".yml",
  ".yaml",
  ".sh",
]);

/** Skip files larger than this to avoid choking on bundles/minified blobs. */
const MAX_FILE_BYTES = 1_000_000;

/**
 * Manifest files that, when changed, justify re-running the dependency check
 * in --diff mode. Matched by basename so a manifest in any changed directory
 * triggers it.
 */
const MANIFEST_FILES = new Set([
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
]);

export interface ScanOptions {
  /** Skip the network-dependent dependency check. */
  skipDependencies?: boolean;
  /** Include test/example/fixture directories (excluded by default). */
  includeTestDirs?: boolean;
  /** Additional directory names to exclude (basename match). */
  excludeDirs?: string[];
  /**
   * Disable suppression: ignore .scannerignore and inline scanner-ignore comments.
   * Useful for auditing what a suppression file is hiding.
   */
  noIgnore?: boolean;
  /**
   * Restrict the scan to files changed in git. `base` is the ref to diff
   * against (e.g. "main", "origin/main"); when omitted, uncommitted
   * working-tree changes (plus untracked files) are scanned. Presence of this
   * object enables diff mode.
   */
  diff?: { base?: string };
}

/**
 * Recursively yields absolute file paths under `dir`, skipping any directory
 * whose basename is in `skipDirs`. Silently skips unreadable directories so a
 * single permission error does not abort the entire scan.
 */
async function* walk(
  dir: string,
  opts: { skipDirs: Set<string> },
): AsyncGenerator<string> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (opts.skipDirs.has(entry.name)) continue;
      yield* walk(full, opts);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

/**
 * Main entry point. Walks the project tree, runs all enabled checks, applies
 * suppressions, and returns a complete ScanResult. Callers should catch top-level
 * errors; individual check failures (network, parse) are swallowed internally.
 */
export async function scan(
  root: string,
  options: ScanOptions = {},
): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const absRoot = path.resolve(root);
  const findings: Finding[] = [];
  let filesScanned = 0;

  // In --diff mode, resolve the set of changed files once up front. A null set
  // means diff mode is off and every walked file is eligible.
  const changedFiles = options.diff
    ? await getChangedFiles(absRoot, options.diff.base)
    : null;

  // Load .scannerignore once up front (empty if file absent or noIgnore is set).
  const ignoreRules = options.noIgnore ? [] : await loadIgnoreFile(absRoot);

  // Track each file's lines for inline scanner-ignore comment matching.
  const fileLines = new Map<string, string[]>();

  const skipDirs = new Set([
    ...IGNORED_DIRS,
    ...(options.includeTestDirs ? [] : NON_PRODUCTION_DIRS),
    ...(options.excludeDirs ?? []),
  ]);

  for await (const file of walk(absRoot, { skipDirs })) {
    const ext = path.extname(file).toLowerCase();
    const base = path.basename(file);
    const dockerfile = base === "Dockerfile" || base.startsWith("Dockerfile.") || ext === ".dockerfile";
    const relPathEarly = path.relative(absRoot, file).split(path.sep).join("/");
    const ghaWorkflow =
      relPathEarly.startsWith(".github/workflows/") &&
      (ext === ".yml" || ext === ".yaml");
    // Read source/config files, dotenv-style files, Dockerfiles, and GHA workflows.
    if (!SCANNABLE_EXT.has(ext) && !base.startsWith(".env") && !dockerfile) continue;

    try {
      const info = await stat(file);
      if (info.size > MAX_FILE_BYTES) continue;
    } catch {
      continue;
    }

    let content: string;
    try {
      content = await readFile(file, "utf8");
    } catch {
      continue;
    }

    const relPath = relPathEarly;

    // In diff mode, skip files that haven't changed.
    if (changedFiles && !changedFiles.has(relPath)) continue;

    // Store lines for inline suppression checks.
    if (!options.noIgnore) {
      fileLines.set(relPath, content.split(/\r?\n/));
    }

    findings.push(...scanSecrets(relPath, content));
    findings.push(...scanMisconfigs(relPath, content));
    if (dockerfile) findings.push(...scanDockerfile(relPath, content));
    if (ghaWorkflow) findings.push(...scanGitHubActions(relPath, content));
    filesScanned++;
  }

  // In diff mode, only re-run the dependency check when a manifest/lockfile is
  // among the changed files — otherwise the dependency tree is unchanged.
  const manifestChanged =
    !changedFiles ||
    [...changedFiles].some((f) => MANIFEST_FILES.has(f.split("/").pop() ?? ""));

  if (!options.skipDependencies && manifestChanged) {
    try {
      findings.push(...(await scanDependencies(absRoot)));
    } catch {
      // Network failure shouldn't abort the whole scan.
    }
  }

  // IaC / cloud misconfig checks — repo-level, run unconditionally.
  findings.push(...(await scanTrackedEnvFiles(absRoot)));

  // Apply .scannerignore and inline scanner-ignore suppressions.
  const { kept, suppressedFindings } = options.noIgnore
    ? { kept: findings, suppressedFindings: [] }
    : applySuppressions(findings, ignoreRules, fileLines);

  return {
    root: absRoot,
    startedAt,
    finishedAt: new Date().toISOString(),
    filesScanned,
    findings: kept,
    suppressedFindings,
    suppressedCount: suppressedFindings.length,
  };
}
