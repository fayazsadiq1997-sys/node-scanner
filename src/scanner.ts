import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import type { Finding, ScanResult } from "./types";
import { scanSecrets } from "./checks/secrets";
import { scanMisconfigs } from "./checks/misconfigs";
import { scanDependencies } from "./checks/dependencies";

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

export interface ScanOptions {
  /** Skip the network-dependent dependency check. */
  skipDependencies?: boolean;
  /** Include test/example/fixture directories (excluded by default). */
  includeTestDirs?: boolean;
  /** Additional directory names to exclude (basename match). */
  excludeDirs?: string[];
}

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

export async function scan(
  root: string,
  options: ScanOptions = {},
): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const absRoot = path.resolve(root);
  const findings: Finding[] = [];
  let filesScanned = 0;

  const skipDirs = new Set([
    ...IGNORED_DIRS,
    ...(options.includeTestDirs ? [] : NON_PRODUCTION_DIRS),
    ...(options.excludeDirs ?? []),
  ]);

  for await (const file of walk(absRoot, { skipDirs })) {
    const ext = path.extname(file).toLowerCase();
    const base = path.basename(file);
    // Read source/config files and any dotenv-style file.
    if (!SCANNABLE_EXT.has(ext) && !base.startsWith(".env")) continue;

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

    const relPath = path.relative(absRoot, file).split(path.sep).join("/");
    findings.push(...scanSecrets(relPath, content));
    findings.push(...scanMisconfigs(relPath, content));
    filesScanned++;
  }

  if (!options.skipDependencies) {
    try {
      findings.push(...(await scanDependencies(absRoot)));
    } catch {
      // Network failure shouldn't abort the whole scan.
    }
  }

  return {
    root: absRoot,
    startedAt,
    finishedAt: new Date().toISOString(),
    filesScanned,
    findings,
  };
}
