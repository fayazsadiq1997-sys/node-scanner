import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/**
 * Runs a git command in `root` and returns stdout. Throws a descriptive Error
 * for the two most common failure modes: git not installed and not-a-repo.
 */
async function git(root: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync("git", ["-C", root, ...args], {
      maxBuffer: 10 * 1024 * 1024,
    });
    return stdout;
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") {
      throw new Error("git is not installed or not on PATH; --diff requires git.");
    }
    const msg = error.message ?? String(err);
    if (/not a git repository/i.test(msg)) {
      throw new Error(`'${root}' is not inside a git repository; --diff requires git.`);
    }
    throw new Error(`git failed: ${msg.trim()}`);
  }
}

/**
 * Example/template env files are committed deliberately (with placeholder
 * values) as documentation — flagging them is pure noise.
 */
const ENV_EXAMPLE_RE = /\.(example|sample|template|dist)$/i;

/**
 * Returns forward-slash paths (relative to `root`) of every `.env`-style file
 * that git tracks — i.e. is committed, not just present on disk. Excludes
 * example/template variants (.env.example etc.) and .envrc, which is a direnv
 * script rather than a dotenv credentials file.
 * Returns an empty array if `root` is not a git repo or git is unavailable.
 */
export async function getTrackedEnvFiles(root: string): Promise<string[]> {
  let output: string;
  try {
    output = await git(root, ["ls-files"]);
  } catch (err) {
    const msg = (err as Error).message ?? String(err);
    // Unexpected failure (e.g. maxBuffer exceeded, permission error on .git/).
    if (!/not installed|not on PATH|not inside a git repository/i.test(msg)) {
      console.error(`[node-sec-scanner] committed-env check skipped: ${msg}`);
    }
    return [];
  }
  return output
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => {
      if (!l) return false;
      const base = l.split("/").pop() ?? "";
      if (!base.startsWith(".env")) return false;
      if (base === ".envrc") return false;
      return !ENV_EXAMPLE_RE.test(base);
    });
}

/**
 * Returns the set of files that have changed, as forward-slash paths relative
 * to `root`, suitable for matching against the scanner's relPath.
 *
 * Without a ref: uncommitted working-tree changes (staged + unstaged tracked
 * modifications vs HEAD, plus untracked files). With a ref (e.g. "main" or
 * "origin/main"): every file that differs between that ref and the current
 * working tree, plus untracked files.
 *
 * `--relative` both restricts output to the `root` subtree and emits paths
 * relative to it, so a scan rooted in a monorepo subdirectory stays scoped.
 */
export async function getChangedFiles(
  root: string,
  ref?: string,
): Promise<Set<string>> {
  const diffArgs = ["diff", "--name-only", "--relative"];
  if (ref) diffArgs.push(ref);
  else diffArgs.push("HEAD");

  const [diffOut, untrackedOut] = await Promise.all([
    git(root, diffArgs),
    git(root, ["ls-files", "--others", "--exclude-standard"]),
  ]);

  const files = new Set<string>();
  for (const line of `${diffOut}\n${untrackedOut}`.split("\n")) {
    const trimmed = line.trim();
    // git already emits forward slashes, even on Windows.
    if (trimmed) files.add(trimmed);
  }
  return files;
}
