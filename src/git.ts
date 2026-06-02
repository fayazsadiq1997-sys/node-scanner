import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

async function git(root: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync("git", ["-C", root, ...args], {
      maxBuffer: 10 * 1024 * 1024,
    });
    return stdout;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (/ENOENT/.test(msg)) {
      throw new Error("git is not installed or not on PATH; --diff requires git.");
    }
    if (/not a git repository/i.test(msg)) {
      throw new Error(`'${root}' is not inside a git repository; --diff requires git.`);
    }
    throw new Error(`git failed: ${msg.trim()}`);
  }
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
