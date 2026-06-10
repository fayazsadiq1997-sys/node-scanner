import type { Finding } from "../types";
import { getTrackedEnvFiles } from "../git";

// ── GitHub Actions checks ─────────────────────────────────────────────────────

const GHA_SHA_RE = /^[0-9a-f]{40}$/;

/**
 * Checks for two GitHub Actions workflow security issues:
 *   1. Unpinned action version tag (e.g. @v4 instead of a full commit SHA)
 *   2. pull_request_target trigger combined with actions/checkout (pwn-request vector)
 *
 * All matching runs against comment-stripped lines: a YAML comment mentioning
 * `pull_request_target` must not trigger a finding, and a `uses:` ref followed
 * by an inline comment (`uses: actions/checkout@v4 # note`) must still be parsed.
 * Excerpts use the original line so reports show real file content.
 */
export function scanGitHubActions(relPath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);
  const codeLines = lines.map((l) => {
    const hash = l.indexOf("#");
    return hash >= 0 ? l.slice(0, hash) : l;
  });

  // ── Unpinned action SHA ───────────────────────────────────────────────────
  for (let i = 0; i < codeLines.length; i++) {
    const m = codeLines[i].match(/^\s*(?:-\s+)?uses:\s+(\S+)\s*$/);
    if (!m) continue;
    // YAML allows the ref to be quoted; strip quotes so the SHA test runs
    // against the ref itself rather than `...@v4"`.
    const ref = m[1].replace(/^['"]|['"]$/g, "");
    if (ref.startsWith("docker://")) continue;
    const atIdx = ref.lastIndexOf("@");
    if (atIdx < 0) continue;
    const pin = ref.slice(atIdx + 1);
    if (!GHA_SHA_RE.test(pin)) {
      findings.push({
        ruleId: "misconfig.gha-unpinned-action",
        category: "misconfig",
        severity: "medium",
        title: "Unpinned GitHub Actions version",
        file: relPath,
        line: i + 1,
        excerpt: lines[i].trim(),
        remediation:
          "Pin actions to a full commit SHA instead of a mutable tag " +
          "(e.g. `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`). " +
          "Tags can be moved to point to different (potentially malicious) code.",
      });
    }
  }

  // ── pwn-request: pull_request_target + checkout ───────────────────────────
  const hasPrTarget = codeLines.some((l) => l.includes("pull_request_target"));
  const hasCheckout = codeLines.some((l) => /uses:\s+['"]?actions\/checkout/.test(l));
  if (hasPrTarget && hasCheckout) {
    const prtIdx = codeLines.findIndex((l) => l.includes("pull_request_target"));
    findings.push({
      ruleId: "misconfig.gha-pwn-request",
      category: "misconfig",
      severity: "high",
      title: "pull_request_target with actions/checkout (pwn-request vector)",
      file: relPath,
      line: prtIdx >= 0 ? prtIdx + 1 : undefined,
      excerpt: prtIdx >= 0 ? lines[prtIdx].trim() : undefined,
      remediation:
        "Combining `pull_request_target` with `actions/checkout` of the PR head " +
        "runs untrusted code with elevated repository permissions. " +
        "Use `pull_request` instead, or if elevated permissions are required, " +
        "build and test in a separate job that does not check out PR code.",
    });
  }

  return findings;
}

// ── Committed .env detection ─────────────────────────────────────────────────

const ENV_FILE_REMEDIATION =
  "Remove the file from git history (`git filter-repo --path <file> --invert-paths`), " +
  "add it to .gitignore, and rotate any secrets it contained.";

/**
 * Flags .env files that are committed (git-tracked) rather than gitignored.
 * A tracked .env file exposes credentials to anyone who can clone the repo.
 */
export async function scanTrackedEnvFiles(root: string): Promise<Finding[]> {
  const files = await getTrackedEnvFiles(root);
  return files.map((file) => ({
    ruleId: "misconfig.committed-env-file",
    category: "misconfig" as const,
    severity: "high" as const,
    title: "Environment file committed to git",
    file,
    remediation: ENV_FILE_REMEDIATION,
  }));
}

// ── Dockerfile checks ────────────────────────────────────────────────────────

const SECRET_KEY_RE =
  /(?:password|passwd|secret|token|api[_-]?key|auth(?:_?key)?|private[_-]?key|credentials?|access[_-]?key|client[_-]?secret)\b/i;

/**
 * Returns true when an ENV value looks like it contains a real credential
 * rather than a variable reference or empty placeholder.
 */
function looksLikeSecretValue(value: string): boolean {
  if (!value) return false;
  if (/^\$/.test(value)) return false; // $VAR or ${VAR}
  if (value === '""' || value === "''") return false;
  return true;
}

/**
 * Checks for three Dockerfile security issues:
 *   1. Unpinned base image tag (FROM image or FROM image:latest)
 *   2. Container runs as root (no non-root USER instruction)
 *   3. Secret value hardcoded in an ENV instruction
 *
 * The root-user check is evaluated per build stage: each FROM resets the
 * tracking, so only the final stage (the one that actually runs in production)
 * decides the finding. A USER in an earlier build stage does not count.
 */
export function scanDockerfile(relPath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);

  let hasNonRootUser = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const lineNum = i + 1;

    // ── FROM: unpinned base image ────────────────────────────────────────────
    // Skip leading --flags (e.g. `FROM --platform=linux/amd64 node:20`) so a
    // flag token is never mistaken for the image name.
    const fromMatch = line.match(/^FROM\s+(?:--\S+\s+)*(\S+)/i);
    if (fromMatch) {
      // New build stage — only the final stage's USER matters at runtime.
      hasNonRootUser = false;
      const image = fromMatch[1];
      // scratch is a special no-op base; digest-pinned images are fine
      if (image.toLowerCase() !== "scratch" && !image.includes("@")) {
        const colonIdx = image.indexOf(":");
        const tag = colonIdx >= 0 ? image.slice(colonIdx + 1) : null;
        if (tag === null || tag === "latest") {
          findings.push({
            ruleId: "misconfig.dockerfile-latest-tag",
            category: "misconfig",
            severity: "low",
            title: "Unpinned base image tag",
            file: relPath,
            line: lineNum,
            excerpt: line,
            remediation:
              "Pin base images to an immutable version tag or digest " +
              "(e.g. `ubuntu:22.04` or `ubuntu@sha256:...`) to prevent " +
              "unexpected changes when the image is rebuilt.",
          });
        }
      }
    }

    // ── USER: track whether a non-root user is set ───────────────────────────
    const userMatch = line.match(/^USER\s+(\S+)/i);
    if (userMatch) {
      // Strip an optional :group suffix ("0:0" runs as root too), and compare
      // UIDs numerically so zero-padded forms ("00", "0000") don't bypass the
      // check. parseInt of a username is NaN, which never equals 0.
      const who = userMatch[1].split(":")[0];
      if (who !== "root" && parseInt(who, 10) !== 0) hasNonRootUser = true;
    }

    // ── ENV: secret hardcoded in instruction ─────────────────────────────────
    if (/^ENV\s/i.test(line)) {
      const envContent = line.slice(4).trim();

      // Detect form: new (KEY=VALUE) vs old (KEY VALUE)
      const firstToken = envContent.split(/\s+/)[0];
      if (firstToken.includes("=")) {
        // New form — may have multiple KEY=VALUE pairs on one line. Each key
        // must sit at the start of the line or after whitespace; without the
        // anchor, a KEY=VALUE substring embedded in a value fires a false
        // positive (e.g. `ENV BUILD_OPTS=--api_key=x`).
        for (const m of envContent.matchAll(/(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=(\S*)/g)) {
          const [, key, value] = m;
          if (SECRET_KEY_RE.test(key) && looksLikeSecretValue(value)) {
            findings.push({
              ruleId: "misconfig.dockerfile-env-secret",
              category: "misconfig",
              severity: "high",
              title: "Potential secret in ENV instruction",
              file: relPath,
              line: lineNum,
              excerpt: `ENV ${key}=***`,
              remediation:
                "Do not store secrets in Dockerfile ENV instructions — they are " +
                "baked into image layers and visible in `docker inspect`. " +
                "Pass secrets at runtime via orchestrator secrets or environment variables.",
            });
          }
        }
      } else {
        // Old form: ENV KEY VALUE (rest of line is the value)
        const spaceIdx = envContent.search(/\s/);
        if (spaceIdx >= 0) {
          const key = envContent.slice(0, spaceIdx);
          const value = envContent.slice(spaceIdx + 1).trim();
          if (SECRET_KEY_RE.test(key) && looksLikeSecretValue(value)) {
            findings.push({
              ruleId: "misconfig.dockerfile-env-secret",
              category: "misconfig",
              severity: "high",
              title: "Potential secret in ENV instruction",
              file: relPath,
              line: lineNum,
              excerpt: `ENV ${key} ***`,
              remediation:
                "Do not store secrets in Dockerfile ENV instructions — they are " +
                "baked into image layers and visible in `docker inspect`. " +
                "Pass secrets at runtime via orchestrator secrets or environment variables.",
            });
          }
        }
      }
    }
  }

  // ── Root user: emit once per file if no non-root USER was found ─────────────
  if (!hasNonRootUser) {
    findings.push({
      ruleId: "misconfig.dockerfile-root-user",
      category: "misconfig",
      severity: "medium",
      title: "Container runs as root",
      file: relPath,
      remediation:
        "Add a USER instruction after package installation to run the container " +
        "as a non-root user (e.g. `RUN useradd -u 1001 appuser && USER appuser`).",
    });
  }

  return findings;
}
