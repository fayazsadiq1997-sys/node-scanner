import type { Finding } from "../types";
import { getTrackedEnvFiles } from "../git";

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
 */
export function scanDockerfile(relPath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);

  let hasNonRootUser = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const lineNum = i + 1;

    // ── FROM: unpinned base image ────────────────────────────────────────────
    const fromMatch = line.match(/^FROM\s+(\S+)/i);
    if (fromMatch) {
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
      const who = userMatch[1];
      if (who !== "root" && who !== "0") hasNonRootUser = true;
    }

    // ── ENV: secret hardcoded in instruction ─────────────────────────────────
    if (/^ENV\s/i.test(line)) {
      const envContent = line.slice(4).trim();

      // Detect form: new (KEY=VALUE) vs old (KEY VALUE)
      const firstToken = envContent.split(/\s+/)[0];
      if (firstToken.includes("=")) {
        // New form — may have multiple KEY=VALUE pairs on one line
        for (const m of envContent.matchAll(/([A-Za-z_][A-Za-z0-9_]*)=(\S*)/g)) {
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
