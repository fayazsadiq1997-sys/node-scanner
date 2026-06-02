import type { Finding } from "../types";

/**
 * Regex-based secret detection.
 *
 * This is intentionally rule-driven so new patterns can be added in one place.
 * Regex is fast and dependency-free but cannot understand scope, so each rule
 * is kept specific to limit false positives. A later iteration can layer
 * entropy analysis on top to catch unknown key formats.
 */

interface SecretRule {
  ruleId: string;
  title: string;
  severity: Finding["severity"];
  regex: RegExp;
  remediation: string;
}

const RULES: SecretRule[] = [
  {
    ruleId: "secret.aws-access-key",
    title: "AWS access key ID",
    severity: "critical",
    regex: /\bAKIA[0-9A-Z]{16}\b/,
    remediation:
      "Rotate the key immediately in AWS IAM and load credentials from environment variables or the AWS SDK credential chain.",
  },
  {
    ruleId: "secret.private-key",
    title: "Private key material",
    severity: "critical",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    remediation:
      "Remove the key from source control, rotate it, and store it in a secrets manager (AWS Secrets Manager, Vault).",
  },
  {
    ruleId: "secret.generic-api-key",
    title: "Generic API key assignment",
    severity: "high",
    regex: /\bapi[_-]?key\b\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/i,
    remediation:
      "Move the key to an environment variable and reference it via process.env.",
  },
  {
    ruleId: "secret.jwt-secret",
    title: "Hardcoded JWT secret",
    severity: "high",
    regex: /\bjwt[_-]?secret\b\s*[:=]\s*['"][^'"]{8,}['"]/i,
    remediation:
      "Store the JWT signing secret in an environment variable; never commit it.",
  },
  {
    ruleId: "secret.hardcoded-password",
    title: "Hardcoded password assignment",
    severity: "medium",
    regex: /\bpassword\b\s*[:=]\s*['"][^'"]{6,}['"]/i,
    remediation:
      "Do not hardcode passwords. Inject them via environment variables or a secrets manager.",
  },
  {
    ruleId: "secret.bearer-token",
    title: "Hardcoded bearer token",
    severity: "high",
    regex: /\bBearer\s+[A-Za-z0-9_\-\.]{20,}/,
    remediation:
      "Remove the token from source and supply it at runtime from secure storage.",
  },
];

/** Redact the middle of a matched secret so the report doesn't leak it. */
function redact(match: string): string {
  if (match.length <= 12) return "*".repeat(match.length);
  return `${match.slice(0, 4)}${"*".repeat(match.length - 8)}${match.slice(-4)}`;
}

/**
 * Scan a single file's contents for secrets.
 * @param relPath path relative to scan root (used in the report)
 * @param content full file text
 */
export function scanSecrets(relPath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of RULES) {
      const m = rule.regex.exec(line);
      if (m) {
        findings.push({
          ruleId: rule.ruleId,
          category: "secret",
          severity: rule.severity,
          title: rule.title,
          file: relPath,
          line: i + 1,
          excerpt: redact(m[0]),
          remediation: rule.remediation,
        });
      }
    }
  }

  return findings;
}
