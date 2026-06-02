import type { Finding } from "../types";

/**
 * Detects dangerous code patterns in JS/TS source.
 *
 * Phase 1 uses line-based regex: fast and dependency-free, but it cannot tell
 * code from comments or strings, so expect some false positives. Phase 3 swaps
 * these for AST checks via @typescript-eslint/parser, which can inspect actual
 * call expressions and their arguments.
 */

interface PatternRule {
  ruleId: string;
  title: string;
  severity: Finding["severity"];
  regex: RegExp;
  remediation: string;
}

const RULES: PatternRule[] = [
  {
    ruleId: "misconfig.eval",
    title: "Use of eval()",
    severity: "high",
    regex: /\beval\s*\(/,
    remediation:
      "Avoid eval(); it enables arbitrary code execution. Use JSON.parse or a safe interpreter instead.",
  },
  {
    ruleId: "misconfig.new-function",
    title: "Dynamic code via new Function()",
    severity: "high",
    regex: /\bnew\s+Function\s*\(/,
    remediation:
      "new Function() executes arbitrary strings as code. Refactor to avoid dynamic evaluation.",
  },
  {
    ruleId: "misconfig.child-process-exec",
    title: "child_process.exec with possible injection",
    severity: "high",
    regex: /\bexec(?:Sync)?\s*\(\s*[`'"].*\$\{/,
    remediation:
      "Use execFile/spawn with an argument array instead of interpolating user input into a shell string.",
  },
  {
    ruleId: "misconfig.weak-random",
    title: "Math.random() used for security-sensitive value",
    severity: "medium",
    regex: /\b(?:token|secret|password|otp|nonce|salt)\b[^\n;]*Math\.random\s*\(/i,
    remediation:
      "Use crypto.randomBytes()/crypto.randomUUID() for tokens and secrets; Math.random() is not cryptographically secure.",
  },
  {
    ruleId: "misconfig.tls-reject-disabled",
    title: "TLS certificate validation disabled",
    severity: "critical",
    regex: /NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0|rejectUnauthorized\s*:\s*false/,
    remediation:
      "Never disable TLS verification in production; it exposes traffic to MITM attacks.",
  },
  {
    ruleId: "misconfig.cors-wildcard",
    title: "Permissive CORS origin '*'",
    severity: "medium",
    regex: /cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"]/,
    remediation:
      "Restrict CORS to an explicit allowlist of trusted origins instead of '*'.",
  },
  {
    ruleId: "misconfig.insecure-http",
    title: "Hardcoded plaintext http:// URL",
    severity: "low",
    regex: /['"]http:\/\/(?!localhost|127\.0\.0\.1)[^'"]+['"]/,
    remediation:
      "Use https:// for external endpoints to protect data in transit.",
  },
];

export function scanMisconfigs(relPath: string, content: string): Finding[] {
  // Only inspect source files.
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/.test(relPath)) return [];

  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    // Cheap comment skip to cut obvious false positives.
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;

    for (const rule of RULES) {
      if (rule.regex.test(line)) {
        findings.push({
          ruleId: rule.ruleId,
          category: "misconfig",
          severity: rule.severity,
          title: rule.title,
          file: relPath,
          line: i + 1,
          excerpt: trimmed.slice(0, 120),
          remediation: rule.remediation,
        });
      }
    }
  }

  return findings;
}
