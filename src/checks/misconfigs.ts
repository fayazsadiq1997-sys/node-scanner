import type { Finding } from "../types";
import { parseAST, findAll } from "../ast";
import type { TSESTree } from "@typescript-eslint/types";

interface PatternRule {
  ruleId: string;
  title: string;
  severity: Finding["severity"];
  regex: RegExp;
  remediation: string;
}

// Rules still using regex (not yet ported to AST).
const RULES: PatternRule[] = [
  {
    ruleId: "misconfig.insecure-http",
    title: "Hardcoded plaintext http:// URL",
    severity: "low",
    regex: /['"]http:\/\/(?!localhost|127\.0\.0\.1)[^'"]+['"]/,
    remediation:
      "Use https:// for external endpoints to protect data in transit.",
  },
];

const DYNAMIC_CODE_RULES = [
  {
    ruleId: "misconfig.eval",
    title: "Use of eval()",
    remediation: "Avoid eval(); it enables arbitrary code execution. Use JSON.parse or a safe interpreter instead.",
    regex: /\beval\s*\(/,
    matchesCall: (node: TSESTree.CallExpression) =>
      node.callee.type === "Identifier" && node.callee.name === "eval",
  },
  {
    ruleId: "misconfig.new-function",
    title: "Dynamic code via new Function()",
    remediation: "new Function() executes arbitrary strings as code. Refactor to avoid dynamic evaluation.",
    regex: /\bnew\s+Function\s*\(/,
    matchesNew: (node: TSESTree.NewExpression) =>
      node.callee.type === "Identifier" && node.callee.name === "Function",
  },
] as const;

/** Flags eval() calls and new Function() expressions, which execute arbitrary strings as code. */
function astCheckDynamicCode(ast: TSESTree.Program, relPath: string, lines: string[]): Finding[] {
  const findings: Finding[] = [];

  for (const rule of DYNAMIC_CODE_RULES) {
    if ("matchesCall" in rule) {
      for (const node of findAll<TSESTree.CallExpression>(ast, "CallExpression")) {
        if (rule.matchesCall(node)) {
          const lineNum = node.loc.start.line;
          findings.push({ ruleId: rule.ruleId, category: "misconfig", severity: "high", title: rule.title, file: relPath, line: lineNum, excerpt: lines[lineNum - 1].trim().slice(0, 120), remediation: rule.remediation });
        }
      }
    } else {
      for (const node of findAll<TSESTree.NewExpression>(ast, "NewExpression")) {
        if (rule.matchesNew(node)) {
          const lineNum = node.loc.start.line;
          findings.push({ ruleId: rule.ruleId, category: "misconfig", severity: "high", title: rule.title, file: relPath, line: lineNum, excerpt: lines[lineNum - 1].trim().slice(0, 120), remediation: rule.remediation });
        }
      }
    }
  }

  return findings;
}

const EXEC_NAMES = new Set(["exec", "execSync"]);
const EXEC_REMEDIATION =
  "Use execFile/spawn with an argument array instead of passing a dynamic string to exec.";

/** Collects exec/execSync bindings imported from child_process. */
function collectExecBindings(ast: TSESTree.Program): { direct: Set<string>; namespaces: Set<string> } {
  const direct = new Set<string>();
  const namespaces = new Set<string>();

  for (const node of findAll<TSESTree.ImportDeclaration>(ast, "ImportDeclaration")) {
    if (node.source.value !== "child_process") continue;
    for (const spec of node.specifiers) {
      if (spec.type === "ImportSpecifier") {
        direct.add(spec.local.name);
      } else if (spec.type === "ImportNamespaceSpecifier" || spec.type === "ImportDefaultSpecifier") {
        namespaces.add(spec.local.name);
      }
    }
  }

  for (const node of findAll<TSESTree.VariableDeclarator>(ast, "VariableDeclarator")) {
    const init = node.init;
    if (!init || init.type !== "CallExpression") continue;
    if (init.callee.type !== "Identifier" || init.callee.name !== "require") continue;
    const arg = init.arguments[0];
    if (!arg || arg.type !== "Literal" || arg.value !== "child_process") continue;

    if (node.id.type === "ObjectPattern") {
      for (const prop of node.id.properties) {
        if (prop.type === "Property" && prop.value.type === "Identifier") {
          direct.add(prop.value.name);
        }
      }
    } else if (node.id.type === "Identifier") {
      namespaces.add(node.id.name);
    }
  }

  return { direct, namespaces };
}

/** Returns true if the AST node represents a value that could vary at runtime. */
function isDynamic(node: TSESTree.Node): boolean {
  if (node.type === "Literal") return false;
  if (node.type === "TemplateLiteral") return node.expressions.length > 0;
  return true;
}

/**
 * Flags exec/execSync calls from child_process whose first argument is dynamic (a variable,
 * template literal with expressions, or any non-literal). Static string calls are skipped
 * because they can't carry injected input. Calls to unrelated functions also named exec are
 * ignored — only bindings traceable to a child_process import/require are flagged.
 */
function astCheckExec(ast: TSESTree.Program, relPath: string, lines: string[]): Finding[] {
  const { direct, namespaces } = collectExecBindings(ast);
  if (direct.size === 0 && namespaces.size === 0) return [];

  const findings: Finding[] = [];

  for (const node of findAll<TSESTree.CallExpression>(ast, "CallExpression")) {
    const callee = node.callee;
    const isDirectCall =
      callee.type === "Identifier" &&
      EXEC_NAMES.has(callee.name) &&
      direct.has(callee.name);
    const isMemberCall =
      callee.type === "MemberExpression" &&
      callee.object.type === "Identifier" &&
      namespaces.has(callee.object.name) &&
      callee.property.type === "Identifier" &&
      EXEC_NAMES.has(callee.property.name);

    if (!isDirectCall && !isMemberCall) continue;

    const firstArg = node.arguments[0];
    if (!firstArg || !isDynamic(firstArg as TSESTree.Node)) continue;

    const lineNum = node.loc.start.line;
    findings.push({
      ruleId: "misconfig.child-process-exec",
      category: "misconfig",
      severity: "high",
      title: "child_process.exec with dynamic argument",
      file: relPath,
      line: lineNum,
      excerpt: lines[lineNum - 1].trim().slice(0, 120),
      remediation: EXEC_REMEDIATION,
    });
  }

  return findings;
}

const TLS_REMEDIATION =
  "Never disable TLS verification in production; it exposes traffic to MITM attacks.";

/**
 * Flags two TLS-disabling patterns:
 *   1. rejectUnauthorized: false  — a Property node with key "rejectUnauthorized" and literal false value.
 *   2. process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'  — an AssignmentExpression whose left-hand
 *      side is a member expression ending in that env var name and whose right-hand side is '0' or 0.
 */
function astCheckTLS(ast: TSESTree.Program, relPath: string, lines: string[]): Finding[] {
  const findings: Finding[] = [];

  for (const node of findAll<TSESTree.Property>(ast, "Property")) {
    if (
      node.key.type === "Identifier" &&
      node.key.name === "rejectUnauthorized" &&
      node.value.type === "Literal" &&
      node.value.value === false
    ) {
      const lineNum = node.loc.start.line;
      findings.push({
        ruleId: "misconfig.tls-reject-disabled",
        category: "misconfig",
        severity: "critical",
        title: "TLS certificate validation disabled",
        file: relPath,
        line: lineNum,
        excerpt: lines[lineNum - 1].trim().slice(0, 120),
        remediation: TLS_REMEDIATION,
      });
    }
  }

  for (const node of findAll<TSESTree.AssignmentExpression>(ast, "AssignmentExpression")) {
    const { left, right } = node;
    const targetsEnvVar =
      left.type === "MemberExpression" &&
      left.property.type === "Identifier" &&
      left.property.name === "NODE_TLS_REJECT_UNAUTHORIZED";
    const isZero =
      right.type === "Literal" && (right.value === "0" || right.value === 0);

    if (targetsEnvVar && isZero) {
      const lineNum = node.loc.start.line;
      findings.push({
        ruleId: "misconfig.tls-reject-disabled",
        category: "misconfig",
        severity: "critical",
        title: "TLS certificate validation disabled",
        file: relPath,
        line: lineNum,
        excerpt: lines[lineNum - 1].trim().slice(0, 120),
        remediation: TLS_REMEDIATION,
      });
    }
  }

  return findings;
}

/**
 * Flags cors() calls where the options object has origin set to the wildcard '*'.
 * Only inspects direct calls to a function named cors — the standard cors npm package pattern.
 */
function astCheckCORS(ast: TSESTree.Program, relPath: string, lines: string[]): Finding[] {
  const findings: Finding[] = [];

  for (const node of findAll<TSESTree.CallExpression>(ast, "CallExpression")) {
    if (node.callee.type !== "Identifier" || node.callee.name !== "cors") continue;
    const firstArg = node.arguments[0];
    if (!firstArg || firstArg.type !== "ObjectExpression") continue;

    const hasWildcardOrigin = firstArg.properties.some(
      (p) =>
        p.type === "Property" &&
        p.key.type === "Identifier" &&
        p.key.name === "origin" &&
        p.value.type === "Literal" &&
        p.value.value === "*"
    );

    if (hasWildcardOrigin) {
      const lineNum = node.loc.start.line;
      findings.push({
        ruleId: "misconfig.cors-wildcard",
        category: "misconfig",
        severity: "medium",
        title: "Permissive CORS origin '*'",
        file: relPath,
        line: lineNum,
        excerpt: lines[lineNum - 1].trim().slice(0, 120),
        remediation: "Restrict CORS to an explicit allowlist of trusted origins instead of '*'.",
      });
    }
  }

  return findings;
}

/** Returns true if the node is a Math.random() call expression. */
function isMathRandom(node: TSESTree.Node): boolean {
  return (
    node.type === "CallExpression" &&
    node.callee.type === "MemberExpression" &&
    node.callee.object.type === "Identifier" &&
    node.callee.object.name === "Math" &&
    node.callee.property.type === "Identifier" &&
    node.callee.property.name === "random"
  );
}

const SENSITIVE_NAME_RE = /token|secret|password|otp|nonce|salt/i;

/**
 * Flags Math.random() used to initialise a security-sensitive variable, assignment, or
 * object property. Checks three assignment contexts:
 *   const token = Math.random()       — VariableDeclarator
 *   this.secret = Math.random()       — AssignmentExpression
 *   { nonce: Math.random() }          — Property
 * This is more accurate than the previous regex, which matched on same-line proximity
 * rather than actual structural assignment.
 */
function astCheckWeakRandom(ast: TSESTree.Program, relPath: string, lines: string[]): Finding[] {
  const findings: Finding[] = [];

  const push = (lineNum: number) =>
    findings.push({
      ruleId: "misconfig.weak-random",
      category: "misconfig",
      severity: "medium",
      title: "Math.random() used for security-sensitive value",
      file: relPath,
      line: lineNum,
      excerpt: lines[lineNum - 1].trim().slice(0, 120),
      remediation:
        "Use crypto.randomBytes()/crypto.randomUUID() for tokens and secrets; Math.random() is not cryptographically secure.",
    });

  for (const node of findAll<TSESTree.VariableDeclarator>(ast, "VariableDeclarator")) {
    if (!node.init || !isMathRandom(node.init)) continue;
    const name = node.id.type === "Identifier" ? node.id.name : "";
    if (SENSITIVE_NAME_RE.test(name)) push(node.loc.start.line);
  }

  for (const node of findAll<TSESTree.AssignmentExpression>(ast, "AssignmentExpression")) {
    if (!isMathRandom(node.right)) continue;
    const name = node.left.type === "Identifier" ? node.left.name :
      node.left.type === "MemberExpression" && node.left.property.type === "Identifier"
        ? node.left.property.name : "";
    if (SENSITIVE_NAME_RE.test(name)) push(node.loc.start.line);
  }

  for (const node of findAll<TSESTree.Property>(ast, "Property")) {
    if (!isMathRandom(node.value as TSESTree.Node)) continue;
    const name = node.key.type === "Identifier" ? node.key.name :
      node.key.type === "Literal" ? String(node.key.value) : "";
    if (SENSITIVE_NAME_RE.test(name)) push(node.loc.start.line);
  }

  return findings;
}

/**
 * Scans a JS/TS source file for dangerous misconfigurations.
 * Parses the file into an AST for all major rules. Falls back to line-based regex if parsing
 * fails. The insecure-http rule remains regex-only as it checks string literal values.
 */
export function scanMisconfigs(relPath: string, content: string): Finding[] {
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/.test(relPath)) return [];

  const lines = content.split(/\r?\n/);
  const ast = parseAST(content, relPath);
  const findings: Finding[] = [];

  if (ast) {
    findings.push(...astCheckDynamicCode(ast, relPath, lines));
    findings.push(...astCheckExec(ast, relPath, lines));
    findings.push(...astCheckTLS(ast, relPath, lines));
    findings.push(...astCheckCORS(ast, relPath, lines));
    findings.push(...astCheckWeakRandom(ast, relPath, lines));
  } else {
    // Fallback: regex for AST-ported rules when parsing fails.
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trim();
      if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
      for (const rule of DYNAMIC_CODE_RULES) {
        if (rule.regex.test(lines[i])) {
          findings.push({ ruleId: rule.ruleId, category: "misconfig", severity: "high", title: rule.title, file: relPath, line: i + 1, excerpt: trimmed.slice(0, 120), remediation: rule.remediation });
        }
      }
      if (/\bexec(?:Sync)?\s*\(\s*[`'"].*\$\{/.test(lines[i])) {
        findings.push({ ruleId: "misconfig.child-process-exec", category: "misconfig", severity: "high", title: "child_process.exec with dynamic argument", file: relPath, line: i + 1, excerpt: trimmed.slice(0, 120), remediation: EXEC_REMEDIATION });
      }
      if (/NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0|rejectUnauthorized\s*:\s*false/.test(lines[i])) {
        findings.push({ ruleId: "misconfig.tls-reject-disabled", category: "misconfig", severity: "critical", title: "TLS certificate validation disabled", file: relPath, line: i + 1, excerpt: trimmed.slice(0, 120), remediation: TLS_REMEDIATION });
      }
      if (/cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"]/.test(lines[i])) {
        findings.push({ ruleId: "misconfig.cors-wildcard", category: "misconfig", severity: "medium", title: "Permissive CORS origin '*'", file: relPath, line: i + 1, excerpt: trimmed.slice(0, 120), remediation: "Restrict CORS to an explicit allowlist of trusted origins instead of '*'." });
      }
      if (/\b(?:token|secret|password|otp|nonce|salt)\b[^\n;]*Math\.random\s*\(/i.test(lines[i])) {
        findings.push({ ruleId: "misconfig.weak-random", category: "misconfig", severity: "medium", title: "Math.random() used for security-sensitive value", file: relPath, line: i + 1, excerpt: trimmed.slice(0, 120), remediation: "Use crypto.randomBytes()/crypto.randomUUID() for tokens and secrets; Math.random() is not cryptographically secure." });
      }
    }
  }

  // Remaining rules still on regex.
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
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
