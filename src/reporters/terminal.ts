import pc from "picocolors";
import type { Finding, ScanResult, Severity } from "../types";
import { SEVERITY_ORDER } from "../types";

function colorForSeverity(sev: Severity, text: string): string {
  switch (sev) {
    case "critical":
      return pc.bgRed(pc.white(` ${text} `));
    case "high":
      return pc.red(text);
    case "medium":
      return pc.yellow(text);
    case "low":
      return pc.blue(text);
    default:
      return pc.gray(text);
  }
}

/** Print a human-readable report to stdout. */
export function reportTerminal(result: ScanResult): void {
  const { findings, filesScanned } = result;

  if (findings.length === 0) {
    console.log(pc.green("\n✔ No issues found."));
    console.log(pc.gray(`  Scanned ${filesScanned} files.\n`));
    return;
  }

  // Group findings by severity, strongest first.
  const bySeverity = [...SEVERITY_ORDER].reverse();
  const sorted = [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity),
  );

  console.log("");
  for (const finding of sorted) {
    printFinding(finding);
  }

  // Summary line with per-severity counts.
  const counts = new Map<Severity, number>();
  for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  const summary = bySeverity
    .filter((s) => counts.get(s))
    .map((s) => colorForSeverity(s, `${counts.get(s)} ${s}`))
    .join(pc.gray("  ·  "));

  console.log(pc.gray("─".repeat(50)));
  console.log(`${pc.bold(String(findings.length))} findings   ${summary}`);
  console.log(pc.gray(`Scanned ${filesScanned} files.\n`));
}

function printFinding(f: Finding): void {
  const loc = f.line ? `${f.file}:${f.line}` : f.file;
  console.log(
    `${colorForSeverity(f.severity, f.severity.toUpperCase())} ${pc.bold(f.title)} ${pc.gray(`[${f.ruleId}]`)}`,
  );
  console.log(`  ${pc.cyan(loc)}`);
  if (f.excerpt) console.log(`  ${pc.gray(f.excerpt)}`);
  console.log(`  ${pc.gray("→")} ${f.remediation}`);
  console.log("");
}
