#!/usr/bin/env node
import { Command } from "commander";
import pc from "picocolors";
import { scan } from "./scanner";
import { reportTerminal } from "./reporters/terminal";
import { reportJson } from "./reporters/json";
import { meetsThreshold, type Severity } from "./types";

const program = new Command();

program
  .name("node-sec-scanner")
  .description(
    "Scan a Node.js project for hardcoded secrets, vulnerable dependencies, and dangerous misconfigurations.",
  )
  .version("0.1.0");

program
  .command("scan")
  .argument("[path]", "directory to scan", ".")
  .option("-f, --format <format>", "output format: terminal | json", "terminal")
  .option("-o, --output <file>", "write report to a file (json format)")
  .option(
    "--fail-on <severity>",
    "exit with code 1 if any finding is at or above this severity (critical|high|medium|low)",
  )
  .option("--skip-deps", "skip the dependency vulnerability check (no network)", false)
  .option("--include-test-dirs", "scan test/, examples/, fixtures/ etc. (excluded by default)", false)
  .option("--exclude <dirs>", "comma-separated list of additional directory names to exclude")
  .action(async (targetPath: string, opts) => {
    const result = await scan(targetPath, {
      skipDependencies: opts.skipDeps,
      includeTestDirs: opts.includeTestDirs,
      excludeDirs: opts.exclude ? (opts.exclude as string).split(",").map((d: string) => d.trim()) : [],
    });

    if (opts.format === "json" || opts.output) {
      await reportJson(result, opts.output);
    } else {
      reportTerminal(result);
    }

    if (opts.failOn) {
      const threshold = opts.failOn as Severity;
      const breached = result.findings.some((f) =>
        meetsThreshold(f.severity, threshold),
      );
      if (breached) {
        console.error(
          pc.red(`\nFailing: findings at or above '${threshold}' were detected.`),
        );
        process.exit(1);
      }
    }
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(pc.red(`Error: ${err instanceof Error ? err.message : String(err)}`));
  process.exit(2);
});
