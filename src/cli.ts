#!/usr/bin/env node
import { Command } from "commander";
import pc from "picocolors";
import { scan } from "./scanner";
import { reportTerminal } from "./reporters/terminal";
import { reportJson } from "./reporters/json";
import { reportSarif } from "./reporters/sarif";
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
  .option("-f, --format <format>", "output format: terminal | json | sarif", "terminal")
  .option("-o, --output <file>", "write the report to a file instead of stdout")
  .option(
    "--fail-on <severity>",
    "exit with code 1 if any finding is at or above this severity (critical|high|medium|low)",
  )
  .option("--skip-deps", "skip the dependency vulnerability check (no network)", false)
  .option("--include-test-dirs", "scan test/, examples/, fixtures/ etc. (excluded by default)", false)
  .option("--exclude <dirs>", "comma-separated list of additional directory names to exclude")
  .option("--no-ignore", "disable .scannerignore and inline scanner-ignore comments (show all findings)")
  .action(async (targetPath: string, opts) => {
    const result = await scan(targetPath, {
      skipDependencies: opts.skipDeps,
      includeTestDirs: opts.includeTestDirs,
      excludeDirs: opts.exclude ? (opts.exclude as string).split(",").map((d: string) => d.trim()) : [],
      noIgnore: opts.ignore === false,
    });

    // --format selects the encoder; --output selects the destination. The two
    // are independent, except that the colourised terminal format is not
    // meaningful written to a file.
    const format = (opts.format as string).toLowerCase();
    switch (format) {
      case "terminal":
        if (opts.output) {
          throw new Error(
            "terminal format cannot be written to a file; use --format json or --format sarif with --output",
          );
        }
        reportTerminal(result);
        break;
      case "json":
        await reportJson(result, opts.output);
        break;
      case "sarif":
        await reportSarif(result, opts.output);
        break;
      default:
        throw new Error(
          `unknown format '${opts.format}'; expected terminal | json | sarif`,
        );
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
