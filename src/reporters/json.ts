import { writeFile } from "node:fs/promises";
import type { ScanResult } from "../types";

/**
 * Emit the scan result as JSON — either to stdout or a file.
 * This is the machine-readable format meant for CI pipelines.
 */
export async function reportJson(
  result: ScanResult,
  outputPath?: string,
): Promise<void> {
  const json = JSON.stringify(result, null, 2);
  if (outputPath) {
    await writeFile(outputPath, json, "utf8");
    console.error(`Report written to ${outputPath}`);
  } else {
    console.log(json);
  }
}
