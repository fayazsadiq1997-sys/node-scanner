import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Finding, Severity } from "../types";

/**
 * Queries the OSV.dev database for known vulnerabilities in the project's
 * dependencies. OSV is free, requires no API key, and aggregates advisories
 * across ecosystems including npm.
 *
 * When package-lock.json is available, every installed package — direct and
 * transitive — is checked at its exact version. Without a lockfile, only the
 * dependencies declared in package.json are checked, with their semver ranges
 * cleaned to a concrete-ish version.
 */

interface OsvSeverity {
  type: string;
  score: string;
}

interface OsvVuln {
  id: string;
  summary?: string;
  severity?: OsvSeverity[];
  database_specific?: { severity?: string };
}

interface OsvResponse {
  vulns?: OsvVuln[];
}

interface ResolvedDep {
  name: string;
  version: string;
}

const OSV_QUERY_URL = "https://api.osv.dev/v1/query";

/** Strip a semver range down to a concrete-ish version for querying. */
function cleanVersion(raw: string): string {
  return raw.replace(/^[\^~>=<\s]+/, "").trim();
}

/**
 * A concrete-ish version after range cleaning: "4", "4.17", or "4.17.21",
 * optionally with a prerelease/build suffix. Specifiers that survive cleaning
 * but aren't versions at all (`workspace:*`, `file:../lib`, `*`, `1 || 2`,
 * `git+https://...`) would reach OSV verbatim, return nothing, and make an
 * unscanned package look clean — those are skipped with a warning instead.
 */
const CONCRETE_VERSION_RE = /^\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.-]+)?$/;

/**
 * CVSS v3.x base-metric weights, from the CVSS v3.1 specification (section 7.4).
 * Needed because OSV's severity[].score field holds the CVSS *vector string*
 * (e.g. "CVSS:3.1/AV:N/AC:L/..."), not a numeric score — the base score has to
 * be computed from the metrics.
 */
const CVSS3_WEIGHTS: Record<string, Record<string, number>> = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
};

/** Privileges Required weights differ when scope is changed (S:C). */
const CVSS3_PR_WEIGHTS: Record<"U" | "C", Record<string, number>> = {
  U: { N: 0.85, L: 0.62, H: 0.27 },
  C: { N: 0.85, L: 0.68, H: 0.5 },
};

/**
 * CVSS v3.1 Roundup (spec Appendix A): smallest value with one decimal place
 * that is >= the input, with integer arithmetic to dodge floating-point drift.
 */
function roundup(n: number): number {
  const scaled = Math.round(n * 100000);
  return scaled % 10000 === 0 ? scaled / 100000 : (Math.floor(scaled / 10000) + 1) / 10;
}

/**
 * Computes the CVSS v3.0/v3.1 base score (0–10) from a vector string.
 * Returns null for non-v3 vectors (v2/v4) or vectors missing a required base
 * metric, in which case the caller falls back to a default severity.
 */
export function cvssBaseScoreV3(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;

  const metrics = new Map<string, string>();
  for (const part of vector.split("/").slice(1)) {
    const [k, v] = part.split(":");
    if (k && v) metrics.set(k, v);
  }

  const scope = metrics.get("S");
  if (scope !== "U" && scope !== "C") return null;
  const av = CVSS3_WEIGHTS.AV[metrics.get("AV") ?? ""];
  const ac = CVSS3_WEIGHTS.AC[metrics.get("AC") ?? ""];
  const pr = CVSS3_PR_WEIGHTS[scope][metrics.get("PR") ?? ""];
  const ui = CVSS3_WEIGHTS.UI[metrics.get("UI") ?? ""];
  const c = CVSS3_WEIGHTS.C[metrics.get("C") ?? ""];
  const i = CVSS3_WEIGHTS.I[metrics.get("I") ?? ""];
  const a = CVSS3_WEIGHTS.A[metrics.get("A") ?? ""];
  if ([av, ac, pr, ui, c, i, a].some((w) => w === undefined)) return null;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact =
    scope === "U"
      ? 6.42 * iss
      : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  return scope === "U"
    ? roundup(Math.min(impact + exploitability, 10))
    : roundup(Math.min(1.08 * (impact + exploitability), 10));
}

/**
 * Maps an OSV advisory to one of our severities: the database's own label when
 * present, then a base score computed from a CVSS v3 vector, then "medium" as
 * the documented default (e.g. advisories carrying only a CVSS v2/v4 vector).
 */
function mapSeverity(vuln: OsvVuln): Severity {
  const label = vuln.database_specific?.severity?.toUpperCase();
  if (label === "CRITICAL") return "critical";
  if (label === "HIGH") return "high";
  if (label === "MODERATE" || label === "MEDIUM") return "medium";
  if (label === "LOW") return "low";

  const cvss = vuln.severity?.find((s) => s.type.startsWith("CVSS_V3"));
  if (cvss) {
    const score = cvssBaseScoreV3(cvss.score);
    if (score !== null) {
      if (score >= 9) return "critical";
      if (score >= 7) return "high";
      if (score >= 4) return "medium";
      return "low";
    }
  }
  return "medium";
}

/**
 * Resolves the set of packages to query against OSV.
 *
 * Prefers package-lock.json: it enumerates every installed package — including
 * transitive dependencies, which account for most real-world npm CVE exposure —
 * at exact versions. Without a lockfile, falls back to the direct dependencies
 * declared in package.json. Exported for testing.
 */
export async function resolveDependencies(root: string): Promise<ResolvedDep[]> {
  const lockDeps = await readLockDependencies(root);
  if (lockDeps.length > 0) return lockDeps;

  const pkgPath = path.join(root, "package.json");
  let pkgRaw: string;
  try {
    pkgRaw = await readFile(pkgPath, "utf8");
  } catch {
    return []; // No package.json — nothing to check.
  }

  let pkg: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  try {
    pkg = JSON.parse(pkgRaw);
  } catch (err) {
    // Without this warning a malformed package.json is indistinguishable from
    // a project with no dependencies — the scan would just look clean.
    const msg = err instanceof Error ? err.message : String(err);
    console.error(
      `[node-sec-scanner] dependency check skipped: could not parse package.json (${msg})`,
    );
    return [];
  }

  const declared = { ...pkg.dependencies, ...pkg.devDependencies };
  const deps: ResolvedDep[] = [];
  const skipped: string[] = [];
  for (const [name, range] of Object.entries(declared)) {
    const version = cleanVersion(range);
    if (CONCRETE_VERSION_RE.test(version)) {
      deps.push({ name, version });
    } else {
      skipped.push(`${name}@${range}`);
    }
  }
  if (skipped.length > 0) {
    console.error(
      `[node-sec-scanner] dependency check: skipped ${skipped.length} package(s) with ` +
        `non-semver specifiers OSV cannot resolve (${skipped.slice(0, 5).join(", ")}` +
        `${skipped.length > 5 ? ", …" : ""}); add a lockfile to scan them at exact versions.`,
    );
  }
  return deps;
}

/**
 * Parses package-lock.json and returns every installed package — direct and
 * transitive — at its exact version, deduplicated by name@version (the same
 * package can appear at multiple nested node_modules paths). Returns an empty
 * array if the lockfile is absent or cannot be parsed.
 */
async function readLockDependencies(root: string): Promise<ResolvedDep[]> {
  try {
    const lockRaw = await readFile(path.join(root, "package-lock.json"), "utf8");
    const lock = JSON.parse(lockRaw) as {
      packages?: Record<string, { version?: string }>;
    };
    const seen = new Set<string>();
    const deps: ResolvedDep[] = [];
    for (const [key, val] of Object.entries(lock.packages ?? {})) {
      // Keys look like "node_modules/<name>" or nested paths. The "" key is
      // the root project itself; workspace links carry no version. Both skipped.
      const m = key.match(/(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/);
      if (!m || !val.version) continue;
      const id = `${m[1]}@${val.version}`;
      if (seen.has(id)) continue;
      seen.add(id);
      deps.push({ name: m[1], version: val.version });
    }
    return deps;
  } catch {
    return []; // Caller falls back to package.json's declared dependencies.
  }
}

/** Abort an OSV query after this long so one hung connection can't stall the scan. */
const OSV_TIMEOUT_MS = 10_000;

/**
 * Queries the OSV.dev API for known vulnerabilities in a single package at a
 * specific version. Throws on network failure, timeout, or a non-OK response
 * (e.g. 429 rate limiting) so callers can distinguish "no advisories" from
 * "query failed".
 */
async function queryOsv(dep: ResolvedDep): Promise<OsvVuln[]> {
  const res = await fetch(OSV_QUERY_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      version: dep.version,
      package: { name: dep.name, ecosystem: "npm" },
    }),
    signal: AbortSignal.timeout(OSV_TIMEOUT_MS),
  });
  if (!res.ok) {
    throw new Error(`OSV returned HTTP ${res.status} for ${dep.name}@${dep.version}`);
  }
  const data = (await res.json()) as OsvResponse;
  return data.vulns ?? [];
}

/**
 * Resolves all dependencies in the project and queries OSV.dev for known vulnerabilities.
 * Queries are batched to limit concurrent network requests. A failed query
 * (timeout, rate limit, network error) skips that package and is reported once
 * on stderr at the end, so an incomplete run is distinguishable from a clean one.
 */
export async function scanDependencies(root: string): Promise<Finding[]> {
  const deps = await resolveDependencies(root);
  const findings: Finding[] = [];
  let failedQueries = 0;
  let firstError: string | undefined;

  // Query with bounded concurrency to stay polite to the API.
  const CONCURRENCY = 8;
  for (let i = 0; i < deps.length; i += CONCURRENCY) {
    const batch = deps.slice(i, i + CONCURRENCY);
    const results = await Promise.all(
      batch.map(async (dep) => {
        try {
          return { dep, vulns: await queryOsv(dep) };
        } catch (err) {
          failedQueries++;
          if (firstError === undefined) {
            firstError = err instanceof Error ? err.message : String(err);
          }
          return { dep, vulns: [] };
        }
      }),
    );
    for (const { dep, vulns } of results) {
      for (const vuln of vulns) {
        findings.push({
          ruleId: `dependency.${vuln.id}`,
          category: "dependency",
          severity: mapSeverity(vuln),
          title: `${dep.name}@${dep.version}: ${vuln.id}`,
          file: "package.json",
          excerpt: vuln.summary?.slice(0, 160) ?? vuln.id,
          remediation: `Review https://osv.dev/vulnerability/${vuln.id} and upgrade ${dep.name} to a patched version.`,
        });
      }
    }
  }

  if (failedQueries > 0) {
    console.error(
      `[node-sec-scanner] dependency check incomplete: ${failedQueries}/${deps.length} ` +
        `OSV queries failed (first error: ${firstError}); results may be missing findings.`,
    );
  }

  return findings;
}
