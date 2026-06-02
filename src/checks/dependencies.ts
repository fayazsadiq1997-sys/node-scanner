import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Finding, Severity } from "../types";

/**
 * Queries the OSV.dev database for known vulnerabilities in the project's
 * dependencies. OSV is free, requires no API key, and aggregates advisories
 * across ecosystems including npm.
 *
 * We resolve exact installed versions from package-lock.json when available
 * (more accurate), falling back to the declared ranges in package.json.
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

/** Map an OSV advisory to one of our severities. */
function mapSeverity(vuln: OsvVuln): Severity {
  const label = vuln.database_specific?.severity?.toUpperCase();
  if (label === "CRITICAL") return "critical";
  if (label === "HIGH") return "high";
  if (label === "MODERATE" || label === "MEDIUM") return "medium";
  if (label === "LOW") return "low";

  // Fall back to CVSS score if present.
  const cvss = vuln.severity?.find((s) => s.type.startsWith("CVSS"));
  if (cvss) {
    const score = parseFloat(cvss.score);
    if (!Number.isNaN(score)) {
      if (score >= 9) return "critical";
      if (score >= 7) return "high";
      if (score >= 4) return "medium";
      return "low";
    }
  }
  return "medium";
}

async function resolveDependencies(root: string): Promise<ResolvedDep[]> {
  const pkgPath = path.join(root, "package.json");
  let pkgRaw: string;
  try {
    pkgRaw = await readFile(pkgPath, "utf8");
  } catch {
    return []; // No package.json — nothing to check.
  }

  const pkg = JSON.parse(pkgRaw) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  const declared = { ...pkg.dependencies, ...pkg.devDependencies };

  // Prefer exact versions from the lockfile if we can read it.
  const lockVersions = await readLockVersions(root);

  return Object.entries(declared).map(([name, range]) => ({
    name,
    version: lockVersions.get(name) ?? cleanVersion(range),
  }));
}

async function readLockVersions(root: string): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  try {
    const lockRaw = await readFile(path.join(root, "package-lock.json"), "utf8");
    const lock = JSON.parse(lockRaw) as {
      packages?: Record<string, { version?: string }>;
    };
    if (lock.packages) {
      for (const [key, val] of Object.entries(lock.packages)) {
        // Keys look like "node_modules/<name>" or nested paths.
        const m = key.match(/(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/);
        if (m && val.version) map.set(m[1], val.version);
      }
    }
  } catch {
    // Lockfile missing or unparseable — caller falls back to declared ranges.
  }
  return map;
}

async function queryOsv(dep: ResolvedDep): Promise<OsvVuln[]> {
  const res = await fetch(OSV_QUERY_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      version: dep.version,
      package: { name: dep.name, ecosystem: "npm" },
    }),
  });
  if (!res.ok) return [];
  const data = (await res.json()) as OsvResponse;
  return data.vulns ?? [];
}

export async function scanDependencies(root: string): Promise<Finding[]> {
  const deps = await resolveDependencies(root);
  const findings: Finding[] = [];

  // Query with bounded concurrency to stay polite to the API.
  const CONCURRENCY = 8;
  for (let i = 0; i < deps.length; i += CONCURRENCY) {
    const batch = deps.slice(i, i + CONCURRENCY);
    const results = await Promise.all(
      batch.map(async (dep) => ({ dep, vulns: await queryOsv(dep) })),
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

  return findings;
}
