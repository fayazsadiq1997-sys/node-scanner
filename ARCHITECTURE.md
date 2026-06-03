# Architecture

Guidance for navigating this codebase. Describes architecture and conventions, not a function-by-function inventory (which goes stale). Read source for exact signatures.

## What this is

`node-sec-scanner` — a CLI that scans Node.js projects for three classes of issue:
- **secrets** — hardcoded credentials (regex-based)
- **dependency** vulnerabilities (OSV.dev lookup)
- **misconfig** — dangerous code patterns (AST-based, regex fallback)

## Commands

- `npm run dev -- scan <path> [opts]` — run from source via tsx (no build)
- `npm run build` — compile TS → `dist/`
- `npm test` — run `tests/**/*.test.ts` via the Node test runner (tsx). Requires Node 22 for the glob support.
- `npm run scan` — shortcut for `tsx src/cli.ts scan`

CLI flags live in [src/cli.ts](src/cli.ts): `--format terminal|json|sarif`, `--output`, `--fail-on <sev>`, `--skip-deps`, `--include-test-dirs`, `--exclude`, `--no-ignore`, `--diff [ref]`.

## Architecture / data flow

```
cli.ts  →  scanner.scan()  →  checks/*  →  Finding[]
                          →  suppression (filter)
                          →  reporters/*  (terminal | json | sarif)
```

1. **[src/cli.ts](src/cli.ts)** — commander setup, flag parsing, picks a reporter, applies `--fail-on` exit logic. Exit codes: 1 = threshold breached, 2 = error.
2. **[src/scanner.ts](src/scanner.ts)** — orchestrator. Walks the tree (`walk` async generator), filters by extension/size/excluded dirs, runs each content check, runs the dependency check once, then applies suppressions. Returns `ScanResult`. Diff mode resolves changed files up front via git.
3. **[src/checks/](src/checks)** — one file per category, each exporting a `scanX(relPath, content)` (or `scanDependencies(root)`) returning `Finding[]`.
4. **[src/suppression.ts](src/suppression.ts)** — filters findings via `.scannerignore` + inline `// scanner-ignore` comments; returns kept + suppressed (tagged).
5. **[src/reporters/](src/reporters)** — encode a `ScanResult` to an output format. Pure formatting, no scanning logic.

## Key conventions

- **`Finding` is the universal currency.** Defined in [src/types.ts](src/types.ts). Every check produces them; every reporter consumes them. Change this type carefully — it ripples everywhere.
- **Adding a secret/http rule** = append to the `RULES` array in the relevant check file. Regex-driven, declarative.
- **Adding a misconfig rule** = prefer an AST check in [src/checks/misconfigs.ts](src/checks/misconfigs.ts) (`astCheckX` functions over `findAll`), with a regex fallback for when parsing fails. AST parsing lives in [src/ast.ts](src/ast.ts).
- **Severity ordering** is centralized: `SEVERITY_ORDER` + `meetsThreshold()` in types.ts. Don't hardcode comparisons.
- **Paths in findings** are relative to scan root, forward-slashed (even on Windows).
- **`ruleId` namespacing**: `secret.*`, `dependency.*`, `misconfig.*`. Used by suppression and SARIF rule catalog.

## Tests

`tests/` mirror behavior, not file structure (e.g. [tests/sarif.test.ts](tests/sarif.test.ts), [tests/suppression.test.ts](tests/suppression.test.ts), [tests/diff.test.ts](tests/diff.test.ts)). Fixtures under `tests/fixtures/`. Uses the built-in `node:test` runner.

## Gotchas

- Dependency check hits the network (OSV.dev); failures are swallowed so they don't abort a scan. Use `--skip-deps` for offline/deterministic runs.
- Test/example/fixture dirs are **excluded by default** (`NON_PRODUCTION_DIRS` in scanner.ts) to cut false positives. `--include-test-dirs` opts back in.
- In `--diff` mode the dependency check only re-runs when a manifest/lockfile changed (`MANIFEST_FILES`).
- `terminal` format can't be written to `--output` (colors); cli.ts throws.
- Project is `commonjs` (`type` in package.json); compiled output targets `dist/`.

## Reference docs

- [README.md](README.md) — user-facing usage
- [plan.md](plan.md) — roadmap / ongoing work
- [FINDINGS.md](FINDINGS.md)
