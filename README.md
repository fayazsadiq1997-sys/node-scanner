# node-sec-scanner

A security scanner for Node.js / TypeScript projects. It statically inspects a
codebase for three classes of problem that show up constantly in real AppSec
review:

1. **Hardcoded secrets** — AWS keys, private keys, API keys, JWT secrets, bearer tokens, hardcoded passwords.
2. **Vulnerable dependencies** — known CVEs in `package.json` dependencies, resolved against the [OSV.dev](https://osv.dev) database.
3. **Dangerous misconfigurations** — `eval()`, command injection via `child_process.exec`, weak randomness for tokens, disabled TLS verification, wildcard CORS, plaintext `http://` endpoints.

Built with TypeScript and a deliberately tiny dependency tree (2 runtime deps).

## Install

```bash
npm install
```

## Usage

```bash
# Scan a directory (defaults to current directory)
npm run dev -- scan ./path/to/project

# Try it against the bundled vulnerable fixture
npm run dev -- scan ./tests/fixtures/vulnerable-app

# JSON output for CI pipelines
npm run dev -- scan . --format json --output report.json

# Skip the network-dependent dependency check
npm run dev -- scan . --skip-deps

# Fail the build (exit 1) if anything high or above is found — for CI
npm run dev -- scan . --fail-on high
```

After `npm run build`, the compiled CLI is runnable as `node dist/cli.js scan .`.

## How it works

| Check | Technique | Source |
|-------|-----------|--------|
| Secrets | Rule-driven regex with redacted output | `src/checks/secrets.ts` |
| Dependencies | OSV.dev REST API, exact versions from `package-lock.json` | `src/checks/dependencies.ts` |
| Misconfigurations | Line-based regex (AST upgrade planned) | `src/checks/misconfigs.ts` |

The file walker skips `node_modules`, `.git`, `dist`, and other build output, and
ignores files over 1 MB.

## Roadmap

- [ ] AST-based misconfig checks via `@typescript-eslint/parser` (fewer false positives)
- [ ] SARIF output for GitHub Code Scanning
- [ ] Entropy-based detection for unknown secret formats
- [ ] GitHub Actions workflow that runs the scanner on itself

## License

MIT
