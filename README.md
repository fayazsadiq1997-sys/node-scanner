# node-sec-scanner

A static security scanner for Node.js / TypeScript projects. Inspects a
codebase for four classes of problem that appear constantly in real AppSec
review:

1. **Hardcoded secrets** — AWS keys, private keys, API keys, JWT secrets, bearer tokens, hardcoded passwords.
2. **Vulnerable dependencies** — known CVEs in `package.json` dependencies, resolved against the [OSV.dev](https://osv.dev) database.
3. **Dangerous misconfigurations** — `eval()`, command injection via `child_process.exec`, weak randomness for security tokens, disabled TLS verification (`rejectUnauthorized: false`), wildcard CORS, plaintext `http://` endpoints.
4. **IaC misconfigurations** — committed `.env` files (git-tracked rather than gitignored), Dockerfile issues (unpinned base image tags, containers running as root, secrets in `ENV` instructions), GitHub Actions workflow issues (unpinned action SHAs, `pull_request_target` + checkout pwn-request vector).

Built with TypeScript and a deliberately small dependency footprint (2 runtime deps).

## Install

```bash
npm install
```

## Usage

```bash
# Scan the current directory
npm run dev -- scan .

# Scan a specific directory
npm run dev -- scan ./path/to/project

# Try it against the bundled vulnerable fixture
npm run dev -- scan ./tests/fixtures/vulnerable-app
```

After `npm run build`, the compiled CLI is runnable directly:

```bash
node dist/cli.js scan .
```

## Output formats

`--format` and `--output` are independent flags. `--format` selects the encoder;
`--output` routes it to a file (stdout when omitted).

```bash
# Colourised terminal output (default)
npm run dev -- scan .

# JSON — to stdout or a file
npm run dev -- scan . --format json
npm run dev -- scan . --format json --output report.json

# SARIF 2.1.0 — for GitHub Code Scanning
npm run dev -- scan . --format sarif --output results.sarif
```

The `terminal` format cannot be written to a file; pair `--output` with
`--format json` or `--format sarif`.

## All flags

| Flag | Default | Description |
|------|---------|-------------|
| `-f, --format <fmt>` | `terminal` | Output encoder: `terminal` \| `json` \| `sarif` |
| `-o, --output <file>` | stdout | Write report to a file |
| `--fail-on <severity>` | off | Exit 1 if any finding is at or above `critical` \| `high` \| `medium` \| `low` |
| `--skip-deps` | off | Skip the dependency check (no network call) |
| `--include-test-dirs` | off | Scan `test/`, `examples/`, `fixtures/` etc. (excluded by default) |
| `--exclude <dirs>` | — | Comma-separated additional directory names to skip |
| `--no-ignore` | off | Disable `.scannerignore` and inline suppression comments |
| `--diff [ref]` | off | Scan only files changed vs `<ref>`; omit ref to scan uncommitted working-tree changes |

## Suppression

Two mechanisms let you acknowledge false positives without deleting findings
from the tool's knowledge.

### .scannerignore file

Place a `.scannerignore` in the project root. Each line is a rule:

```
# suppress all findings in a file
src/legacy/unsafe-shim.ts

# suppress one rule in a file
src/config/db.ts  misconfig.eval

# suppress a rule everywhere
*  misconfig.insecure-http
```

Lines starting with `#` are comments. Blank lines are ignored.

### Inline comments

```ts
const url = "http://internal-only.local"; // scanner-ignore: misconfig.insecure-http

// scanner-ignore: misconfig.eval
eval(trustedTemplate);

// scanner-ignore   (no rule ID = suppress all rules on the next line)
const h = crypto.createHash("md5");
```

Both trailing-line and preceding-line placements are supported. Multiple rule
IDs can be comma-separated: `// scanner-ignore: rule.one, rule.two`.

Use `--no-ignore` to temporarily disable all suppressions and see the raw
findings — useful for auditing what a suppression file is hiding.

## Diff mode

Scan only the files that have changed, rather than the whole project:

```bash
# Uncommitted working-tree changes (staged + unstaged + untracked)
npm run dev -- scan . --diff

# Changed vs a branch or commit
npm run dev -- scan . --diff main
npm run dev -- scan . --diff origin/main
npm run dev -- scan . --diff HEAD~3
```

The dependency check is re-run only when a manifest or lockfile
(`package.json`, `package-lock.json`, `yarn.lock`, etc.) is among the changed
files — otherwise the dependency tree is unchanged and the network call is
skipped.

## Directory filtering

Non-production directories are excluded by default to reduce false positives
(hardcoded credentials in fixtures, `eval()` in test payloads, `http://` in
demo scripts):

> `test/`, `tests/`, `__tests__/`, `spec/`, `examples/`, `demo/`, `fixtures/`,
> `__mocks__/`, `mocks/`, `stubs/`, `e2e/`

Pass `--include-test-dirs` to opt back in, or `--exclude <dirs>` to add extra
directories to the skip list.

Always-ignored: `node_modules/`, `.git/`, `dist/`, `build/`, `coverage/`,
`.next/`, `.cache/`.

## GitHub Actions / CI

The repo ships a workflow at [`.github/workflows/scan.yml`](.github/workflows/scan.yml)
that runs on every push and pull request to `main`, plus a weekly schedule to
catch newly-disclosed CVEs. The job:

1. Builds and runs the test suite (gate — fails the job on error).
2. Self-scans the repo and writes `results.sarif`.
3. Uploads the SARIF to GitHub Code Scanning (`security-events: write`).

To use SARIF upload in your own workflow:

```yaml
- name: Run security scan
  run: node dist/cli.js scan . --format sarif --output results.sarif

- name: Upload SARIF to code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

`if: always()` ensures findings reach the Security tab even if a prior step
failed. The `--fail-on` flag is separate — omit it from the scan step if you
want findings to be report-only rather than breaking the build.

## How it works

| Check | Technique | Source |
|-------|-----------|--------|
| Secrets | Rule-driven regex with redacted output | `src/checks/secrets.ts` |
| Dependencies | OSV.dev REST API, exact versions from `package-lock.json` | `src/checks/dependencies.ts` |
| Misconfigurations | AST via `@typescript-eslint/parser`; `insecure-http` remains regex | `src/checks/misconfigs.ts` |
| Committed `.env` files | `git ls-files` — flags tracked `.env*` files, not just present on disk | `src/checks/iac.ts` |
| Dockerfile issues | Line-by-line: unpinned tags, root user, secrets in `ENV` | `src/checks/iac.ts` |
| GitHub Actions issues | Line-by-line: unpinned action SHAs (`@tag` vs 40-char commit SHA), `pull_request_target` + checkout | `src/checks/iac.ts` |

The misconfig AST checks are import-aware: `exec` is only flagged when the
binding comes from `child_process`, and weak-random is only flagged when the
result is assigned to a security-relevant variable.

## License

MIT
