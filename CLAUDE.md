# CLAUDE.md

Before navigating or modifying this codebase, read [ARCHITECTURE.md](ARCHITECTURE.md) — it documents the data flow (cli → scanner → checks → reporters), where rules live, and key conventions. Don't re-derive structure by grepping when that file covers it.

**Adding a GitHub Actions workflow rule** = add to `scanGitHubActions` in `src/checks/iac.ts`. Scanner routes files matching `.github/workflows/*.yml` or `.github/workflows/*.yaml` there. No YAML parser — line-by-line regex, same pattern as `scanDockerfile`.
