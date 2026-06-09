# Findings

Real-world scan results from running node-sec-scanner against public Node.js repositories.

---

## expressjs/express

**Scanned:** 2026-06-02  
**Version:** latest main branch  
**Command:** `npm run dev -- scan ../RandomRepos/express`

### Real Findings

#### qs@6.14.2 — Remote DoS via stringify (GHSA-q8mj-m7cp-5q26)
- **Severity:** Medium
- **File:** `package.json` (transitive dependency via express)
- **CVE:** [GHSA-q8mj-m7cp-5q26](https://osv.dev/vulnerability/GHSA-q8mj-m7cp-5q26)
- **Detail:** `qs.stringify` crashes with a `TypeError` on `null`/`undefined` entries in comma-format arrays when `encodeValuesOnly` is set. Remotely triggerable if user input reaches `qs.stringify` with that option enabled.
- **Remediation:** Upgrade `qs` to a patched version.

---

### False Positives

These findings were raised by the scanner but are not genuine security issues in production code.

#### eval() in test/res.redirect.js:115-116
- **Why false positive:** The word `eval` appears inside a string literal (`var xss = 'javascript:eval(...)'`) used to simulate an XSS payload in a test. The scanner's regex matches the string content — no code is being dynamically evaluated.
- **Root cause:** Regex-based detection cannot distinguish `eval(...)` call expressions from `eval` appearing inside string literals or comments.
- **Planned fix:** Upgrade to AST-based detection via `@typescript-eslint/parser`, which inspects the actual call graph rather than raw text.

#### Hardcoded password in examples/auth/index.js:50
- **Why false positive:** Intentional placeholder credentials in a demo authentication example shipped with the framework. Not production code.
- **Root cause:** Scanner does not exclude `examples/`, `demo/`, or `sample/` directories.
- **Planned fix:** Add configurable path exclusions; auto-exclude common non-production directories (`test/`, `tests/`, `examples/`, `fixtures/`, `__mocks__/`).

#### http:// URL in examples/vhost/index.js:39
- **Why false positive:** Plaintext redirect in a localhost vhost demo. Intentionally uses `http://` for local development.
- **Root cause:** Scanner flags all non-localhost `http://` URLs without considering file context.
- **Planned fix:** Combine path exclusions (above) with a tighter URL rule that skips `example.com` and other documentation-convention domains.

---

## node-sec-scanner (self-scan)

**Scanned:** 2026-06-03
**Version:** main branch
**Command:** `node dist/cli.js scan . --skip-deps --format json`

### Real Findings

#### Unpinned GitHub Actions in .github/workflows/scan.yml

- **Severity:** Medium
- **Rule:** `misconfig.gha-unpinned-action`
- **Findings:**
  - Line 23: `uses: actions/checkout@v4`
  - Line 25: `uses: actions/setup-node@v4`
  - Line 51: `uses: github/codeql-action/upload-sarif@v3`
- **Detail:** All three action references use mutable version tags. A compromised publisher account could move a tag to point to malicious code, which would then run with the permissions granted to the workflow (`contents: read`, `security-events: write`).
- **Remediation:** Pin each action to its full commit SHA. Tags should be left as comments for readability.
- **Status:** Detected by the scanner on the same run that introduced the rule — confirmed dogfood.

![GitHub Code Scanning alerts showing 3 unpinned GitHub Actions version findings in scan.yml](docs/screenshots/gha-code-scanning-findings.png)

---

## appsecco/dvna (Damn Vulnerable NodeJS Application)

**Scanned:** 2026-06-09  
**Version:** HEAD `9ba473a` (shallow clone)  
**Command:** `npm run dev -- scan ../RandomRepos/dvna`  
**Result:** 32 findings — 15 critical · 5 high · 9 medium · 3 low (21 files scanned)

DVNA is a purpose-built vulnerable app, so it exercises every check class at once.
The dependency check performed excellently; the code-level misconfig check missed
DVNA's flagship command injection. Both outcomes are documented below.

### Real Findings

#### Dependency CVEs — 27 advisories across 10 packages

The highest-value output of the run. The check resolved exact pinned versions from
`package.json` and matched them against OSV.dev. Representative critical findings:

| Package | Version | Advisory | Issue |
|---------|---------|----------|-------|
| `node-serialize` | 0.0.4 | [GHSA-q4v7-4rhw-9hqm](https://osv.dev/vulnerability/GHSA-q4v7-4rhw-9hqm) | Code execution through IIFE (deserialization RCE) |
| `mathjs` | 3.10.1 | [GHSA-pv8x-p9hq-j328](https://osv.dev/vulnerability/GHSA-pv8x-p9hq-j328) | Arbitrary code execution |
| `sequelize` | 4.13.10 | [GHSA-j9xp-92vc-559j](https://osv.dev/vulnerability/GHSA-j9xp-92vc-559j) | SQL injection |
| `mysql2` | 1.4.2 | [GHSA-fpw7-j2hg-69v5](https://osv.dev/vulnerability/GHSA-fpw7-j2hg-69v5) | Remote code execution |
| `ejs` | 2.5.7 | [GHSA-phwq-j96m-2c2q](https://osv.dev/vulnerability/GHSA-phwq-j96m-2c2q) | Template injection |
| `express-fileupload` | 0.4.0 | [GHSA-9wcg-jrwf-8gg7](https://osv.dev/vulnerability/GHSA-9wcg-jrwf-8gg7) | Prototype pollution |
| `morgan` | 1.9.0 | [GHSA-gwg9-rgvj-4h5j](https://osv.dev/vulnerability/GHSA-gwg9-rgvj-4h5j) | Code injection |
| `libxmljs` | 0.19.1 | [GHSA-6433-x5p4-8jc7](https://osv.dev/vulnerability/GHSA-6433-x5p4-8jc7) | Type confusion |

Zero false positives in this category — exact versions, confirmed advisories.

#### Container runs as root — Dockerfile

- **Severity:** Medium
- **Rule:** `misconfig.dockerfile-root-user`
- **Detail:** No `USER` instruction; the container runs as root.
- **Remediation:** Add a non-root `USER` after package installation.

### Missed Finding — command injection not detected

This is the important negative result. DVNA's signature OS command injection lives in
a **production directory that was scanned** (`core/appHandler.js`, not an excluded
test/fixture dir), yet the AST misconfig check did not flag it:

```js
core/appHandler.js:3    const exec = require('child_process').exec;
core/appHandler.js:39   exec('ping -c 2 ' + req.body.address, function (err, stdout, stderr) {
```

This is `child_process.exec` with a user-tainted, concatenated argument — precisely
what the exec check is supposed to catch.

- **How it was missed:** `collectExecBindings` in `src/checks/misconfigs.ts` recognises
  three binding forms — ESM `import { exec }`, destructured `const { exec } = require(...)`,
  and namespace `const cp = require('child_process')` (then `cp.exec`). The require-then-member
  form **`const exec = require('child_process').exec`** is unhandled: the `VariableDeclarator`
  init is a `MemberExpression` (object = the `require(...)` call, property = `exec`), but the
  collector's guard requires `init.type === "CallExpression"` and `continue`s past it. The
  `exec` binding is therefore never registered as a child_process binding, so the call site is
  never inspected.
- **Why the regex fallback didn't catch it either:** the fallback pattern only matches
  template-literal interpolation (`exec(`...${...}`)`), not string concatenation
  (`'ping -c 2 ' + req.body.address`).
- **Planned fix:** Extend `collectExecBindings` to handle a `VariableDeclarator` whose init is
  a `MemberExpression` over `require('child_process')`, mapping the property name (`exec`/`execSync`)
  to a direct binding. Add a regression test using this exact DVNA pattern.

Two other DVNA sinks were not flagged, but those are accepted limitations rather than bugs:
`mathjs.eval(req.body.eqn)` (a library method, not global `eval`) and
`serialize.unserialize(...)` (no deserialization rule exists — caught only as the
`node-serialize` dependency CVE above).

### False Positives

#### http:// URL in public/assets/showdown.min.js:3
- **Why false positive:** The `http://` is inside Showdown, a **vendored minified
  third-party library** bundled under `public/assets/` — not one of DVNA's own endpoints.
- **Root cause:** The regex `insecure-http` rule has no notion of vendored/minified assets;
  `public/assets/` is not in the default exclusion list.
- **Planned fix:** Add a default exclusion (or lower-confidence treatment) for vendored
  asset paths and `*.min.js` bundles.

---

## Lessons Learned

1. **Regex scanning generates false positives in test and example code.** The highest-value improvement to this scanner is AST-based analysis, which understands whether `eval` is being called or merely referenced in a string.

2. **Dependency scanning is the highest signal-to-noise check.** The `qs` CVE was a genuine finding with zero ambiguity — exact version, confirmed advisory, real dependency. No false positive risk.

3. **Path context matters.** A finding in `src/` carries very different weight than the same finding in `test/` or `examples/`. A future version will annotate findings with a confidence score based on file path. Vendored/minified bundles under `public/assets/` are a third bucket: scanned production code, but not the project's own — the DVNA `showdown.min.js` http:// false positive argues for excluding them too.

4. **AST detection is only as good as its binding-form coverage.** Moving from regex to AST removed string-literal false positives, but the DVNA command-injection miss showed the opposite failure mode: a real sink slipping through because the import/require pattern (`const exec = require('child_process').exec`) wasn't one of the forms the binding collector recognised. Test fixtures should enumerate every common way a sink can be bound — destructuring, namespace, and require-then-member — not just the canonical one.
