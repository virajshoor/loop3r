# Coverage

## Implemented and verified

| Area | Evidence |
|---|---|
| Parsers | 17 embedded Tree-sitter grammars covering 16 languages plus TSX |
| AST rules | 22 exact qualified-call rules with argument matchers; each has a positive real-parse-tree fixture plus safe-spelling negatives |
| Import resolution | Python and JS/TS/TSX aliases resolve to canonical callees with `resolved_callee` recorded; other languages match written names only |
| False-positive guard | Comments and string literals cannot trigger call rules; exact matching prevents `re.compile` from matching Python `compile` |
| Secrets | 10 format-validated rules (PEM, AWS, GitHub, Slack token/webhook, Stripe, OpenAI, GitLab, PyPI, JWT) with redacted evidence, fingerprints, and documented-example negatives, over source and config files |
| Scope | Target, include/exclude globs, language filters, 1 MB default file cap, ignored dependency/build trees, no followed symlinks, oversized/unsupported/secret-only counts |
| Scheduling | Seeded shuffled file order and 600-second default budget; report marks timeout |
| Reports | Structured JSON (source v4, deps v2, web v1, diff v1) with checked-in schemas and a `validate` command, SARIF 2.1.0 for scan/web, independent confidence and scale, atomic private output |
| Baseline and diff | Stable fingerprints, `diff` comparison, `--baseline` gating on new findings, suppressions with owner/reason/expiry that never hide findings |
| Dependencies | Exact inventory from `Cargo.lock` and `package-lock.json`; recognized-but-unsupported lockfiles and per-file errors reported; CycloneDX SBOM export; exact-version matching against a user-supplied advisory snapshot (no snapshot ships) |
| Local HTTP | One authorized loopback GET, no redirects, TLS validation; XCTO/CSP/HSTS, credentialed CORS reflection, RFC-parsed cookie flags, Set-Cookie cache check, redirect-location reporting; real TCP HTTP integration tests |
| Validation | 88 debug and release tests pass; formatting, strict all-target/all-feature Clippy, release build, multi-OS CI workflow; seed-42 self-scan reports no findings and writes mode `0600` |
| Failures | Distinct scanner-error exit code; malformed scope, suppression, advisory, and baseline inputs fail closed |

## Not implemented; no coverage claimed

- Cross-function and cross-file taint/data flow (taint-lite is
  same-function only, for Python and JS/TS, and never proves
  attacker control).
- Framework-specific source, sanitizer, and sink semantics.
- Advisory ingestion pipelines and version-range semantics
  (exact-version matching against user-supplied snapshots only).
- Import resolution for languages beyond Python and JS/TS.
- Network, port, TLS-detail, API, authentication, authorization,
  or workflow probes beyond the single loopback GET.
- HTML, CSS, and SQL security semantics beyond syntax parsing.
- Fuzzing, runtime instrumentation, sandboxing, and exploit confirmation.
- Finding correlation into proven attack paths.
- Signed Core updates and reproducible release signing.
- HTML output and CI annotations.

Production release requires real implementations plus positive,
negative, regression, malformed-input, timeout, and resource-limit
tests for each item. Real CVE references in
`core/real-examples.json` are research material only; they never
create findings without matching code evidence.
