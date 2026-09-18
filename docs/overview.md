# Overview

loop3r audits source code and local web responses without network
dependencies, runtimes, or external scanners. One compiled binary ships
the parsers, the rule catalog, and the report writers.

## Commands

| Command | Purpose | Network |
|---|---|---|
| `scan <target>` | Parse source, match AST rules (import-aware), detect secrets in source and config files | None; fully offline |
| `deps <target>` | Inventory exact versions from `Cargo.lock` and `package-lock.json`; optional advisory matching and CycloneDX SBOM | None; fully offline |
| `web <loopback-url> --authorized` | One read-only GET; header, cookie, CORS, cache, and redirect checks | Loopback only |
| `diff <old> <new>` | Compare two scan reports by finding fingerprint | None |
| `validate <file> --schema <kind>` | Check a report against its embedded JSON schema | None |

## Product rules

These rules constrain every feature and are enforced by tests:

- One compiled CLI. No runtime dependency on external scanners,
  browsers, proxies, models, or hosted services.
- Source audit works offline. Parsers and rule data ship in the binary.
- Findings require code or protocol evidence. CVE similarity, templates,
  and guesses never create findings.
- Severity measures impact. Confidence measures evidence strength.
  They are always reported separately.
- Active checks require explicit scope and authorization. The `web`
  command refuses non-loopback targets and requires `--authorized`.
- “No findings” never means “secure.” Reports carry skip counts,
  syntax findings, timeout flags, unsupported inventories, and the
  confidence scale so gaps stay visible.
- Suppressions and baselines never delete findings. Suppressed
  findings stay in the report with their justification; baselines
  only change which findings affect the exit code.

## Maturity

Implemented and tested:

- 17 embedded Tree-sitter grammars covering 16 languages plus TSX.
- 22 exact AST-call rules with import-alias resolution and
  argument matchers for Python and JavaScript/TypeScript, each with
  real parse-tree fixtures, plus same-function taint-lite flow
  traces for those languages.
- 10 format-validated secret rules with redacted evidence, applied to
  source files and config formats (`.env`, JSON, YAML, TOML, INI, and kin).
- Lockfile inventory for Cargo and npm with explicit unsupported lists,
  exact-version advisory matching against a user-supplied snapshot,
  and CycloneDX 1.6 SBOM export. No snapshot ships with the binary.
- 8 passive loopback web checks with RFC-compliant cookie parsing and
  redirect-location reporting.
- Stable finding fingerprints, `diff` mode, `--baseline` gating, and
  suppressions with owner, reason, and expiry.
- JSON reports (source schema v4, deps schema v2, web schema v1,
  diff schema v1) with checked-in schemas in `schema/` and a
  `validate` command, plus SARIF 2.1.0 output for `scan` and `web`
  (including SARIF suppressions and taint properties).

Not implemented: cross-function taint, advisory ingestion with
version-range semantics, authenticated web probes, HTML/CSS/SQL
security semantics, finding correlation, and signed updates. See
`coverage.md` and `roadmap.md`.
