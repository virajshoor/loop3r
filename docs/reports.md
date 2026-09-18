# Reports

## Formats

- `scan` and `web` emit pretty-printed JSON by default (`--json` to
  stdout, `--output` to a file) or SARIF 2.1.0 with
  `--format sarif`.
- `deps` emits JSON inventory only, or CycloneDX 1.6 SBOM with
  `--format sbom`.
- `diff` emits its JSON comparison; `validate` checks any report
  against the checked-in schemas in `schema/`.
- Without machine-output flags, commands print a one-line human
  summary plus baseline, suppression, skip, or redirect lines when
  applicable.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success; for `scan`/`web`, no non-suppressed findings (with `--baseline`, none new); `deps`/`diff` always 0 on success; `validate` conforms |
| 1 | `scan`/`web` produced at least one gated finding; `validate` found schema errors |
| 2 | Scanner or configuration error (bad flags, unreadable input, failed probe, malformed suppression/advisory/baseline file) |

## Source report (schema v3)

Top-level fields:

| Field | Contents |
|---|---|
| `schema_version` | `3` |
| `files_parsed` | Files parsed before the budget expired |
| `secret_files_scanned` | Config files scanned for secrets without parsing |
| `files_skipped_oversized` | Files over `--max-file-bytes` (directory walks) |
| `files_skipped_unsupported` | Files with unrecognized extensions (directory walks) |
| `languages` | Per-language parsed-file counts |
| `syntax_findings` | Grammar error/missing nodes with path, language, line, column, node kind |
| `security_findings` | AST matches with rule, severity, CWE, location, callee, optional `resolved_callee`, evidence, message, references, confidence, optional suppression |
| `secret_findings` | Secret matches with rule, severity, CWE, location, redacted evidence, fingerprint, message, reference, confidence, optional suppression |
| `timed_out` | True when the budget expired before all files were scanned |
| `seed` | Shuffle seed used for file order |
| `scope` | Target, caps, budget, include/exclude patterns, language filters |
| `baseline` | Null, or path plus new/fixed security/secret counts |
| `suppressions` | Suppression file, applied count, expired entry identifiers |
| `confidence_scale` | Definitions of `confirmed`, `high`, `medium`, `low` |

All three finding lists are sorted by path, then line, then rule ID.
Schema: `schema/scan-v3.schema.json`.

## Dependency report (schema v2)

| Field | Contents |
|---|---|
| `schema_version` | `2` |
| `target` | Scanned path |
| `lockfiles` | Successfully parsed lockfiles |
| `packages` | Sorted `{ecosystem, name, version, source, lockfile}` entries |
| `unsupported` | Recognized lockfiles with no parser yet |
| `errors` | Per-lockfile parse failures with messages |
| `advisory_db` | Snapshot path, or null when not supplied |
| `vulnerabilities` | Exact matches with advisory, package, severity, summary, reference, lockfile |

Ecosystems are `cargo` (with registry `source` when present) and
`npm` (no source). Matching is exact version only. Schema:
`schema/deps-v2.schema.json`.

## Web report (schema v1)

| Field | Contents |
|---|---|
| `schema_version` | `1` |
| `url` | Normalized request URL |
| `status` | HTTP status of the single response |
| `duration_ms` | Request round-trip time |
| `redirect` | 3xx `Location`, truncated and sanitized, or null |
| `findings` | Rule, severity, message, evidence, reference, confidence |
| `confidence_scale` | Definitions of `confirmed`, `high`, `medium`, `low` |

Schema: `schema/web-v1.schema.json`.

## Diff report (schema v1)

| Field | Contents |
|---|---|
| `schema_version` | `1` |
| `old`, `new` | Compared report paths |
| `added_security`, `fixed_security` | Full finding objects by fingerprint |
| `added_secrets`, `fixed_secrets` | Full finding objects by fingerprint |
| `unchanged_security`, `unchanged_secrets` | Counts |

Inputs load tolerantly across schema versions. Schema:
`schema/diff-v1.schema.json`.

## SARIF 2.1.0

`--format sarif` maps findings onto SARIF runs:

- `$schema` is the schemastore SARIF 2.1.0 schema; `version` is
  `2.1.0`; the driver is `loop3r` with the binary version.
- Severity maps to levels: `high` → `error`, `medium` →
  `warning`, anything else → `note`.
- Source results carry file URI plus start line/column; web results
  carry the request URL without a region.
- Rule metadata is built from rules that actually fired (AST rule
  title/message plus first reference; secret rule data; web rule
  data). Syntax diagnostics use the synthetic rule
  `LOOP3R-SYNTAX` at `note` level.
- Properties preserve `cwe`, `confidence`, `severity`, `evidence`
  (redacted for secrets), plus `callee`, `resolvedCallee`,
  `fingerprint`, or `language` where applicable.
- Suppressed findings carry `suppressions` with kind `external`
  and the reason, owner, and expiry as justification.
- No code flows are emitted: loop3r has no taint engine, so
  multi-hop flows would be fabricated.

## Redaction and output safety

- Secret values never appear in console output or reports; only
  redacted shapes, fingerprints, and trailing characters.
- `--output` writes to a uniquely named temporary file with mode
  `0600` on Unix, fsyncs, and renames atomically. Interrupted
  writes leave either the old file or nothing, never a partial
  report.
