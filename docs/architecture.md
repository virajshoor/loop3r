# Architecture

## Modules

| Module | Responsibility |
|---|---|
| `main.rs` | CLI parsing, subcommand dispatch, exit codes, integration tests |
| `language.rs` | `LanguageId` enum, embedded Tree-sitter grammars, extension mapping |
| `scope.rs` | Include/exclude globs, language filters, file discovery, skip counts |
| `core.rs` | Embedded AST rule catalog loading and validation |
| `source.rs` | Parse loop, AST inspection, secrets fan-out, report assembly |
| `imports.rs` | Import-alias collection and callee resolution (Python, JS/TS) |
| `secrets.rs` | Byte-oriented secret validators, redaction, fingerprints |
| `deps.rs` | Lockfile discovery and inventory parsers |
| `advisory.rs` | Exact-version advisory matching against a supplied snapshot |
| `sbom.rs` | CycloneDX SBOM mapping for dependency inventory |
| `web.rs` | Loopback HTTP probe and header/cookie checks |
| `report.rs` | Finding structs, confidence scale, private atomic writer |
| `sarif.rs` | SARIF 2.1.0 mapping for source and web reports |
| `fingerprint.rs` | Stable finding fingerprints for diff and baseline |
| `diff.rs` | Tolerant report loading, `diff` comparison, baseline gating |
| `suppress.rs` | Suppression file loading, expiry, and matching |
| `schema.rs` | Embedded JSON schemas and report conformance checking |

`main.rs` only dispatches; all analysis lives in the other modules.
There are no import cycles.

## Source scanning pipeline

1. Validate flags (`--budget-seconds` and `--max-file-bytes` must be
   positive) and build the scope from include/exclude globs plus
   language filters.
2. Discover files: walk the target without following symlinks, skip
   `.git`, `.hg`, `.svn`, `node_modules`, `target`, `vendor`, and
   `.venv`, count oversized and unsupported files, and split supported
   files into parsed sources and secrets-only configs (see below).
3. Shuffle parsed-file order with a seeded xorshift PRNG so deadline
   expiry degrades fairly; a fixed `--seed` reproduces the order exactly.
4. For each file within budget: read bytes, run secret validators on
   the raw bytes, parse with the language grammar, collect import
   aliases, and walk the tree iteratively (no recursion) collecting
   syntax errors and exact-call matches against resolved callees.
5. Scan secrets-only files for secrets without parsing.
6. Apply suppressions, then the baseline summary, when requested.
7. Sort every finding list deterministically by path, line, and rule
   so output is stable regardless of shuffle order.
8. Render JSON or SARIF to stdout, or atomically to `--output`.

Discovery details:

- A file target that is a symlink is refused. Directory symlinks are
  never followed.
- A single oversized or unsupported file target fails closed with
  exit code 2. During directory walks, oversized and unsupported
  files are counted in `files_skipped_oversized` and
  `files_skipped_unsupported` instead of failing the scan.
- Supported source extensions: `c`, `h`, `cs`, `css`, `go`, `htm`,
  `html`, `java`, `js`, `jsx`, `kt`, `kts`, `php`, `py`, `rb`, `rs`,
  `sh`, `sql`, `swift`, `ts`, `tsx`.
- Secrets-only files: `.env`, `.env.*`, `.envrc`, plus `json`,
  `yaml`, `yml`, `toml`, `ini`, `cfg`, `conf`, `properties`. They
  honor include/exclude globs but ignore `--language` filters, are
  never parsed, and are counted as `secret_files_scanned`.

## Call matching

`is_call` maps each language to its Tree-sitter call node kinds
(for example `call`, `call_expression`, `method_invocation`,
`invocation_expression`, and shell `command`). The callee is the
source slice before the argument list (or the shell command name).

For Python, `import x as y` and `from m import n [as a]` bindings
resolve the call head to its canonical dotted path. For
JavaScript/TypeScript/TSX, `require` (plain, destructured, renamed),
named `import`, and `import *` bindings resolve likewise. Last
binding wins, matching runtime rebinding; default imports, wildcard
imports, and relative modules never resolve. The written callee stays
in `callee`; the canonical form appears in `resolved_callee` only
when an alias applied.

Matching is exact after whitespace removal: the canonical callee must
equal a rule callee. Shell, HTML, CSS, and SQL have no sink semantics
beyond this: HTML/CSS/SQL parse for syntax coverage only.

Evidence is the matched node text truncated to 160 characters.

## Secrets

Secret validators scan raw bytes, so they work even when a file does
not parse. PEM blocks require a `PRIVATE KEY` header and matching
footer within 16 KB with a base64-only body. AWS and GitHub patterns
require strict lengths and token boundaries. Any match near a
documentation marker (`example`, `placeholder`, `fake`, `dummy`,
`sample`, `mock`) is treated as a negative. Findings store a
redacted summary plus an FNV-1a fingerprint, never the secret.

## Fingerprints, baseline, and suppressions

- Security fingerprints hash rule, path, line, column, and callee;
  secret fingerprints hash rule, path, line, column, and the secret
  content fingerprint, so rotation resurfaces.
- `diff` loads two reports tolerantly (any schema version with
  finding lists) and partitions findings into added, fixed, and
  unchanged by fingerprint.
- `--baseline` records new/fixed counts in the report and gates the
  exit code on new non-suppressed findings only.
- `--suppress` loads entries of rule, path glob, reason, owner, and
  `YYYY-MM-DD` expiry. All fields are required; bad globs, dates, or
  JSON fail closed. Paths match against the stored path and the
  target-relative path. Matches attach their justification to the
  finding; expired entries are listed and ignored. Suppressed
  findings never affect the exit code but stay in the report and in
  SARIF (as `suppressions` with kind `external`).

## Dependencies and advisories

`deps` walks the target with the same ignored-directory rules and
collects `Cargo.lock` (parsed with a minimal `[[package]]` reader
for name, version, and source) and `package-lock.json` (v1
`dependencies` and v2/v3 `packages`, skipping the root, links, and
version-less entries). Recognized but unparsed lockfiles
(`pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `Pipfile.lock`,
`Gemfile.lock`, `composer.lock`, `go.sum`, `Package.resolved`,
`packages.lock.json`, `gradle.lockfile`) are listed under
`unsupported`. Malformed lockfiles are recorded per file under
`errors` during directory walks, or fail the command when passed as
a direct target. Lockfiles over 32 MB are refused.

`--advisory-db` loads a versioned snapshot
(`format_version: 1`, advisories with id, cargo/npm ecosystem,
package, exact `vulnerable_versions`, low/medium/high/critical
severity, summary, and HTTPS reference) and reports exact
`(ecosystem, package, version)` matches. There is no range
evaluation and no bundled snapshot. `--format sbom` renders the
inventory as CycloneDX 1.6 with package URLs.

## Web probing

`web` validates the URL (http/https, no credentials, loopback host:
`localhost`, IPv4 loopback, or IPv6 loopback), builds a blocking
client with redirects disabled and rustls TLS validation, and sends
one GET with `Origin: https://loop3r.invalid`. Findings derive
solely from the status line and response headers of that single
response; a 3xx `Location` is reported (truncated, control
characters stripped) but never followed. No second request,
preflight, body parsing, or credential submission exists.

## Determinism and limits

- Fixed `--seed` reproduces file order; all finding lists are
  sorted, so identical inputs produce identical reports.
- Default 1 MB per-file cap, 600-second budget (the report marks
  `timed_out` instead of silently dropping work), 16 KB PEM window,
  32 MB lockfile cap, 160-character AST evidence.
- Timeouts and skips are reported, never hidden.
