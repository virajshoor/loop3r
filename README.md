# loop3r

Self-contained compiled source-security CLI. Core embeds real Tree-sitter
grammars for Rust, C, HTML, CSS, JavaScript/JSX, TypeScript/TSX, shell, Python,
Java, C#, Go, PHP, Ruby, Kotlin, Swift, and SQL.

```bash
cargo build --release
./target/release/loop3r scan /path/to/repository
./target/release/loop3r scan . --json --seed 42
./target/release/loop3r scan . --output report.json --include 'src/**' --exclude 'src/generated/**'
./target/release/loop3r scan . --language rust --budget-seconds 600
./target/release/loop3r scan . --format sarif --seed 42
./target/release/loop3r scan . --baseline base.json --suppress suppress.json
./target/release/loop3r diff base.json report.json
./target/release/loop3r validate report.json --schema scan
./target/release/loop3r deps . --json
./target/release/loop3r deps . --format sbom --advisory-db snapshot.json
./target/release/loop3r web http://127.0.0.1:3000 --authorized
cargo test
```

Full documentation lives in [docs/](docs/README.md). Report schemas
live in [schema/](schema/scan-v3.schema.json).

Exit codes: `0` no gated findings (`deps`/`diff` always `0` on
success), `1` findings or schema errors, `2` scanner/configuration
error. `--output` writes atomically with mode `0600` on Unix. Symlink
targets are rejected. Directory symlinks and dependency/build
directories are skipped; oversized, unsupported, and secret-only files
are counted in the report.

Core currently ships 18 exact AST-call rules with import-alias
resolution for Python and JavaScript/TypeScript, 3 format-validated
secret rules with redacted evidence over source and config files,
exact lockfile inventory for Cargo and npm with optional
exact-version advisory matching and SBOM export, and 8 passive
loopback web checks. Every AST rule must trigger through its real
grammar fixture in CI. Comments and strings do not match. `review`
severity means dangerous boundary found without proven
attacker-controlled flow. Confidence is separate: source review
boundaries are `low`, other exact dangerous calls are `medium`,
secrets and header/cookie observations are `high`, and observed
credentialed CORS reflection is `confirmed`. Reports include the
confidence scale; confirmed reflection does not establish
sensitive-data exposure or arbitrary-origin acceptance.

`web <loopback-url> --authorized` performs one read-only GET with redirects disabled
and normal TLS validation. It checks XCTO, HTML CSP, HTTPS HSTS, credentialed CORS
reflection, RFC-parsed cookie flags, and Set-Cookie cache controls, and reports
redirect locations without following them. It does not test authentication or
exploitability. `deps` reports exact installed versions with optional advisory
matching against a snapshot you supply; no snapshot ships with the binary.

## Status

Parser, import-aware matching, scoping, deadline, reporting, secrets
redaction, dependency inventory, SBOM, advisory matching, baseline,
diff, suppressions, SARIF output, schemas, and AST-rule foundation are
implemented. Interprocedural taint, advisory ingestion with range
semantics, network probes, authorization workflows, HTML/CSS/SQL
semantic rules, and attack correlation are not yet production
implementations. Scanner does not claim coverage for them. See
[COVERAGE.md](COVERAGE.md).

Safe intentionally vulnerable validation targets: [SAFE_TARGETS.md](SAFE_TARGETS.md).
