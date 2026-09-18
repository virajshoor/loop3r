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
cargo test
```

Exit codes: `0` no security findings, `1` findings, `2` scanner/configuration
error. `--output` writes atomically with mode `0600` on Unix. Symlink targets
are rejected. Directory symlinks and dependency/build directories are skipped.

Core currently ships 18 exact AST-call rules. Every rule must trigger through
its real grammar fixture in CI. Comments and strings do not match. `review`
severity means dangerous boundary found without proven attacker-controlled flow.
Confidence is separate: source review boundaries are `low`, other exact dangerous
calls are `medium`, header/cookie observations are `high`, and observed credentialed
CORS reflection is `confirmed`. Reports include the confidence scale; confirmed
reflection does not establish sensitive-data exposure or arbitrary-origin acceptance.

`web <loopback-url> --authorized` performs one read-only GET with redirects disabled
and normal TLS validation. It checks XCTO, HTML CSP, HTTPS HSTS, credentialed CORS
reflection, and cookie flags. It does not test authentication or exploitability.

## Status

Parser, scoping, deadline, reporting, and AST-rule foundation are implemented.
Interprocedural taint, dependency-version analysis, secrets, network probes,
authorization workflows, HTML/CSS/SQL semantic rules, and attack correlation
are not yet production implementations. Scanner does not claim coverage for
them. See [COVERAGE.md](COVERAGE.md).

Safe intentionally vulnerable validation targets: [SAFE_TARGETS.md](SAFE_TARGETS.md).
