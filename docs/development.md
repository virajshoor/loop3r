# Development

## Mandatory gates

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --release
cargo build --release
```

All five must pass before merging. After modifying code, refresh the
knowledge graph (AST-only, no API cost):

```bash
graphify update .
```

`.github/workflows/ci.yml` runs the same gates plus a seed-42
self-scan on Ubuntu, macOS, and Windows for every push and pull
request.

## Test layout

- `src/main.rs` holds cross-module integration tests: every grammar
  parses real syntax, call rules ignore comments/strings,
  language-specific structural matches, import-alias resolution with
  negatives, every AST rule fires on a real fixture with correct
  confidence, filesystem scope with private output, secrets redaction,
  dependency inventory, skip counts, baseline/diff/suppression flows,
  and real TCP loopback probes (no HTTP mocks).
- Focused unit tests live with their modules (`imports`, `secrets`,
  `deps`, `advisory`, `sbom`, `sarif`, `diff`, `suppress`, `schema`,
  `web`, `fingerprint`), including malformed and truncated inputs.
- `src/schema.rs` checks every checked-in JSON schema against a real
  generated report, so schema drift fails the suite.
- Fixture secrets are format-valid but fictitious (for example an
  `AKIA` ID built from repeated `Z`), and AWS/GitHub documentation
  examples are asserted as negatives.

## Adding an AST rule

1. Add the rule to `core/ast-rules.json` with a unique ID, title,
   `high` or `review` severity, `CWE-NNN` code, non-empty language
   list, non-empty callee list, remediation message, and HTTPS
   references.
2. Confirm the callee spelling against the real Tree-sitter node
   text for that language (check `callee()` and `is_call()` in
   `src/source.rs`).
3. Add a positive fixture to
   `every_ast_rule_has_a_real_parse_tree_fixture` and, for new
   languages or call shapes, to
   `language_specific_calls_are_structural`.
4. Add a negative case where confusion is plausible (comment/string,
   similarly named callee such as `re.compile` vs `compile`).
5. Update `docs/rules.md` and the rule count in `README.md`.

Rules without real-grammar fixtures are rejected by convention and
by review, not just by tests.

## Adding a secret validator

1. Implement a byte-oriented scanner in `src/secrets.rs` with strict
   boundaries and lengths; never match on entropy.
2. Redact evidence (shape plus at most four trailing characters),
   store an FNV-1a fingerprint, and set confidence to `high`.
3. Add positives built programmatically (never commit literal
   secrets, even fake-looking ones), negatives for documented
   examples, and truncation/binary edge cases.
4. Re-run the seed-42 self-scan: the scanner must not flag its own
   source.

## Conventions

- No scanner-owned `unsafe` without a written safety invariant.
- No panics on untrusted input: walk trees iteratively, bound every
  search window, and handle invalid UTF-8.
- Findings sort by path, line, and rule ID; reports stay
  deterministic under a fixed seed.
- Docs describe implemented behavior only. Update `docs/` and the
  root `COVERAGE.md` alongside code changes.
