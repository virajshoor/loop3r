# loop3r documentation

loop3r is a self-contained, compiled source-security CLI. It parses source
with embedded Tree-sitter grammars, matches exact dangerous calls, scans
for high-confidence secrets, inventories lockfile dependencies, and runs
read-only HTTP checks against authorized loopback targets.

Every statement in these docs reflects the current implementation. If a
capability is listed under coverage gaps, the scanner does not claim it.

## Contents

- `overview.md` — what loop3r is and is not, product rules, command summary
- `installation.md` — prerequisites, build, verified platforms
- `usage.md` — `scan`, `web`, and `deps` syntax, flags, exit codes, real examples
- `rules.md` — AST, secret, and web rule catalog with severity and confidence
- `architecture.md` — modules, parsing, scope, determinism, and limits
- `reports.md` — JSON schemas, SARIF mapping, redaction, atomic output
- `coverage.md` — implemented coverage and explicit non-coverage
- `development.md` — gates, tests, and how to add rules
- `security-model.md` — trust model, authorization, and safe test targets
- `roadmap.md` — shipped items and remaining work tracker

Report JSON schemas live in `schema/` at the repository root and are
checked by the test suite; see `reports.md`.
