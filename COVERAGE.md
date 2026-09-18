# Coverage

## Implemented and verified

| Area | Evidence |
|---|---|
| Parsers | 17 embedded Tree-sitter grammars covering 16 requested languages plus TSX |
| AST rules | 18 exact qualified-call rules; each has positive real-parse-tree fixture |
| False-positive guard | Comments and string literals cannot trigger call rules; exact matching prevents `re.compile` from matching Python `compile` |
| Scope | Target, include/exclude globs, language filters, 1 MB default file cap, ignored dependency/build trees, no followed symlinks |
| Scheduling | Seeded shuffled file order and 600-second default budget; report marks timeout |
| Reports | Structured JSON, source location/evidence/CWE/reference, independent confidence and scale, atomic private output |
| Local HTTP | One authorized loopback GET, no redirects, TLS validation; XCTO/CSP/HSTS, credentialed CORS reflection, cookie flags; real TCP HTTP integration test |
| Validation | 8 debug and release tests pass; formatting, strict all-target/all-feature Clippy, release build pass on macOS; seed-42 self-scan reports no findings and writes mode `0600` |
| Failures | Distinct scanner-error exit code; malformed scope and unreadable inputs fail closed |

## Not implemented; no coverage claimed

- Cross-function and cross-file taint/data flow.
- Framework-specific source, sanitizer, and sink semantics.
- Dependency lockfile parsing and affected-version evaluation.
- Secret detection with entropy, format validation, and redaction.
- Network, port, TLS, HTTP, API, authentication, authorization, or workflow probes.
- HTML, CSS, and SQL security semantics beyond syntax parsing.
- Fuzzing, runtime instrumentation, sandboxing, and exploit confirmation.
- Finding correlation into proven attack paths.
- Signed Core updates, advisory ingestion, suppression lifecycle, baseline/diff mode.
- SARIF/HTML output, SBOM, CI annotations, and reproducible release signing.

Production release requires real implementations plus positive, negative,
regression, malformed-input, timeout, and resource-limit tests for each item.
Real CVE references in `core/real-examples.json` are research material only;
they never create findings without matching code evidence.
