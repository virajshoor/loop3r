# loop3r implementation handoff

## Non-negotiable product rules

- One compiled CLI. No runtime dependency on nmap, browsers, proxies, AI models,
  hosted scanners, or external pentest binaries.
- Source audit works offline. Embedded parsers and Core data ship in binary or
  signed release bundle.
- Findings need code/protocol evidence. Never generate findings from CVE
  similarity, attack-chain templates, randomization, or unsupported assumptions.
- Severity measures impact. Confidence measures evidence strength. Keep them
  separate.
- Active checks require explicit scope and authorization. State-changing checks
  run only against isolated test environments with cleanup.
- “No findings” never means “secure.” Report unsupported coverage, exclusions,
  parse failures, timeouts, and skipped checks.

## Current state — all green on macOS (2026-09-17)

- Rust 2024 CLI in `src/main.rs`.
- 17 embedded Tree-sitter grammars: requested 16 languages plus separate TSX.
- Source command supports target, include/exclude globs, language filters,
  1 MB default file limit, seeded shuffled order, 600-second budget, JSON, and
  atomic Unix `0600` output.
- Symlink target rejected. Directory symlinks and common dependency/build trees
  skipped.
- 18 exact qualified-call AST rules in `core/ast-rules.json`.
- Comments and strings cannot trigger call rules.
- Every AST rule has real grammar-backed positive fixture.
- Confidence wired end to end: `review` AST rules → `low`, exact dangerous
  calls → `medium`, header/cookie observations → `high`, observed credentialed
  CORS reflection → `confirmed`; `confidence_scale` in both reports; tests
  assert per-rule confidence.
- Website command performs one read-only GET against authorized loopback URL.
  Redirects disabled. TLS uses rustls validation. Checks XCTO, CSP, HSTS,
  credentialed CORS reflection, and cookie flags.
- Real TCP loopback HTTP integration test exists; no HTTP mock.
- Gates verified: fmt check, 8 debug/release tests, strict all-target
  all-feature Clippy `-D warnings`, release build, seed-42 self-scan with
  `-rw-------` output.
- Release profile uses thin LTO, stripping, and one codegen unit.

## P1: split current single file — DONE (2026-09-18)

Behavior unchanged; code now lives in `src/language.rs`, `src/scope.rs`,
`src/report.rs`, `src/core.rs`, `src/source.rs`, `src/web.rs`, with `main.rs`
reduced to CLI/exit-code dispatch and tests. `core.rs` additionally validates
the embedded rule catalog at load (duplicate IDs, severity, CWE format,
non-empty languages/callees, HTTPS-only references). All gates re-verified:
fmt check, 8 debug/release tests, strict Clippy `-D warnings`, release build,
seed-42 self-scan with `-rw-------` output. Repo published public at
github.com/virajshoor/loop3r with no secrets in tracked files.

No generic plugin framework yet. Add abstraction only when second real
implementation needs it.

## P1: production source analysis

### Structural rule engine

- Replace generic call slicing with compiled Tree-sitter queries per grammar.
- Core rule schema must specify language, query, captures, message, CWE,
  severity, confidence policy, references, positive fixtures, negative fixtures,
  and fixed-version fixtures.
- Compile every query against its grammar at startup/build test.
- Reject duplicate IDs, unknown captures, invalid CWE, non-HTTPS references,
  unsupported severity/confidence, and rules without fixtures.
- Preserve exact node ranges and source excerpts. Redact secret values.

### Typed data flow

Build language adapters incrementally. Start Python, JavaScript/TypeScript,
Rust, C, Java, then remaining languages.

For each adapter:

- Function/method boundaries and lexical scopes.
- Definitions, uses, assignments, destructuring, parameters, returns, fields,
  closures, aliases, and call arguments.
- Control-flow graph with branches, loops, exceptions, early returns, and
  unreachable code.
- Source, propagator, sanitizer, and sink semantics tied to exact framework/API
  versions.
- Context-specific sanitizers. HTML escaping must never clear SQL/shell taint.
- Interprocedural summaries and recursion limits.
- Cross-file imports/modules and conservative unknown-call behavior.
- Path trace: source location → each propagation → sanitizer decision → sink.
- Confidence high only when complete unsanitized path exists.

Never revive file-wide “variable appeared within 200 lines” logic.

### Language-specific semantic coverage

- C: bounds, allocation arithmetic, integer conversion, lifetime/ownership,
  format strings, TOCTOU, command/process APIs.
- Rust: unsafe invariants, FFI, raw pointers, transmute, process execution,
  path handling, deserialization, crypto misuse.
- HTML: executable URL schemes, dangerous iframe/sandbox combinations,
  integrity/crossorigin configuration, unsafe inline sinks.
- CSS: insecure imports and browser-specific data-exfiltration primitives only
  where real browser behavior is documented.
- JavaScript/TypeScript: DOM XSS, prototype pollution, command/SQL/template
  injection, SSRF, redirects, path traversal, regex DoS.
- Shell: quoting, eval/source, command substitution, temp files, globbing,
  injection, unsafe curl/wget execution chains.
- Python/Java/C#/Go/PHP/Ruby/Kotlin/Swift: framework-specific request sources,
  database sinks, template sinks, serializers, filesystem, HTTP clients,
  redirects, headers, logs, LDAP/XPath, crypto/TLS.
- SQL: dialect-aware dynamic SQL, privilege grants, dangerous extensions and
  OS-command features, insecure procedure permissions.

## P1: dependency and advisory analysis

- Parse real lockfiles, not manifests alone: Cargo.lock, package-lock/pnpm/yarn,
  requirements/Poetry/uv, Maven/Gradle resolution output, go.sum, Composer.lock,
  Gemfile.lock, NuGet lock/assets, Package.resolved.
- Implement ecosystem-correct version/range comparison. Do not reuse SemVer for
  Maven, Python, Debian, or Ruby without their actual rules.
- Bundle normalized OSV/GHSA/RustSec/advisory snapshot with source attribution,
  retrieval time, checksum, withdrawals, aliases, affected ranges, and fixes.
- Match exact package ecosystem/name/version. CVE/CWE similarity alone is never
  a finding.
- Mark CISA KEV only as exploitation-priority metadata after exact match.
- Add signed, atomic Core update command with rollback and offline verification.

## P1: secrets

- Scan parser string/comment nodes and relevant config formats.
- High-confidence format validators for private keys and provider credentials.
- Entropy only supports candidates; entropy alone never creates high confidence.
- Detect placeholders/test keys and documented public examples as negatives.
- Redact values in console/report. Store fingerprint and last four characters
  only when useful.
- Never validate credentials by sending them to provider APIs by default.

## P1: website and API analysis

Current web command is loopback-only and passive. Keep that default.

### Scope model

- Scope file: exact schemes, hosts, resolved IP/CIDR, ports, path prefixes,
  methods, request budget, rate, timeout, environment, roles, and expiry.
- Revalidate every redirect and DNS resolution against scope. Defend against DNS
  rebinding and IPv4/IPv6 representation tricks.
- Remote mode needs explicit `--authorized`, exact allowlist, audit log, and
  safe defaults. Never infer permission from website content.
- POST/PUT/PATCH/DELETE disabled unless isolated environment, synthetic tenant,
  reset endpoint, and cleanup verification are configured.

### Passive/read-only probes

- TLS hostname/chain/expiry/protocol/cipher policy.
- Redirect chain and scope enforcement.
- Security headers with response-context awareness.
- Cookie parsing using RFC-compliant parser, not substring search.
- CORS preflight and credential behavior.
- Cache controls for authenticated/sensitive responses.
- `security.txt`, OpenAPI, GraphQL schema, robots, sitemap, and documented route
  discovery. Absence alone usually informational, not vulnerability.
- Exact configured TCP ports using own sockets. Open port is inventory unless
  policy marks it forbidden.

### Authenticated and stateful probes

- OpenAPI/GraphQL schema-aware request generation.
- Anonymous/user/admin differential testing.
- Object authorization/BOLA/IDOR using two synthetic accounts and owned records.
- Session rotation, fixation, expiry, logout invalidation, cookie scope.
- Password reset, MFA recovery, verification, CSRF, and rate-limit workflows.
- Harmless canary payloads for SQL/NoSQL/LDAP/template/command injection.
- Reflected/stored/DOM XSS requires browser confirmation in isolated target.
- Path traversal, archive extraction, upload type/content/path controls.
- SSRF uses owned callback service and explicit destination scope.
- Business chain: fake signup → synthetic order → owner-ID substitution →
  cross-user access. Record every request/response and clean all created state.

## P2: evidence correlation

- Correlate only concrete findings with compatible asset, route, identity,
  object, data type, and prerequisite evidence.
- Attack path must reference finding IDs and exact transitions.
- Never create Cartesian “possible combinations” from CWE labels alone.
- Distinguish observed path, statically proven path, and hypothesis.
- Cap graph depth/count and explain omitted paths.

## P2: reports and integrations

- Versioned JSON Schema.
- SARIF 2.1.0 with code flows.
- Escaped standalone HTML report.
- Baseline/diff mode with stable fingerprints.
- Suppression requires owner, reason, expiry, and scope.
- CI annotations and deterministic ordering.
- Report Core/advisory versions, binary version, seed, scope fingerprint,
  incomplete reasons, parse coverage, and unsupported languages/features.

## Robustness and optimization protocol

### Mandatory CI gates

```bash
rtk proxy cargo fmt --check
rtk proxy cargo clippy --all-targets --all-features -- -D warnings
rtk cargo test
rtk cargo test --release
rtk cargo build --release
```

### Test classes

- Every grammar: valid modern syntax, malformed syntax, huge nesting, Unicode,
  CRLF, empty file, generated code, and invalid UTF-8 bytes.
- Every rule: vulnerable real commit/fixture positive, patched commit negative,
  nearby benign code negative, comment/string negative, alias/import variants,
  malformed input, and stable location/evidence.
- Every flow rule: direct, propagated, branched, looped, sanitized, wrong-context
  sanitizer, interprocedural, recursive, and cross-file cases.
- Scope: symlinks, `..`, absolute paths, glob edge cases, case sensitivity,
  permission errors, files changing during scan, oversized files, and timeout.
- Web: real local HTTP/TLS servers, redirects, chunking, compression, duplicate
  headers, malformed headers, slowloris/timeouts, IPv4/IPv6, DNS rebinding
  simulation, large bodies, connection failure, and TLS failure. No mocks for
  protocol behavior.
- Reports: escaping, redaction, atomic replacement, permissions, deterministic
  output, schema compatibility, and interrupted write recovery.
- Exit codes: clean, findings, timeout/incomplete, invalid configuration, and
  internal failure.

### Fuzzing and memory

- No scanner-owned `unsafe` without written safety invariant and focused tests.
- Fuzz each parser entry, Core decoder, URL/scope parser, HTTP header/cookie
  parser, lockfile parser, version comparator, and report serializer.
- Run ASan/LSan on parser/HTTP integration suites where platform supports it.
- Run Miri on pure Rust modules; exclude unsupported Tree-sitter/HTTP FFI paths.
- Long soak: repeated scans and web probes; assert bounded RSS/file descriptors.
- Test cancellation/time budget while parsing many files and slow endpoints.
- Cap file count, total bytes, AST nodes, query captures, findings, path depth,
  response bytes, redirects, requests, and correlation nodes.
- Replace recursive AST walking with bounded iterative traversal; current source
  scanner already does this.

### Performance acceptance

- Define reference hardware and pinned real corpora before setting thresholds.
- Product promise: complete supported checks within 10 minutes or emit explicit
  incomplete report. Never silently drop remaining work.
- Benchmark cold/warm runs, peak RSS, files/second, LOC/second, Core load time,
  report serialization, and each language separately.
- Compare releases against stored baseline. Block regression beyond agreed
  threshold unless documented.
- Use bounded worker pool. Parser per worker; do not share non-thread-safe parser.
- Random order only improves deadline fairness. Fixed seed must reproduce order.

## Real validation corpus

Pin repository commit and checksum. Do not track moving branches.

- OWASP Juice Shop: JavaScript/TypeScript/web/API.
- OWASP WebGoat: Java/Spring.
- OWASP crAPI: API authorization/business logic.
- DVWA: PHP/web injection.
- Google Gruyere: only user-created authorized challenge instance.
- Real vulnerable and patched commits referenced by Core advisories.

Run source scans offline against checked-out commits. Run active probes only on
local disposable instances. Never probe arbitrary public vulnerable websites.

## Release checklist

- All gates green on Linux, macOS, and Windows.
- No dead Core rules; positive and patched-negative fixture for every rule.
- No unbounded network or filesystem operation.
- No secret values in logs/reports.
- Dependency licenses reviewed; lockfile committed.
- Reproducible release build and SBOM.
- Binary and Core signed; signatures verified before update/use.
- Threat model and security policy published.
- Supported coverage and known gaps match actual implementation.
- Independent security review completed before production claim.
