# Roadmap

This file is the authoritative remaining-work tracker. It replaces the
former `NEXT.md` handoff (deleted 2026-09-18 after its shipped items
were implemented and documented).

## Shipped

- Single-file split into focused modules.
- Confidence wired end to end with per-report scales.
- Secrets detection with format validators and redaction, over
  source and config files.
- Dependency inventory for `Cargo.lock` and `package-lock.json`,
  CycloneDX SBOM export, and exact-version advisory matching
  against user-supplied snapshots.
- SARIF 2.1.0 output for `scan` and `web`, including suppressions.
- Deterministic finding order and skip/unsupported/secret-only counts.
- RFC-compliant cookie parsing, Set-Cookie cache check, and
  redirect-location reporting.
- Import-alias resolution for Python and JavaScript/TypeScript.
- Stable fingerprints, `diff` mode, `--baseline` gating, and
  suppressions with owner, reason, and expiry.
- Checked-in JSON schemas with conformance tests and a `validate`
  command.
- Multi-OS CI workflow (Ubuntu, macOS, Windows).

## P1: production source analysis

- Structural rule engine: compiled Tree-sitter queries per grammar,
  with fixture-backed schema validation.
- Import resolution for remaining languages (Java, C#, Go, Rust,
  Ruby, PHP, and the rest).
- Typed data flow per language adapter (scopes, CFG, sources,
  propagators, context-specific sanitizers, interprocedural
  summaries, cross-file imports, path traces).
- Language-specific semantic coverage: C bounds/lifetime, Rust
  unsafe/FFI, HTML executable schemes, JS/TS injection families,
  shell quoting, framework request/database/template sinks, and
  dialect-aware SQL.

## P1: dependencies and secrets

- Advisory ingestion (OSV/GHSA/RustSec) with attribution, checksums,
  withdrawals, and ecosystem-correct version-range semantics; KEV as
  priority metadata only; signed atomic snapshot updates with rollback.
- More provider secret validators and AST string/comment-node
  targeting.

## P1: website and API analysis

- Scope files with exact hosts, CIDRs, ports, paths, methods,
  budgets, and expiry; redirect/DNS revalidation.
- Passive probes: TLS detail, redirect chains, context-aware
  headers, preflight CORS, security.txt/OpenAPI/GraphQL discovery,
  exact-port inventory.
- Authenticated and stateful probes against isolated synthetic
  tenants only: differential roles, BOLA/IDOR with two accounts,
  session lifecycle, injection canaries, upload/traversal controls,
  owned-callback SSRF, and full cleanup.

## P2 and hardening

- Evidence correlation restricted to compatible concrete findings.
- HTML reports and CI annotations.
- Fuzzing of parsers and protocol handling, ASan/LSan and Miri
  where supported, soak tests, bounded everything, and the
  10-minute-or-explicit-incomplete performance promise.
- Release checklist: all platforms green, fixture-complete rules,
  no unbounded operations, no secret leakage, licensed and signed
  reproducible builds with SBOM, published threat model, and
  independent review.
