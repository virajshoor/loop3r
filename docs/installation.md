# Installation

## Prerequisites

- Rust stable toolchain with `cargo` (developed and tested with
  Rust 1.93.1).
- No runtime dependencies. The binary embeds all grammars and rules.

## Build

```bash
cargo build --release
./target/release/loop3r --help
```

The release profile uses thin LTO, symbol stripping, and a single
codegen unit. The resulting binary is approximately 29 MB on macOS.

## Verify

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --release
cargo build --release
```

Then run the self-scan gate:

```bash
./target/release/loop3r scan . --json --seed 42
```

The repository scans clean: no security findings and no secret
findings. Any finding on the loop3r codebase itself is treated as a
bug in either the code or the rule.

## Verified platforms

Linux, macOS, and Windows are release targets, but the current
verification history is macOS only. Other platforms are unsupported
until the gates above pass on them in CI.
