# Usage

All examples below are real output from the release binary (version
0.1.0). Commands:

```text
Usage: loop3r <COMMAND>

Commands:
  scan      Parse source with embedded grammars and report syntax coverage
  web       Run read-only HTTP checks against an authorized loopback website
  deps      Inventory exact dependency versions from lockfiles, optionally matched advisories
  diff      Compare two source scan reports by finding fingerprint
  validate  Validate a report file against its embedded JSON schema
```

## `scan`

```text
Usage: loop3r scan [OPTIONS] <TARGET>

Options:
      --max-file-bytes <MAX_FILE_BYTES>  [default: 1000000]
      --json
      --output <OUTPUT>
      --budget-seconds <BUDGET_SECONDS>  [default: 600]
      --seed <SEED>
      --include <INCLUDE>
      --exclude <EXCLUDE>
      --language <LANGUAGE>  [possible values: c, c-sharp, css, go, html,
                             java, java-script, kotlin, php, python, ruby,
                             rust, shell, sql, swift, type-script, tsx]
      --format <FORMAT>      [default: json] [possible values: json, sarif]
      --baseline <BASELINE>
      --suppress <SUPPRESS>
```

Self-scan of this repository:

```bash
./target/release/loop3r scan . --seed 42
```

```text
18 files parsed (51 secret-only scanned); 0 syntax findings; 0 security findings; 0 secret findings
skipped 0 oversized and 20 unsupported files
```

Exit code `0`. Config files (`.env`, JSON, YAML, TOML, INI, and kin)
are scanned for secrets only and counted separately; `--language`
filters never exclude them.

Import-aware matching resolves aliases before rule comparison:

```python
from os import system as run
run(user)
```

reports `CORE-PY-SHELL` with callee `run` resolved to `os.system`.
Python `import`/`from` forms, `require` (including destructuring),
and `import`/`import *` forms in JavaScript/TypeScript are covered;
other languages match written callees only.

SARIF output for CI ingestion:

```bash
./target/release/loop3r scan src --format sarif --seed 7
```

`--output` writes atomically with mode `0600` on Unix and prints the
path. Fixed `--seed` reproduces file order and therefore identical
reports.

## Baseline, suppressions, and diff

Write a baseline, then gate on new findings only:

```bash
./target/release/loop3r scan demo --output base.json --seed 7
./target/release/loop3r scan demo --baseline base.json --seed 7
```

```text
1 files parsed (0 secret-only scanned); 0 syntax findings; 2 security findings; 0 secret findings
baseline /tmp/demo-base.json: 1 new security, 0 new secrets (0 fixed)
```

Exit code is `1` because one finding is new. With no new
non-suppressed findings the exit code is `0` even when old findings
remain. Fingerprints cover rule, path, line, column, and callee
(secret content for secrets), so moves and rotations resurface.

Compare any two reports directly:

```bash
./target/release/loop3r diff base.json new.json
```

```text
+1 -0 security, +0 -0 secrets (1 unchanged)
```

Suppress with owner, reason, and expiry (all required):

```json
{"suppressions": [{"rule_id": "CORE-PY-EVAL", "path": "**/app.py",
  "reason": "demo reviewed", "owner": "docs", "expires": "2999-01-01"}]}
```

```bash
./target/release/loop3r scan demo --suppress suppress.json --seed 7
```

```text
1 files parsed (0 secret-only scanned); 0 syntax findings; 2 security findings; 0 secret findings
suppressions from /tmp/suppress-demo.json: 1 applied, 0 expired
```

Suppressed findings stay in the report with their justification and
do not affect the exit code; expired entries are listed and ignored.
Malformed suppression files fail closed with exit code `2`.

## `deps`

```text
Usage: loop3r deps [OPTIONS] <TARGET>

Options:
      --json
      --output <OUTPUT>
      --format <FORMAT>            [default: json] [possible values: json, sbom]
      --advisory-db <ADVISORY_DB>
```

```bash
./target/release/loop3r deps .
```

```text
183 packages from 1 lockfiles; 0 unsupported; 0 errors
```

CycloneDX SBOM export:

```bash
./target/release/loop3r deps . --format sbom
```

emits CycloneDX `1.6` with 183 components (first:
`pkg:cargo/aho-corasick@1.1.5`).

Exact-version advisory matching against a user-supplied snapshot
(here with two demonstration entries matching the real lockfile):

```bash
./target/release/loop3r deps . --advisory-db /tmp/snapshot-demo.json
```

```text
183 packages from 1 lockfiles; 0 unsupported; 0 errors; 2 vulnerabilities (db /tmp/snapshot-demo.json)
```

`deps` always exits `0` on success; gate on the `vulnerabilities`
array. No advisory snapshot ships with loop3r: matching is exact
`(ecosystem, package, version)` only, and version ranges are an
explicit non-goal until ecosystem version semantics are implemented.

## `web`

```text
Usage: loop3r web [OPTIONS] <URL>

Options:
      --authorized
      --timeout-seconds <TIMEOUT_SECONDS>  [default: 10]
      --json
      --output <OUTPUT>
      --format <FORMAT>  [default: json] [possible values: json, sarif]
```

Probe of a local Python static server on loopback:

```bash
./target/release/loop3r web http://127.0.0.1:8931/ --authorized
```

```text
HTTP 200; 2 findings
```

Redirects are never followed; the location is reported:

```bash
./target/release/loop3r web http://127.0.0.1:8932/ --authorized
```

```text
HTTP 301; 1 findings
redirects disabled; Location: /elsewhere
```

Any non-loopback URL, missing `--authorized`, credentialed URL, or
timeout outside 1–120 seconds exits `2` without sending a request.

## `validate`

```bash
./target/release/loop3r validate report.json --schema scan
```

```text
/tmp/demo-new.json conforms to scan schema
```

Exit `0` when the file conforms, `1` with one error per line when it
does not, `2` on I/O or JSON errors. Schemas live in `schema/`
(`scan`, `deps`, `web`, `diff`).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success; `scan`/`web` found nothing new (`deps`/`diff` always 0 on success; `validate` conforms) |
| 1 | `scan`/`web` produced at least one non-suppressed (and, with `--baseline`, new) finding; `validate` found schema errors |
| 2 | Scanner or configuration error |
