# Rules

loop3r ships three rule families. AST rules come from the embedded
`core/ast-rules.json` catalog and are validated at startup (duplicate
IDs, severity, CWE format, non-empty languages and callees, and
HTTPS-only references are all rejected). Secret and web rules are
compiled into the binary.

## Severity

- `high` — dangerous construct with serious impact if reachable.
- `medium` — hardening gap worth fixing (web checks only).
- `review` — security-sensitive boundary that needs human review;
  a vulnerability is not established.

## Confidence

Confidence is independent of severity and is defined in every report:

| Level | Meaning |
|---|---|
| `confirmed` | Active observation directly proves reported condition |
| `high` | Parser or protocol evidence directly proves reported construct |
| `medium` | Exact dangerous construct found; attacker reachability unproven |
| `low` | Security boundary needs review; vulnerability not established |

Mapping: AST rules with `review` severity report `low`, other AST
rules report `medium`. Secret rules report `high`. Web rules report
`high`, except observed credentialed CORS reflection, which reports
`confirmed`. Confirmed reflection proves the header behavior only; it
does not establish sensitive-data exposure or arbitrary-origin
acceptance.

## AST rules (18)

Matching is exact and structural: the callee text must equal a listed
callee after whitespace removal, and only real call nodes match, so
comments and string literals never trigger.

For Python and JavaScript/TypeScript/TSX, import aliases resolve to
canonical names before matching: `from os import system as run`
followed by `run(x)` matches `CORE-PY-SHELL` with `resolved_callee`
`os.system`, as do `require` (including destructured and renamed
forms), named `import`, and `import *` forms in JS/TS. Last binding
wins, matching runtime rebinding; default imports, wildcard imports,
and relative modules never resolve. All other languages match
written callees only, and `resolved_callee` is absent when no alias
applied.

| ID | Title | Severity | CWE | Languages | Callees |
|---|---|---|---|---|---|
| CORE-C-BOUNDS | Unbounded C string operation | high | CWE-120 | c | `gets`, `strcpy`, `strcat`, `sprintf` |
| CORE-C-SHELL | C shell command sink | review | CWE-78 | c | `system`, `popen` |
| CORE-PY-EVAL | Python dynamic code sink | high | CWE-95 | python | `eval`, `exec`, `compile` |
| CORE-PY-SHELL | Python shell command sink | review | CWE-78 | python | `os.system`, `os.popen` |
| CORE-PY-DESERIALIZE | Python object deserialization sink | high | CWE-502 | python | `pickle.load`, `pickle.loads`, `dill.load`, `dill.loads`, `yaml.load` |
| CORE-JS-EVAL | JavaScript dynamic code sink | high | CWE-95 | javascript, typescript, tsx | `eval`, `Function` |
| CORE-JS-SHELL | Node.js shell command sink | review | CWE-78 | javascript, typescript, tsx | `child_process.exec`, `child_process.execSync` |
| CORE-PHP-SHELL | PHP shell command sink | review | CWE-78 | php | `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open` |
| CORE-PHP-DESERIALIZE | PHP object deserialization sink | high | CWE-502 | php | `unserialize` |
| CORE-RB-EVAL | Ruby dynamic code sink | high | CWE-95 | ruby | `eval`, `class_eval`, `instance_eval` |
| CORE-RB-SHELL | Ruby shell command sink | review | CWE-78 | ruby | `system`, `exec`, `spawn` |
| CORE-RB-DESERIALIZE | Ruby object deserialization sink | high | CWE-502 | ruby | `Marshal.load`, `YAML.load` |
| CORE-RUST-TRANSMUTE | Rust transmute safety boundary | review | CWE-843 | rust | `transmute`, `std::mem::transmute`, `core::mem::transmute` |
| CORE-SH-EVAL | Shell eval sink | high | CWE-78 | shell | `eval` |
| CORE-JAVA-SHELL | Java process execution sink | review | CWE-78 | java, kotlin | `Runtime.getRuntime().exec` |
| CORE-CS-PROCESS | .NET process execution sink | review | CWE-78 | csharp | `Process.Start`, `System.Diagnostics.Process.Start` |
| CORE-GO-PROCESS | Go process execution boundary | review | CWE-78 | go | `exec.Command`, `exec.CommandContext` |
| CORE-SWIFT-PROCESS | Swift process execution boundary | review | CWE-78 | swift | `Process.launchedProcess` |

Every rule above has a positive fixture parsed by its real grammar in
the test suite. HTML, CSS, and SQL have grammars but no AST rules yet.

## Secret rules (3)

Secrets are detected by strict format validators over raw file bytes
in every scoped source file. There is no entropy scoring: entropy
alone never creates a finding. Evidence is always redacted; reports
carry a stable FNV-1a fingerprint and at most the last four
characters of the matched material.

| ID | Title | Severity | CWE | Format |
|---|---|---|---|---|
| SECRET-PEM-PRIVATE-KEY | Private key material in source | high | CWE-798 | `-----BEGIN … PRIVATE KEY-----` … base64 body … matching `-----END …` footer within 16 KB |
| SECRET-AWS-ACCESS-KEY | AWS access key ID in source | high | CWE-798 | `AKIA` followed by exactly 16 uppercase letters or digits, with non-alphanumeric boundaries |
| SECRET-GITHUB-TOKEN | GitHub token in source | high | CWE-798 | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` with 36+ alphanumerics, or `github_pat_` with 20+ word characters |

Documented examples are negatives: matches near `example`,
`placeholder`, `fake`, `dummy`, `sample`, or `mock` (including
inside the match, such as the AWS documentation key
`AKIAIOSFODNN7EXAMPLE`) are skipped.

Secrets run over scoped source files plus secrets-only config files,
which are never parsed: `.env`, `.env.*`, `.envrc`, and `json`,
`yaml`, `yml`, `toml`, `ini`, `cfg`, `conf`, `properties` extensions.
Config files are counted as `secret_files_scanned`, honor
include/exclude globs, and are intentionally unaffected by
`--language` filters.

## Web rules (8)

The `web` command performs one GET with redirects disabled, normal
TLS validation, and `Origin: https://loop3r.invalid`. Cookie
attributes are parsed per RFC semantics (semicolon-separated
attributes, case-insensitive keys, quoted values); cookie values can
never satisfy an attribute check.

| ID | Severity | Confidence | Trigger |
|---|---|---|---|
| WEB-XCTO | medium | high | `X-Content-Type-Options: nosniff` absent or different |
| WEB-CSP | review | high | `text/html` response without `Content-Security-Policy` |
| WEB-HSTS | medium | high | HTTPS response without `Strict-Transport-Security` |
| WEB-CORS-CREDENTIALS | high | confirmed | Test origin reflected with `Access-Control-Allow-Credentials: true` |
| WEB-COOKIE-HTTPONLY | review | high | `Set-Cookie` without the `HttpOnly` attribute |
| WEB-COOKIE-SECURE | medium | high | HTTPS `Set-Cookie` without the `Secure` attribute |
| WEB-COOKIE-SAMESITE | review | high | `Set-Cookie` without valid `SameSite=Lax/Strict/None` |
| WEB-CACHE | review | high | `Set-Cookie` present with no `Cache-Control` header at all |
