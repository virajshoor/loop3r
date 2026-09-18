# Security model

## Trust boundaries

- `scan` and `deps` are fully offline. They read files under the
  target, never follow directory symlinks, refuse symlink file
  targets, and make no network connections.
- `web` makes exactly one GET request to an explicitly authorized
  loopback URL. It never follows redirects, never sends credentials,
  and never issues state-changing methods.
- Reports may contain source excerpts (truncated AST evidence) but
  never secret values. `--output` files are created mode `0600`.

## Authorization

- `web` requires `--authorized` and a loopback host (`localhost`,
  IPv4 loopback, or IPv6 loopback). Anything else exits with code 2.
- There is no remote-scan mode. Probing non-loopback hosts, even
  intentionally vulnerable training apps, is refused until the
  scope model in `roadmap.md` (exact allowlist, audit log, rate
  caps) is implemented.

## What loop3r does not do

- It does not confirm exploitability. AST findings prove a
  dangerous call exists, not that attackers reach it. Taint-lite
  traces prove same-function data flow from a parameter or input
  call, which is weaker than attacker control.
- It does not validate credentials. Suspected secrets are reported
  from shape alone and are never sent to provider APIs.
- It does not ship advisories. `--advisory-db` matches exact
  versions against a snapshot you supply; loop3r cannot vouch for
  that snapshot's completeness or freshness.
- It does not correlate findings into attack paths.

## Baselines and suppressions

- Baselines and suppressions never delete findings. Both stay
  visible in JSON and SARIF with their justification.
- Suppressions require an owner, a reason, and an expiry, and
  expired entries are reported and ignored. Review them like code:
  an over-broad `**` glob with a distant expiry silences real
  findings from the exit code.
- Regenerate baselines from clean checkouts with the same binary
  version; a hand-edited baseline is just an unreviewed
  suppression list.

## Safe validation targets

Use isolated local instances bound to `127.0.0.1`, with disposable
containers or VMs, synthetic data, and teardown after testing. See
`SAFE_TARGETS.md` at the repository root:

- OWASP Juice Shop (`http://127.0.0.1:3000`)
- OWASP WebGoat (`http://127.0.0.1:8080/WebGoat`)
- OWASP crAPI (`http://127.0.0.1:8888`)
- DVWA (`http://127.0.0.1:4280`)
- Google Gruyere (only the challenge instance created for you;
  source and manual validation until remote scopes exist)

WebGoat warns the host becomes vulnerable while running; DVWA warns
against public deployment. Never expose these instances to a LAN or
the internet.
