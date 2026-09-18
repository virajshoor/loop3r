# Authorized test targets

Use isolated local instances. Never expose them to LAN or internet.

| Target | Official source | Local URL | Best coverage |
|---|---|---|---|
| OWASP Juice Shop | https://github.com/juice-shop/juice-shop | `http://127.0.0.1:3000` | JavaScript/TypeScript, REST, auth, XSS, injection, business logic |
| OWASP WebGoat | https://github.com/WebGoat/WebGoat | `http://127.0.0.1:8080/WebGoat` | Java/Spring, auth, injection, access control, secure-coding lessons |
| OWASP crAPI | https://github.com/OWASP/crAPI | `http://127.0.0.1:8888` | API authorization, BOLA/IDOR, mass assignment, SSRF, rate limits |
| DVWA | https://github.com/digininja/DVWA | `http://127.0.0.1:4280` | PHP, SQLi, command injection, upload, CSRF, XSS |
| Google Gruyere | https://google-gruyere.appspot.com/ | Per-user challenge instance | XSS, path traversal, auth, data tampering; test only instance created for you |

WebGoat warns host becomes vulnerable while running. DVWA warns against public
deployment. Bind to `127.0.0.1`, use disposable container/VM, keep synthetic
data, and stop/delete instance after testing.

Core can source-scan checked-out repositories offline. Live probes currently
accept loopback only. Gruyere remains source/manual validation target until
remote scopes gain signed authorization, rate cap, and explicit challenge URL.
