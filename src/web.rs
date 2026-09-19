//! Loopback web probe: one read-only GET plus passive header checks.
//!
//! `web` exists for local security smoke-testing (a dev server on
//! 127.0.0.1), NOT for scanning the internet: non-loopback hosts,
//! credentials in URLs, and non-HTTP(S) schemes are all refused before any
//! socket opens. The probe itself is a single GET with redirects DISABLED
//! (a 3xx `Location` is reported, sanitized, but never followed —
//! following it would issue unconsented second requests), a distinctive
//! `Origin: https://loop3r.invalid` for the CORS reflection test, and a
//! bounded timeout. Findings derive SOLELY from the status line and
//! response headers; bodies are never read, parsed, or stored.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use reqwest::header::{HeaderMap, HeaderName};

use crate::report::{Confidence, WebFinding, WebReport, confidence_scale};

/// Extracts one header value as an owned string, or `None` when absent or
/// non-UTF-8. Non-UTF-8 headers are treated as absent (no finding either
/// way) rather than erroring — a weird byte sequence is not evidence.
fn header(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers.get(name)?.to_str().ok().map(str::to_owned)
}

/// Parsed `Set-Cookie` attributes relevant to the cookie-flag rules.
/// Only the name (for evidence) and the three graded flags are kept.
struct CookieFlags {
    /// Cookie name, control-char-stripped and capped at 64 chars for
    /// evidence safety (header bytes reach reports, so they are bounded).
    name: String,
    /// Whether the `HttpOnly` attribute was present.
    httponly: bool,
    /// Whether the `Secure` attribute was present.
    secure: bool,
    /// Whether a valid `SameSite=Lax/Strict/None` attribute was present.
    samesite: bool,
}

/// Parses one `Set-Cookie` header per RFC semantics.
///
/// The first `;`-segment is ALWAYS the cookie (`name=value`) and can never
/// satisfy an attribute check — this is what stops a cookie VALUE like
/// `trick=httponly-secure` from faking flags. Remaining segments split on
/// the first `=` into case-insensitive keys with optional (possibly quoted)
/// values; `SameSite` additionally requires a valid value (`Lax`, `Strict`,
/// or `None` — `Sometimes` does not count). Empty headers, blank names, and
/// `=value` (no name) return `None` and are skipped, not findings.
fn parse_set_cookie(header: &str) -> Option<CookieFlags> {
    let mut segments = header.split(';');
    let first = segments.next()?.trim();
    if first.is_empty() {
        return None;
    }
    let raw_name = first.split('=').next().unwrap_or("cookie").trim();
    if raw_name.is_empty() {
        return None;
    }
    let name: String = raw_name
        .chars()
        .filter(|char| !char.is_control())
        .take(64)
        .collect();
    let mut flags = CookieFlags {
        name,
        httponly: false,
        secure: false,
        samesite: false,
    };
    for segment in segments {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let (key, value) = match segment.split_once('=') {
            Some((key, value)) => (key.trim(), Some(value.trim().trim_matches('"'))),
            None => (segment, None),
        };
        if key.eq_ignore_ascii_case("httponly") {
            flags.httponly = true;
        } else if key.eq_ignore_ascii_case("secure") {
            flags.secure = true;
        } else if key.eq_ignore_ascii_case("samesite")
            && value.is_some_and(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "lax" | "strict" | "none"
                )
            })
        {
            flags.samesite = true;
        }
    }
    Some(flags)
}

/// Probes one loopback URL and reports passive header/cookie observations.
///
/// Guard rails first: timeout must be 1–120s (unbounded waits hang CI; the
/// 120s ceiling matches the scan budget order of magnitude), URL must parse
/// as http/https with NO credentials, and the host must be loopback
/// (`localhost`, IPv4 127/8, or IPv6 ::1 — matched via the `url` crate's
/// typed host, not string comparison, so `localhost.evil.com` fails).
///
/// The client identifies as `loop3r/<version>` (polite scanning) and the
/// single GET carries `Origin: https://loop3r.invalid` — an unroutable test
/// origin, so any reflection of it in `Access-Control-Allow-Origin` proves
/// the server echoes arbitrary origins. Checks, in order: XCTO `nosniff`,
/// CSP on HTML responses, HSTS on HTTPS responses, credentialed CORS
/// reflection (the only `Confirmed` finding in the tool — and even it proves
/// header behaviour only, not data exposure), per-cookie HttpOnly/Secure/
/// SameSite flags, and the Set-Cookie-without-Cache-Control observation.
pub fn web_scan(raw_url: &str, timeout_seconds: u64) -> Result<WebReport> {
    if timeout_seconds == 0 || timeout_seconds > 120 {
        bail!("timeout-seconds must be between 1 and 120");
    }
    let url = url::Url::parse(raw_url).context("invalid web URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.username() != "" || url.password().is_some()
    {
        bail!("URL must use http/https and must not contain credentials");
    }
    let loopback = match url.host() {
        Some(url::Host::Domain(name)) => name == "localhost",
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    if !loopback {
        bail!("web checks currently require explicit loopback URL");
    }
    let client = reqwest::blocking::Client::builder()
        // Redirects disabled: the Location is REPORTED, never followed.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(timeout_seconds))
        .user_agent(concat!("loop3r/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building HTTP client")?;
    let started = Instant::now();
    let response = client
        .get(url.clone())
        .header(reqwest::header::ORIGIN, "https://loop3r.invalid")
        .send()
        .with_context(|| format!("GET {url}"))?;
    let status = response.status().as_u16();
    let headers = response.headers();
    let mut findings = Vec::new();
    // XCTO must be exactly `nosniff` (case-insensitive); any other value or
    // absence equally fails to stop MIME sniffing.
    if !header(headers, reqwest::header::X_CONTENT_TYPE_OPTIONS)
        .is_some_and(|value| value.eq_ignore_ascii_case("nosniff"))
    {
        findings.push(WebFinding {
            rule_id: "WEB-XCTO",
            severity: "medium",
            message: "Set X-Content-Type-Options: nosniff.",
            evidence: "header absent or not nosniff".into(),
            reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options",
            confidence: Confidence::High,
        });
    }
    // CSP is graded only for HTML responses: demanding it on JSON or images
    // would be noise, and `starts_with("text/html")` tolerates charsets.
    let html = header(headers, reqwest::header::CONTENT_TYPE)
        .is_some_and(|value| value.to_ascii_lowercase().starts_with("text/html"));
    if html && !headers.contains_key("content-security-policy") {
        findings.push(WebFinding {
            rule_id: "WEB-CSP",
            severity: "review",
            message: "Define tested Content-Security-Policy for HTML responses.",
            evidence: "HTML response without CSP".into(),
            reference: "https://developer.mozilla.org/docs/Web/HTTP/CSP",
            confidence: Confidence::High,
        });
    }
    // HSTS only applies to HTTPS responses — grading plain-HTTP loopback
    // (the common dev case) would punish the tool's own target audience.
    if url.scheme() == "https" && !headers.contains_key(reqwest::header::STRICT_TRANSPORT_SECURITY)
    {
        findings.push(WebFinding {
            rule_id: "WEB-HSTS",
            severity: "medium",
            message: "Set Strict-Transport-Security after confirming HTTPS-only operation.",
            evidence: "HTTPS response without HSTS".into(),
            reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
            confidence: Confidence::High,
        });
    }
    // Credentialed CORS reflection: BOTH the exact test origin echoed back
    // AND `Allow-Credentials: true` are required. Note the origin comparison
    // is case-SENSITIVE (origins are exact) while the boolean is not.
    let reflected_origin = header(headers, reqwest::header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_some_and(|value| value == "https://loop3r.invalid");
    let credentials = header(headers, reqwest::header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    if reflected_origin && credentials {
        findings.push(WebFinding {
            rule_id: "WEB-CORS-CREDENTIALS",
            severity: "high",
            message: "Do not reflect arbitrary Origin while allowing credentials.",
            evidence: "test Origin reflected with Access-Control-Allow-Credentials: true".into(),
            reference: "https://cwe.mitre.org/data/definitions/942.html",
            confidence: Confidence::Confirmed,
        });
    }
    // Every Set-Cookie is graded independently (one cookie's flags say
    // nothing about another's); unparseable headers are skipped, and the
    // `Secure` rule only applies to HTTPS responses.
    let mut saw_cookie = false;
    for cookie in headers.get_all(reqwest::header::SET_COOKIE) {
        let Ok(cookie) = cookie.to_str() else {
            continue;
        };
        let Some(flags) = parse_set_cookie(cookie) else {
            continue;
        };
        saw_cookie = true;
        if !flags.httponly {
            findings.push(WebFinding {
                rule_id: "WEB-COOKIE-HTTPONLY",
                severity: "review",
                message: "Set HttpOnly on session or authentication cookies.",
                evidence: format!("cookie {} lacks HttpOnly", flags.name),
                reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie",
                confidence: Confidence::High,
            });
        }
        if url.scheme() == "https" && !flags.secure {
            findings.push(WebFinding {
                rule_id: "WEB-COOKIE-SECURE",
                severity: "medium",
                message: "Set Secure on cookies sent by HTTPS applications.",
                evidence: format!("cookie {} lacks Secure", flags.name),
                reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie",
                confidence: Confidence::High,
            });
        }
        if !flags.samesite {
            findings.push(WebFinding {
                rule_id: "WEB-COOKIE-SAMESITE",
                severity: "review",
                message: "Set explicit SameSite policy on state-bearing cookies.",
                evidence: format!("cookie {} lacks valid SameSite", flags.name),
                reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie",
                confidence: Confidence::High,
            });
        }
    }
    // Responses that set cookies without ANY Cache-Control risk storing
    // authenticated content in shared caches.
    if saw_cookie && !headers.contains_key(reqwest::header::CACHE_CONTROL) {
        findings.push(WebFinding {
            rule_id: "WEB-CACHE",
            severity: "review",
            message: "Send Cache-Control with Set-Cookie responses; use no-store for authenticated content.",
            evidence: "Set-Cookie without Cache-Control".into(),
            reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Cache-Control",
            confidence: Confidence::High,
        });
    }
    Ok(WebReport {
        schema_version: 1,
        url: url.to_string(),
        status,
        duration_ms: started.elapsed().as_millis(),
        // 3xx Location is sanitized (control chars stripped, 200-char cap —
        // header bytes are attacker-influenced) and reported, never followed.
        redirect: if (300..400).contains(&status) {
            header(headers, reqwest::header::LOCATION).map(|location| {
                location
                    .chars()
                    .filter(|char| !char.is_control())
                    .take(200)
                    .collect()
            })
        } else {
            None
        },
        findings,
        confidence_scale: confidence_scale(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Flag keys match case-insensitively and `SameSite=Lax` validates.
    #[test]
    fn parses_cookie_attributes_case_insensitively() {
        let flags = parse_set_cookie("session=abc; httponly; SECURE; samesite=Lax").unwrap();
        assert_eq!(flags.name, "session");
        assert!(flags.httponly && flags.secure && flags.samesite);
    }

    /// Attribute-looking text inside the cookie VALUE cannot set flags —
    /// the anti-spoofing test for the first-segment rule.
    #[test]
    fn cookie_values_cannot_fake_attributes() {
        let flags = parse_set_cookie("trick=httponly-samesite-secure; Path=/").unwrap();
        assert_eq!(flags.name, "trick");
        assert!(!flags.httponly && !flags.secure && !flags.samesite);
    }

    /// Unknown `SameSite` values are treated as absent, not as a pass.
    #[test]
    fn rejects_invalid_samesite_value() {
        let flags = parse_set_cookie("a=b; SameSite=Sometimes").unwrap();
        assert!(!flags.samesite);
    }

    /// Quoted `SameSite` values unwrap correctly, and unrelated attributes
    /// with commas (`Expires=Wed, 21 Oct …`) do not confuse the parser.
    #[test]
    fn accepts_quoted_samesite_and_ignores_expires() {
        let flags =
            parse_set_cookie("a=b; Expires=Wed, 21 Oct 2015 07:28:00 GMT; SameSite=\"Strict\"")
                .unwrap();
        assert!(flags.samesite);
    }

    /// Empty, blank, and nameless cookie headers are skipped (`None`), not
    /// findings and not panics.
    #[test]
    fn rejects_empty_cookie_headers() {
        assert!(parse_set_cookie("").is_none());
        assert!(parse_set_cookie("   ").is_none());
        assert!(parse_set_cookie("=value").is_none());
    }
}
