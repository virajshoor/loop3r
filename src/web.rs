use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use reqwest::header::{HeaderMap, HeaderName};

use crate::report::{Confidence, WebFinding, WebReport, confidence_scale};

fn header(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers.get(name)?.to_str().ok().map(str::to_owned)
}

struct CookieFlags {
    name: String,
    httponly: bool,
    secure: bool,
    samesite: bool,
}

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

    #[test]
    fn parses_cookie_attributes_case_insensitively() {
        let flags = parse_set_cookie("session=abc; httponly; SECURE; samesite=Lax").unwrap();
        assert_eq!(flags.name, "session");
        assert!(flags.httponly && flags.secure && flags.samesite);
    }

    #[test]
    fn cookie_values_cannot_fake_attributes() {
        let flags = parse_set_cookie("trick=httponly-samesite-secure; Path=/").unwrap();
        assert_eq!(flags.name, "trick");
        assert!(!flags.httponly && !flags.secure && !flags.samesite);
    }

    #[test]
    fn rejects_invalid_samesite_value() {
        let flags = parse_set_cookie("a=b; SameSite=Sometimes").unwrap();
        assert!(!flags.samesite);
    }

    #[test]
    fn accepts_quoted_samesite_and_ignores_expires() {
        let flags =
            parse_set_cookie("a=b; Expires=Wed, 21 Oct 2015 07:28:00 GMT; SameSite=\"Strict\"")
                .unwrap();
        assert!(flags.samesite);
    }

    #[test]
    fn rejects_empty_cookie_headers() {
        assert!(parse_set_cookie("").is_none());
        assert!(parse_set_cookie("   ").is_none());
        assert!(parse_set_cookie("=value").is_none());
    }
}
