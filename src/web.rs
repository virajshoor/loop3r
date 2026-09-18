use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use reqwest::header::{HeaderMap, HeaderName};

use crate::report::{Confidence, WebFinding, WebReport, confidence_scale};

fn header(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers.get(name)?.to_str().ok().map(str::to_owned)
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
    for cookie in headers.get_all(reqwest::header::SET_COOKIE) {
        let Ok(cookie) = cookie.to_str() else {
            continue;
        };
        let attributes = cookie.to_ascii_lowercase();
        let name = cookie.split('=').next().unwrap_or("cookie");
        if !attributes.contains("httponly") {
            findings.push(WebFinding {
                rule_id: "WEB-COOKIE-HTTPONLY",
                severity: "review",
                message: "Set HttpOnly on session or authentication cookies.",
                evidence: format!("cookie {name} lacks HttpOnly"),
                reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie",
                confidence: Confidence::High,
            });
        }
        if url.scheme() == "https" && !attributes.contains("secure") {
            findings.push(WebFinding {
                rule_id: "WEB-COOKIE-SECURE",
                severity: "medium",
                message: "Set Secure on cookies sent by HTTPS applications.",
                evidence: format!("cookie {name} lacks Secure"),
                reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie",
                confidence: Confidence::High,
            });
        }
        if !attributes.contains("samesite") {
            findings.push(WebFinding {
                rule_id: "WEB-COOKIE-SAMESITE",
                severity: "review",
                message: "Set explicit SameSite policy on state-bearing cookies.",
                evidence: format!("cookie {name} lacks SameSite"),
                reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie",
                confidence: Confidence::High,
            });
        }
    }
    Ok(WebReport {
        schema_version: 1,
        url: url.to_string(),
        status,
        duration_ms: started.elapsed().as_millis(),
        findings,
        confidence_scale: confidence_scale(),
    })
}
