//! Secret detection: strict format validators over raw file bytes.
//!
//! Ten rules (PEM keys, AWS, GitHub, Slack token/webhook, Stripe, OpenAI,
//! GitLab, PyPI, JWT) scan bytes directly — no parsing, no regex engine, no
//! entropy scoring. Byte scanning means secrets are found even in files that
//! fail to parse, and format strictness (exact prefixes, lengths, token
//! boundaries) is what keeps false positives near zero without ever scoring
//! randomness.
//!
//! Three invariants hold for every rule:
//! 1. Evidence is ALWAYS redacted (shape + at most 4 trailing chars). Tests
//!    assert the full secret never appears in serialized output.
//! 2. Documented examples are negatives: matches near `example`,
//!    `placeholder`, `fake`, `dummy`, `sample`, or `mock` are skipped, so
//!    docs and test fixtures do not self-report.
//! 3. Scanners are total over bytes: truncated, empty, and binary inputs
//!    return no findings instead of panicking (all arithmetic saturates,
//!    all slicing is bounds-checked).

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::report::Confidence;

/// One validated secret match with redacted evidence.
///
/// Rule metadata is `&'static str` (compiled into the binary, not loaded from
/// a catalog), while path/evidence/fingerprint are owned per finding.
#[derive(Debug, Serialize)]
pub struct SecretFinding {
    /// Secret rule ID, e.g. `SECRET-AWS-ACCESS-KEY`.
    pub rule_id: &'static str,
    /// Human title.
    pub title: &'static str,
    /// Always `high`: leaked credentials are direct impact.
    pub severity: &'static str,
    /// Always `CWE-798` (hardcoded credentials).
    pub cwe: &'static str,
    /// File containing the match.
    pub path: PathBuf,
    /// 1-based line of the match start.
    pub line: usize,
    /// 1-based column of the match start (byte-based, not grapheme-based).
    pub column: usize,
    /// Redacted shape (`AKIA[redacted]ZZZZ`): prefix + tail only. The full
    /// secret MUST never appear here — tests enforce this per rule.
    pub evidence: String,
    /// FNV-1a hash of the matched bytes: stable correlation ID that doubles
    /// as the fingerprint input so rotation changes identity.
    pub fingerprint: String,
    /// Remediation guidance (revoke, remove from history, use a manager).
    pub message: &'static str,
    /// Supporting reference.
    pub reference: &'static str,
    /// Always `High`: the byte pattern directly proves the construct.
    pub confidence: Confidence,
    /// Justification attached when a suppression entry matched.
    pub suppressed: Option<crate::report::SuppressedBy>,
}

/// Case-insensitive markers that turn a match into a documented example.
///
/// Checked in a radius around (and inside) every candidate match, so both
/// `# EXAMPLE key` comments and embedded words like `...EXAMPLE` in the AWS
/// documentation key suppress the finding.
const DENY_WORDS: [&[u8]; 6] = [
    b"example",
    b"placeholder",
    b"fake",
    b"dummy",
    b"sample",
    b"mock",
];

/// PEM block delimiters. The header/footer marks locate candidates; `PEM_KIND`
/// restricts matches to private keys (public keys and certificates are not
/// secrets and must not report).
const PEM_HEADER_MARK: &[u8] = b"-----BEGIN ";
const PEM_FOOTER_MARK: &[u8] = b"-----END ";
const PEM_KIND: &[u8] = b"PRIVATE KEY-----";
/// Maximum header→footer span (16 KB): bounds the search on files with a
/// header but no nearby footer, and matches real key sizes.
const PEM_MAX_BLOCK: usize = 16 * 1024;

/// Byte-substring search starting at `from`, returning the absolute offset.
///
/// Hand-rolled instead of `memchr`/regex to keep the dependency tree small;
/// a simple `windows().position()` scan is fast enough at these sizes.
fn find_from(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|relative| from + relative)
}

/// Converts a byte offset to 1-based (line, column) by counting newlines.
///
/// Columns count bytes, not characters: matches are ASCII token patterns, so
/// byte columns equal what editors show for these findings. Offsets past the
/// end are clamped rather than panicking.
fn line_col(bytes: &[u8], offset: usize) -> (usize, usize) {
    let end = offset.min(bytes.len());
    let mut line = 1_usize;
    let mut column = 1_usize;
    for byte in &bytes[..end] {
        if *byte == b'\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

/// Extracts the byte window around a candidate match for deny-word checking.
/// Saturating arithmetic keeps truncated inputs safe.
fn context(bytes: &[u8], start: usize, end: usize, radius: usize) -> &[u8] {
    let from = start.saturating_sub(radius);
    let to = end.saturating_add(radius).min(bytes.len());
    &bytes[from..to]
}

/// Whether surrounding text marks a match as a documented example.
///
/// Lowercases a copy of the window and substring-searches each deny word.
/// Allocation per candidate is acceptable: candidates are rare relative to
/// file bytes (only reached after a prefix hit).
fn is_documented_example(window: &[u8]) -> bool {
    if window.is_empty() {
        return false;
    }
    let lower: Vec<u8> = window
        .iter()
        .map(|byte| byte.to_ascii_lowercase())
        .collect();
    DENY_WORDS.iter().any(|word| {
        lower.len() >= word.len() && lower.windows(word.len()).any(|slice| slice == *word)
    })
}

/// Whether a PEM body line is plausible base64: non-empty, ≤256 chars, and
/// strictly base64 alphabet. A single non-conforming line rejects the whole
/// block — real keys never contain prose or whitespace inside the body.
fn is_base64_line(line: &[u8]) -> bool {
    !line.is_empty()
        && line.len() <= 256
        && line
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

/// Scans for PEM private-key blocks: `PRIVATE KEY` header + base64 body +
/// matching footer within 16 KB.
///
/// Each gate narrows in turn: header mark → kind check → bounded footer
/// search → footer kind check → non-empty base64-only body (CRLF-tolerant)
/// → deny-word check over a generous 500-byte radius (keys ship with
/// comments). Evidence shows the header line plus body size and the body's
/// last 4 chars; the fingerprint covers the full block so any reissue
/// changes identity. Resumes after the footer so adjacent keys both report.
fn scan_pem(path: &Path, bytes: &[u8], out: &mut Vec<SecretFinding>) {
    let mut from = 0_usize;
    while let Some(start) = find_from(bytes, from, PEM_HEADER_MARK) {
        from = start + 1;
        // Header line is capped at 160 bytes: overlong "headers" are prose
        // containing the mark, not real delimiters.
        let header_end = bytes[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |relative| start + relative);
        let header_end = header_end.min(start.saturating_add(160));
        let header = &bytes[start..header_end];
        if !header.windows(PEM_KIND.len()).any(|line| line == PEM_KIND) {
            continue;
        }
        let search_end = header_end.saturating_add(PEM_MAX_BLOCK).min(bytes.len());
        let Some(footer_start) = find_from(&bytes[..search_end], header_end, PEM_FOOTER_MARK)
        else {
            continue;
        };
        let footer_end = bytes[footer_start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |relative| footer_start + relative);
        let footer_end = footer_end.min(footer_start.saturating_add(160));
        let footer = &bytes[footer_start..footer_end];
        if !footer.windows(PEM_KIND.len()).any(|line| line == PEM_KIND) {
            continue;
        }
        let mut valid_body = false;
        let mut body_ok = true;
        let mut last_line: &[u8] = b"";
        for line in bytes[header_end..footer_start]
            .split(|byte| *byte == b'\n')
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
            .filter(|line| !line.is_empty())
        {
            valid_body = true;
            if !is_base64_line(line) {
                body_ok = false;
                break;
            }
            last_line = line;
        }
        if !valid_body || !body_ok {
            continue;
        }
        if is_documented_example(context(bytes, start, footer_end, 500)) {
            continue;
        }
        let (line, column) = line_col(bytes, start);
        let tail_start = last_line.len().saturating_sub(4);
        let tail = String::from_utf8_lossy(&last_line[tail_start..]);
        let header_text = String::from_utf8_lossy(header);
        out.push(SecretFinding {
            rule_id: "SECRET-PEM-PRIVATE-KEY",
            title: "Private key material in source",
            severity: "high",
            cwe: "CWE-798",
            path: path.to_path_buf(),
            line,
            column,
            evidence: format!(
                "{header_text} [redacted body {} bytes, tail {tail}]",
                footer_start.saturating_sub(header_end)
            ),
            fingerprint: crate::fingerprint::fnv_hex(&bytes[start..footer_end]),
            message:
                "Remove the private key from source control, rotate it, and load it from a secret manager at runtime.",
            reference: "https://cwe.mitre.org/data/definitions/798.html",
            confidence: Confidence::High,
            suppressed: None,
        });
        from = footer_end;
    }
}

/// Scans for AWS access key IDs: `AKIA` + exactly 16 uppercase/digits.
///
/// Length is exact (20 chars) with non-alphanumeric boundaries on both sides,
/// which is what keeps longer identifiers containing `AKIA` from matching.
/// The famous `AKIAIOSFODNN7EXAMPLE` documentation key is killed by the
/// deny-word check (it contains `example`), asserted in tests.
fn scan_aws(path: &Path, bytes: &[u8], out: &mut Vec<SecretFinding>) {
    let mut from = 0_usize;
    while let Some(start) = find_from(bytes, from, b"AKIA") {
        from = start + 1;
        // Left boundary: a preceding alphanumeric means we are mid-token.
        if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
            continue;
        }
        let end = start.saturating_add(20);
        if end > bytes.len() {
            continue;
        }
        let token = &bytes[start..end];
        if !token[4..]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            continue;
        }
        // Right boundary: a following alphanumeric means a longer token.
        if end < bytes.len() && bytes[end].is_ascii_alphanumeric() {
            continue;
        }
        if is_documented_example(context(bytes, start, end, 100)) {
            continue;
        }
        let (line, column) = line_col(bytes, start);
        let tail = String::from_utf8_lossy(&token[16..]);
        out.push(SecretFinding {
            rule_id: "SECRET-AWS-ACCESS-KEY",
            title: "AWS access key ID in source",
            severity: "high",
            cwe: "CWE-798",
            path: path.to_path_buf(),
            line,
            column,
            evidence: format!("AKIA[redacted]{tail}"),
            fingerprint: crate::fingerprint::fnv_hex(token),
            message:
                "Remove the access key from source, deactivate it in IAM, and use short-lived credentials.",
            reference:
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
            confidence: Confidence::High,
            suppressed: None,
        });
    }
}

/// Scans for one GitHub token shape: fixed prefix + minimum body length.
///
/// Kept as a dedicated function (rather than folded into [`scan_prefixed`])
/// because it predates the generic scanner and its prefix/length/underscore
/// parametrization is already covered by tests. The left boundary also
/// rejects `_` so `xghp_…` (a longer identifier) never matches. Body length
/// is capped at 256 chars total to bound the greedy scan.
fn scan_github_token(
    path: &Path,
    bytes: &[u8],
    prefix: &[u8],
    min_len: usize,
    allow_underscore: bool,
    out: &mut Vec<SecretFinding>,
) {
    let mut from = 0_usize;
    while let Some(start) = find_from(bytes, from, prefix) {
        from = start + 1;
        if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
            continue;
        }
        let mut end = start.saturating_add(prefix.len());
        while end < bytes.len()
            && end - start <= 256
            && (bytes[end].is_ascii_alphanumeric() || (allow_underscore && bytes[end] == b'_'))
        {
            end += 1;
        }
        // Body length = total consumed minus the prefix; short matches like
        // `ghp_short` are prose, not tokens.
        if end - start.saturating_add(prefix.len()) < min_len {
            continue;
        }
        let token = &bytes[start..end];
        if is_documented_example(context(bytes, start, end, 100)) {
            continue;
        }
        let (line, column) = line_col(bytes, start);
        let tail_start = token.len().saturating_sub(4);
        let tail = String::from_utf8_lossy(&token[tail_start..]);
        let label = String::from_utf8_lossy(prefix);
        out.push(SecretFinding {
            rule_id: "SECRET-GITHUB-TOKEN",
            title: "GitHub token in source",
            severity: "high",
            cwe: "CWE-798",
            path: path.to_path_buf(),
            line,
            column,
            evidence: format!("{label}[redacted]{tail}"),
            fingerprint: crate::fingerprint::fnv_hex(token),
            message: "Revoke the token, remove it from source control and history, and use a secret manager.",
            reference: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
            confidence: Confidence::High,
            suppressed: None,
        });
    }
}

/// Declarative spec for one prefixed-token rule (Slack, Stripe, OpenAI,
/// GitLab, PyPI): prefixes + body charset + minimum length + report metadata.
///
/// `require_inner` demands one extra byte inside the body — used by Slack,
/// whose `xoxb-…` tokens must contain another `-`, separating real tokens
/// from short `xoxb-` mentions.
struct PrefixedSpec {
    /// Token prefixes to search for (e.g. all five `xox?-` Slack families).
    prefixes: &'static [&'static [u8]],
    /// Minimum body length AFTER the prefix; tunes precision per provider.
    min_body: usize,
    /// Extra body bytes beyond alphanumerics (e.g. `-` for Slack).
    extra_bytes: &'static [u8],
    /// Optional byte that must appear somewhere in the body.
    require_inner: Option<u8>,
    /// Rule ID for findings.
    rule_id: &'static str,
    /// Human title for findings.
    title: &'static str,
    /// Remediation message for findings.
    message: &'static str,
    /// Reference URL for findings.
    reference: &'static str,
}

/// Generic prefixed-token scanner driven by a [`PrefixedSpec`].
///
/// Same discipline as the GitHub scanner: left token boundary (alnum or `_`
/// rejects), greedy body consumption capped at 256 chars, minimum body
/// length, optional inner-byte requirement, deny-word check, then a redacted
/// finding. Adding a provider is one spec literal plus tests — no new code.
fn scan_prefixed(path: &Path, bytes: &[u8], spec: &PrefixedSpec, out: &mut Vec<SecretFinding>) {
    for prefix in spec.prefixes {
        let mut from = 0_usize;
        while let Some(start) = find_from(bytes, from, prefix) {
            from = start + 1;
            if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
                continue;
            }
            let mut end = start.saturating_add(prefix.len());
            while end < bytes.len()
                && end - start <= 256
                && (bytes[end].is_ascii_alphanumeric() || spec.extra_bytes.contains(&bytes[end]))
            {
                end += 1;
            }
            let body = &bytes[start.saturating_add(prefix.len())..end];
            if body.len() < spec.min_body {
                continue;
            }
            if let Some(required) = spec.require_inner
                && !body.contains(&required)
            {
                continue;
            }
            let token = &bytes[start..end];
            if is_documented_example(context(bytes, start, end, 100)) {
                continue;
            }
            let (line, column) = line_col(bytes, start);
            let tail_start = token.len().saturating_sub(4);
            let tail = String::from_utf8_lossy(&token[tail_start..]);
            let label = String::from_utf8_lossy(prefix);
            out.push(SecretFinding {
                rule_id: spec.rule_id,
                title: spec.title,
                severity: "high",
                cwe: "CWE-798",
                path: path.to_path_buf(),
                line,
                column,
                evidence: format!("{label}[redacted]{tail}"),
                fingerprint: crate::fingerprint::fnv_hex(token),
                message: spec.message,
                reference: spec.reference,
                confidence: Confidence::High,
                suppressed: None,
            });
        }
    }
}

/// Base64url-ish token character: alphanumerics plus `-` and `_`.
/// Shared by the webhook and JWT scanners.
fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

/// Scans for Slack webhook URLs: fixed services prefix + three `/`-separated
/// segments of 8+ token chars each.
///
/// The fixed `https://hooks.slack.com/services/` prefix makes this the
/// lowest-FP rule in the file — but the segment structure is still enforced
/// so a bare prefix mention in docs does not report. Parsing is staged: two
/// segments consumed in the loop (breaking after the second slash), then the
/// third scanned separately and length-checked — the ordering matters
/// because the length check must see the fully scanned segment.
fn scan_slack_webhook(path: &Path, bytes: &[u8], out: &mut Vec<SecretFinding>) {
    const PREFIX: &[u8] = b"https://hooks.slack.com/services/";
    let mut from = 0_usize;
    while let Some(start) = find_from(bytes, from, PREFIX) {
        from = start + 1;
        let mut end = start.saturating_add(PREFIX.len());
        let mut segments = 0_usize;
        let mut segment_len = 0_usize;
        while end < bytes.len() && end - start <= 256 {
            let byte = bytes[end];
            if is_token_char(byte) {
                segment_len += 1;
                end += 1;
            } else if byte == b'/' && segment_len >= 8 {
                segments += 1;
                segment_len = 0;
                end += 1;
                if segments == 2 {
                    break;
                }
            } else {
                break;
            }
        }
        if segments != 2 {
            continue;
        }
        while end < bytes.len() && is_token_char(bytes[end]) && end - start <= 256 {
            segment_len += 1;
            end += 1;
        }
        if segment_len < 8 {
            continue;
        }
        let token = &bytes[start..end];
        if is_documented_example(context(bytes, start, end, 100)) {
            continue;
        }
        let (line, column) = line_col(bytes, start);
        let tail_start = token.len().saturating_sub(4);
        let tail = String::from_utf8_lossy(&token[tail_start..]);
        out.push(SecretFinding {
            rule_id: "SECRET-SLACK-WEBHOOK",
            title: "Slack webhook URL in source",
            severity: "high",
            cwe: "CWE-798",
            path: path.to_path_buf(),
            line,
            column,
            evidence: format!("https://hooks.slack.com/services/[redacted]{tail}"),
            fingerprint: crate::fingerprint::fnv_hex(token),
            message: "Revoke the webhook, remove the URL from source control and history, and store it in a secret manager.",
            reference: "https://api.slack.com/messaging/webhooks",
            confidence: Confidence::High,
            suppressed: None,
        });
    }
}

/// Scans for JWT-shaped credentials: `eyJ…` + three dot-separated base64url
/// segments of 10+ chars each.
///
/// `eyJ` is the base64url encoding of `{"` — every JWT header starts with it.
/// Shape-only detection cannot prove the token is live, but a live-looking
/// JWT in source is exactly what this rule family reports (validity is never
/// checked; credentials are never sent to provider APIs). The 2048-char cap
/// accommodates large real-world tokens while bounding the greedy scan.
fn scan_jwt(path: &Path, bytes: &[u8], out: &mut Vec<SecretFinding>) {
    let mut from = 0_usize;
    while let Some(start) = find_from(bytes, from, b"eyJ") {
        from = start + 1;
        if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
            continue;
        }
        let mut end = start;
        let mut segments = 0_usize;
        let mut segment_len = 0_usize;
        while end < bytes.len() && end - start <= 2048 {
            let byte = bytes[end];
            if is_token_char(byte) {
                segment_len += 1;
                end += 1;
            } else if byte == b'.' && segment_len >= 10 {
                segments += 1;
                segment_len = 0;
                end += 1;
                if segments == 2 {
                    break;
                }
            } else {
                break;
            }
        }
        if segments != 2 {
            continue;
        }
        while end < bytes.len() && is_token_char(bytes[end]) && end - start <= 2048 {
            segment_len += 1;
            end += 1;
        }
        if segment_len < 10 {
            continue;
        }
        let token = &bytes[start..end];
        if is_documented_example(context(bytes, start, end, 100)) {
            continue;
        }
        let (line, column) = line_col(bytes, start);
        let tail_start = token.len().saturating_sub(4);
        let tail = String::from_utf8_lossy(&token[tail_start..]);
        out.push(SecretFinding {
            rule_id: "SECRET-GENERIC-JWT",
            title: "JWT-shaped credential in source",
            severity: "high",
            cwe: "CWE-798",
            path: path.to_path_buf(),
            line,
            column,
            evidence: format!("eyJ[redacted]{tail}"),
            fingerprint: crate::fingerprint::fnv_hex(token),
            message: "Revoke the token, remove it from source control and history, and issue short-lived credentials from a secret manager.",
            reference: "https://cwe.mitre.org/data/definitions/798.html",
            confidence: Confidence::High,
            suppressed: None,
        });
    }
}

/// Runs all ten secret validators over one file's bytes.
///
/// Called for every scanned file (parsed sources AND secrets-only configs)
/// before parsing, so unparseable files are still checked. Validators are
/// independent — one rule's miss never affects another — and results are
/// sorted by (line, column, rule) for deterministic reports. Threshold
/// rationale per provider: GitHub `gh?_` needs 36 body chars (real tokens
/// are fixed-length 36); `github_pat_` needs 20 (variable length);
/// Slack needs 20 + inner dash (three-part structure); Stripe needs 16
/// (covers live and test keys); OpenAI needs 32 (short `sk-` prose is
/// common, so the bar is high); GitLab/PyPI need 20.
pub fn scan_secrets(path: &Path, bytes: &[u8]) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    scan_pem(path, bytes, &mut out);
    scan_aws(path, bytes, &mut out);
    for prefix in [b"ghp_".as_slice(), b"gho_", b"ghu_", b"ghs_", b"ghr_"] {
        scan_github_token(path, bytes, prefix, 36, false, &mut out);
    }
    scan_github_token(path, bytes, b"github_pat_", 20, true, &mut out);
    for spec in [
        PrefixedSpec {
            prefixes: &[b"xoxb-", b"xoxp-", b"xoxa-", b"xoxr-", b"xoxs-"],
            min_body: 20,
            extra_bytes: b"-",
            require_inner: Some(b'-'),
            rule_id: "SECRET-SLACK-TOKEN",
            title: "Slack token in source",
            message: "Revoke the token, remove it from source control and history, and use a secret manager.",
            reference: "https://api.slack.com/authentication/token-types",
        },
        PrefixedSpec {
            prefixes: &[b"sk_live_", b"rk_live_", b"sk_test_", b"rk_test_"],
            min_body: 16,
            extra_bytes: b"",
            require_inner: None,
            rule_id: "SECRET-STRIPE-KEY",
            title: "Stripe API key in source",
            message: "Roll the key in the Stripe dashboard, remove it from source control and history, and load it from a secret manager.",
            reference: "https://docs.stripe.com/keys",
        },
        PrefixedSpec {
            prefixes: &[b"sk-"],
            min_body: 32,
            extra_bytes: b"-_",
            require_inner: None,
            rule_id: "SECRET-OPENAI-KEY",
            title: "OpenAI API key in source",
            message: "Revoke the key, remove it from source control and history, and load it from a secret manager.",
            reference: "https://platform.openai.com/docs/guides/production-best-practices",
        },
        PrefixedSpec {
            prefixes: &[b"glpat-"],
            min_body: 20,
            extra_bytes: b"-_",
            require_inner: None,
            rule_id: "SECRET-GITLAB-TOKEN",
            title: "GitLab token in source",
            message: "Revoke the token, remove it from source control and history, and use a secret manager.",
            reference: "https://docs.gitlab.com/ee/security/token_overview.html",
        },
        PrefixedSpec {
            prefixes: &[b"pypi-"],
            min_body: 20,
            extra_bytes: b"-_",
            require_inner: None,
            rule_id: "SECRET-PYPI-TOKEN",
            title: "PyPI token in source",
            message: "Remove the token from the project, revoke it on PyPI, and publish from CI with a trusted publisher or vaulted secret.",
            reference: "https://docs.pypi.org/trusted-publishers/",
        },
    ] {
        scan_prefixed(path, bytes, &spec, &mut out);
    }
    scan_slack_webhook(path, bytes, &mut out);
    scan_jwt(path, bytes, &mut out);
    out.sort_by(|a, b| (a.line, a.column, a.rule_id).cmp(&(b.line, b.column, b.rule_id)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fictitious AWS key: valid shape (`AKIA` + 16), impossible value
    /// (repeated `Z`). Built programmatically so no literal secret — even a
    /// fake-looking one — is ever committed.
    fn aws_key() -> String {
        format!("AKIA{}", "Z".repeat(16))
    }

    /// Fictitious GitHub token: valid shape, impossible value.
    fn github_token() -> String {
        format!("ghp_{}", "a".repeat(36))
    }

    /// Fictitious PEM block: real delimiters around a base64 body of
    /// repeated `Q`, which also makes redaction assertions exact.
    fn pem_block(kind: &str) -> String {
        let header = format!("-----BEGIN {kind} PRIVATE KEY-----");
        let footer = format!("-----END {kind} PRIVATE KEY-----");
        let mut body = String::new();
        for _ in 0..8 {
            body.push_str(&"Q".repeat(64));
            body.push('\n');
        }
        format!("{header}\n{body}{footer}\n")
    }

    /// Full PEM lifecycle: detects at (1,1), keeps the header and a 4-char
    /// tail in evidence, and never leaks 16+ body chars into evidence,
    /// fingerprint output, or serialized JSON.
    #[test]
    fn detects_pem_block_and_redacts_body() {
        let bytes = pem_block("RSA").into_bytes();
        let findings = scan_secrets(Path::new("key.py"), &bytes);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SECRET-PEM-PRIVATE-KEY");
        assert_eq!((findings[0].line, findings[0].column), (1, 1));
        assert!(findings[0].evidence.contains("BEGIN"));
        assert!(findings[0].evidence.contains("tail QQQQ"));
        assert!(!findings[0].evidence.contains(&"Q".repeat(16)));
        assert_eq!(findings[0].fingerprint.len(), 16);
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(!serialized.contains(&"Q".repeat(16)));
    }

    /// An `EXAMPLE` comment above the key suppresses the whole block.
    #[test]
    fn skips_documented_example_pem() {
        let bytes = format!("# EXAMPLE key for docs\n{}", pem_block("RSA")).into_bytes();
        assert!(scan_secrets(Path::new("key.py"), &bytes).is_empty());
    }

    /// AWS detection with exact redacted shape, plus a serialization
    /// no-leak assertion on the full key.
    #[test]
    fn detects_aws_key_and_redacts_middle() {
        let key = aws_key();
        let bytes = format!("key = \"{key}\"\n").into_bytes();
        let findings = scan_secrets(Path::new("app.py"), &bytes);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SECRET-AWS-ACCESS-KEY");
        assert_eq!(findings[0].evidence, "AKIA[redacted]ZZZZ");
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(!serialized.contains(&key));
        assert!(serialized.contains("AKIA[redacted]ZZZZ"));
    }

    /// AWS's own documentation key (`...EXAMPLE`) is the canonical negative:
    /// the deny word sits INSIDE the token span.
    #[test]
    fn skips_aws_documented_example() {
        let bytes = b"key = \"AKIAIOSFODNN7EXAMPLE\"\n".as_slice();
        assert!(scan_secrets(Path::new("app.py"), bytes).is_empty());
    }

    /// GitHub detection with exact redacted shape and no-leak serialization.
    #[test]
    fn detects_github_token_and_redacts() {
        let token = github_token();
        let bytes = format!("token={token}\n").into_bytes();
        let findings = scan_secrets(Path::new("app.js"), &bytes);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SECRET-GITHUB-TOKEN");
        assert_eq!(findings[0].evidence, "ghp_[redacted]aaaa");
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(!serialized.contains(&token));
    }

    /// Short `ghp_` text and mid-identifier `xghp_…` (failed left boundary)
    /// both stay silent.
    #[test]
    fn skips_short_github_like_text() {
        assert!(scan_secrets(Path::new("app.js"), b"ghp_short\n").is_empty());
        assert!(
            scan_secrets(
                Path::new("app.js"),
                b"xghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            )
            .is_empty()
        );
    }

    /// Byte-offset → line/column mapping is 1-based on both axes.
    #[test]
    fn reports_line_and_column() {
        let key = aws_key();
        let bytes = format!("one\ntwo {key}\nthree\n").into_bytes();
        let findings = scan_secrets(Path::new("app.py"), &bytes);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].column, 5);
    }

    /// Slack needs the full three-part shape: the positive has it, a short
    /// body fails length, and a long dash-less body fails `require_inner`.
    #[test]
    fn detects_slack_token_and_requires_structure() {
        let token = format!(
            "xoxb-{}-{}-{}",
            "1".repeat(12),
            "2".repeat(12),
            "a".repeat(24)
        );
        let bytes = format!("token={token}\n").into_bytes();
        let findings = scan_secrets(Path::new("app.js"), &bytes);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SECRET-SLACK-TOKEN");
        assert_eq!(findings[0].evidence, "xoxb-[redacted]aaaa");
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(!serialized.contains(&token));
        assert!(scan_secrets(Path::new("app.js"), b"xoxb_short\n").is_empty());
        assert!(
            scan_secrets(
                Path::new("app.js"),
                format!("xoxb-{}\n", "a".repeat(24)).as_bytes()
            )
            .is_empty()
        );
    }

    /// All four Stripe prefixes (live + restricted × live + test) detect;
    /// short bodies stay silent.
    #[test]
    fn detects_stripe_keys() {
        for prefix in ["sk_live_", "rk_live_", "sk_test_", "rk_test_"] {
            let token = format!("{prefix}{}", "b".repeat(24));
            let bytes = format!("key={token}\n").into_bytes();
            let findings = scan_secrets(Path::new("app.py"), &bytes);
            assert_eq!(findings.len(), 1, "{prefix}");
            assert_eq!(findings[0].rule_id, "SECRET-STRIPE-KEY");
            let serialized = serde_json::to_string(&findings).unwrap();
            assert!(!serialized.contains(&token));
        }
        assert!(scan_secrets(Path::new("app.py"), b"sk_live_short\n").is_empty());
    }

    /// OpenAI/GitLab/PyPI positives plus no-leak serialization; short
    /// lookalikes (`sk-short`, `glpat-short`) stay silent.
    #[test]
    fn detects_openai_gitlab_and_pypi_tokens() {
        let cases = [
            (format!("sk-{}\n", "c".repeat(48)), "SECRET-OPENAI-KEY"),
            (
                format!("token=glpat-{}\n", "d".repeat(26)),
                "SECRET-GITLAB-TOKEN",
            ),
            (
                format!("token=pypi-{}\n", "e".repeat(40)),
                "SECRET-PYPI-TOKEN",
            ),
        ];
        for (body, expected) in cases {
            let findings = scan_secrets(Path::new("app.py"), body.as_bytes());
            assert_eq!(findings.len(), 1, "{expected}");
            assert_eq!(findings[0].rule_id, expected);
            let serialized = serde_json::to_string(&findings).unwrap();
            assert!(!serialized.contains(body.trim()));
        }
        assert!(scan_secrets(Path::new("app.py"), b"sk-short\n").is_empty());
        assert!(scan_secrets(Path::new("app.py"), b"glpat-short\n").is_empty());
    }

    /// Full three-segment webhook URL detects; a bare prefix with one short
    /// segment does not.
    #[test]
    fn detects_slack_webhook_url() {
        let url = format!(
            "https://hooks.slack.com/services/{}/{}/{}",
            "T".to_owned() + &"1".repeat(10),
            "B".to_owned() + &"2".repeat(10),
            "x".repeat(24)
        );
        let bytes = format!("url={url}\n").into_bytes();
        let findings = scan_secrets(Path::new("app.js"), &bytes);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SECRET-SLACK-WEBHOOK");
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(!serialized.contains(&url));
        assert!(
            scan_secrets(
                Path::new("app.js"),
                b"https://hooks.slack.com/services/short\n"
            )
            .is_empty()
        );
    }

    /// Three-segment `eyJ…` detects with exact redacted shape; short segments
    /// and deny-word context (`example … placeholder`) stay silent.
    #[test]
    fn detects_jwt_shaped_credentials() {
        let jwt = format!(
            "eyJ{}.{}.{}",
            "h".repeat(20),
            "p".repeat(20),
            "s".repeat(20)
        );
        let bytes = format!("auth={jwt}\n").into_bytes();
        let findings = scan_secrets(Path::new("app.py"), &bytes);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SECRET-GENERIC-JWT");
        assert_eq!(findings[0].evidence, "eyJ[redacted]ssss");
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(!serialized.contains(&jwt));
        assert!(scan_secrets(Path::new("app.py"), b"eyJshort.nope\n").is_empty());
        assert!(
            scan_secrets(
                Path::new("app.py"),
                format!("token=example {jwt} placeholder\n").as_bytes()
            )
            .is_empty()
        );
    }

    /// Totality over hostile inputs: truncated PEM/AWS matches, empty input,
    /// and invalid-UTF-8 bytes all return empty instead of panicking.
    #[test]
    fn truncated_and_binary_inputs_do_not_panic() {
        let header = format!("-----BEGIN {} PRIVATE KEY-----", "RSA");
        assert!(scan_secrets(Path::new("a.py"), header.as_bytes()).is_empty());
        assert!(scan_secrets(Path::new("a.py"), b"AKIA").is_empty());
        assert!(scan_secrets(Path::new("a.py"), b"").is_empty());
        assert!(scan_secrets(Path::new("a.py"), &[0, 159, 146, 150, 255, 10]).is_empty());
    }
}
