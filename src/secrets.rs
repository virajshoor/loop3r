use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::report::Confidence;

#[derive(Debug, Serialize)]
pub struct SecretFinding {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub severity: &'static str,
    pub cwe: &'static str,
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub evidence: String,
    pub fingerprint: String,
    pub message: &'static str,
    pub reference: &'static str,
    pub confidence: Confidence,
    pub suppressed: Option<crate::report::SuppressedBy>,
}

const DENY_WORDS: [&[u8]; 6] = [
    b"example",
    b"placeholder",
    b"fake",
    b"dummy",
    b"sample",
    b"mock",
];

const PEM_HEADER_MARK: &[u8] = b"-----BEGIN ";
const PEM_FOOTER_MARK: &[u8] = b"-----END ";
const PEM_KIND: &[u8] = b"PRIVATE KEY-----";
const PEM_MAX_BLOCK: usize = 16 * 1024;

fn find_from(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|relative| from + relative)
}

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

fn context(bytes: &[u8], start: usize, end: usize, radius: usize) -> &[u8] {
    let from = start.saturating_sub(radius);
    let to = end.saturating_add(radius).min(bytes.len());
    &bytes[from..to]
}

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

fn is_base64_line(line: &[u8]) -> bool {
    !line.is_empty()
        && line.len() <= 256
        && line
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

fn scan_pem(path: &Path, bytes: &[u8], out: &mut Vec<SecretFinding>) {
    let mut from = 0_usize;
    while let Some(start) = find_from(bytes, from, PEM_HEADER_MARK) {
        from = start + 1;
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

fn scan_aws(path: &Path, bytes: &[u8], out: &mut Vec<SecretFinding>) {
    let mut from = 0_usize;
    while let Some(start) = find_from(bytes, from, b"AKIA") {
        from = start + 1;
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

pub fn scan_secrets(path: &Path, bytes: &[u8]) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    scan_pem(path, bytes, &mut out);
    scan_aws(path, bytes, &mut out);
    for prefix in [b"ghp_".as_slice(), b"gho_", b"ghu_", b"ghs_", b"ghr_"] {
        scan_github_token(path, bytes, prefix, 36, false, &mut out);
    }
    scan_github_token(path, bytes, b"github_pat_", 20, true, &mut out);
    out.sort_by(|a, b| (a.line, a.column, a.rule_id).cmp(&(b.line, b.column, b.rule_id)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aws_key() -> String {
        format!("AKIA{}", "Z".repeat(16))
    }

    fn github_token() -> String {
        format!("ghp_{}", "a".repeat(36))
    }

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

    #[test]
    fn skips_documented_example_pem() {
        let bytes = format!("# EXAMPLE key for docs\n{}", pem_block("RSA")).into_bytes();
        assert!(scan_secrets(Path::new("key.py"), &bytes).is_empty());
    }

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

    #[test]
    fn skips_aws_documented_example() {
        let bytes = b"key = \"AKIAIOSFODNN7EXAMPLE\"\n".as_slice();
        assert!(scan_secrets(Path::new("app.py"), bytes).is_empty());
    }

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

    #[test]
    fn reports_line_and_column() {
        let key = aws_key();
        let bytes = format!("one\ntwo {key}\nthree\n").into_bytes();
        let findings = scan_secrets(Path::new("app.py"), &bytes);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].column, 5);
    }

    #[test]
    fn truncated_and_binary_inputs_do_not_panic() {
        let header = format!("-----BEGIN {} PRIVATE KEY-----", "RSA");
        assert!(scan_secrets(Path::new("a.py"), header.as_bytes()).is_empty());
        assert!(scan_secrets(Path::new("a.py"), b"AKIA").is_empty());
        assert!(scan_secrets(Path::new("a.py"), b"").is_empty());
        assert!(scan_secrets(Path::new("a.py"), &[0, 159, 146, 150, 255, 10]).is_empty());
    }
}
