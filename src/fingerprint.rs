//! Stable finding fingerprints for baseline, diff, and suppression matching.
//!
//! A fingerprint answers "is this the same finding as before?" across runs.
//! The hash inputs are deliberately narrow: moving a finding by one line
//! changes its fingerprint (surfaced as fixed+new, which is honest), while
//! cosmetic report changes — evidence truncation, confidence upgrades,
//! taint traces — must NOT change it, or baselines would churn on every
//! scanner upgrade. The `*Like` structs in `report.rs` exist precisely to
//! pin this input set in one place.
//!
//! FNV-1a is used instead of a cryptographic hash because fingerprints are
//! correlation IDs, not security boundaries; 64 bits rendered as 16 hex
//! characters is enough to make accidental collisions negligible at the
//! finding counts involved.

use crate::report::{SecretFindingLike, SecurityFindingLike};

/// Hashes bytes with 64-bit FNV-1a and renders the digest as 16 hex chars.
///
/// Also reused for secret content fingerprints, where the digest stands in
/// for the redacted secret material in reports.
pub fn fnv_hex(bytes: &[u8]) -> String {
    // FNV offset basis and prime for 64-bit; `wrapping_mul` is the defined
    // overflow behaviour the algorithm requires (not a bug workaround).
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

/// Joins fingerprint parts with NUL separators.
///
/// The separator matters: without it, `("ab", "c")` and `("a", "bc")` would
/// hash identically. NUL cannot appear in rule IDs, paths, or callees in
/// practice, and even adversarial paths cannot induce a collision that
/// survives the surrounding location fields.
fn join(parts: &[&str]) -> String {
    let mut key = String::new();
    for part in parts {
        key.push_str(part);
        key.push('\0');
    }
    key
}

/// Fingerprint for an AST security finding: rule + path + line + column + callee.
///
/// Excludes evidence, message, confidence, `resolved_callee`, and taint so
/// that scanner improvements (better evidence, taint-lite upgrades) never
/// resurrect baselined findings as "new".
pub fn security_fingerprint(finding: &SecurityFindingLike) -> String {
    fnv_hex(
        join(&[
            &finding.rule_id,
            &finding.path,
            &finding.line.to_string(),
            &finding.column.to_string(),
            &finding.callee,
        ])
        .as_bytes(),
    )
}

/// Fingerprint for a secret finding: rule + path + line + column + content hash.
///
/// Unlike security findings, the secret's content hash IS an input: rotating
/// a credential must surface as fixed+new (the old leak is fixed, the new
/// material is a fresh finding), not silently match the old entry.
pub fn secret_fingerprint(finding: &SecretFindingLike) -> String {
    fnv_hex(
        join(&[
            &finding.rule_id,
            &finding.path,
            &finding.line.to_string(),
            &finding.column.to_string(),
            &finding.content_fingerprint,
        ])
        .as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same finding hashes identically; moving one line changes the hash;
    /// output is always 16 hex characters.
    #[test]
    fn fingerprints_are_stable_and_distinct() {
        let base = SecurityFindingLike {
            rule_id: "CORE-PY-EVAL".to_owned(),
            path: "src/app.py".to_owned(),
            line: 3,
            column: 1,
            callee: "eval".to_owned(),
        };
        let same = base.clone();
        let mut moved = base.clone();
        moved.line = 4;
        assert_eq!(security_fingerprint(&base), security_fingerprint(&same));
        assert_ne!(security_fingerprint(&base), security_fingerprint(&moved));
        assert_eq!(security_fingerprint(&base).len(), 16);
    }

    /// Rotating a secret (same location, new content hash) must NOT match
    /// the old fingerprint, or rotation would look like "still present".
    #[test]
    fn secret_rotation_changes_fingerprint() {
        let rotated = SecretFindingLike {
            rule_id: "SECRET-AWS-ACCESS-KEY".to_owned(),
            path: ".env".to_owned(),
            line: 1,
            column: 7,
            content_fingerprint: "bbbb".to_owned(),
        };
        let original = SecretFindingLike {
            content_fingerprint: "aaaa".to_owned(),
            ..rotated.clone()
        };
        assert_ne!(secret_fingerprint(&original), secret_fingerprint(&rotated));
    }
}
