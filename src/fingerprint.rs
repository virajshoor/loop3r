use crate::report::{SecretFindingLike, SecurityFindingLike};

pub fn fnv_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn join(parts: &[&str]) -> String {
    let mut key = String::new();
    for part in parts {
        key.push_str(part);
        key.push('\0');
    }
    key
}

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
