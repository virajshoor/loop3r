use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use globset::{Glob, GlobMatcher};
use serde::Deserialize;

use crate::report::{Report, SuppressedBy, SuppressionReport};

#[derive(Debug, Deserialize)]
struct SuppressionEntry {
    rule_id: String,
    path: String,
    reason: String,
    owner: String,
    expires: String,
}

#[derive(Debug, Deserialize)]
struct SuppressionFile {
    #[serde(default)]
    suppressions: Vec<SuppressionEntry>,
}

struct Compiled {
    entry: SuppressionEntry,
    matcher: GlobMatcher,
}

pub fn today_iso() -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() / 86_400)
        .unwrap_or(0) as i64;
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let civil_year = if month <= 2 { year + 1 } else { year };
    format!("{civil_year:04}-{month:02}-{day:02}")
}

fn valid_expiry(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        if index == 4 || index == 7 {
            continue;
        }
        if !byte.is_ascii_digit() {
            return false;
        }
    }
    let month: u32 = value[5..7].parse().unwrap_or(0);
    let day: u32 = value[8..10].parse().unwrap_or(0);
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

fn load(path: &Path) -> Result<Vec<Compiled>> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let file: SuppressionFile =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    let mut compiled = Vec::new();
    for (index, entry) in file.suppressions.into_iter().enumerate() {
        let location = format!("{} entry {index}", path.display());
        if entry.rule_id.is_empty() {
            bail!("{location}: rule_id is empty");
        }
        if entry.path.is_empty() {
            bail!("{location}: path is empty");
        }
        if entry.reason.is_empty() {
            bail!("{location}: reason is empty");
        }
        if entry.owner.is_empty() {
            bail!("{location}: owner is empty");
        }
        if !valid_expiry(&entry.expires) {
            bail!("{location}: expires must be YYYY-MM-DD");
        }
        let matcher = Glob::new(&entry.path)
            .with_context(|| format!("{location}: invalid path glob"))?
            .compile_matcher();
        compiled.push(Compiled { entry, matcher });
    }
    Ok(compiled)
}

pub fn apply_suppressions(report: &mut Report, path: &Path) -> Result<()> {
    let compiled = load(path)?;
    let today = today_iso();
    let mut expired = BTreeSet::new();
    let mut applied = 0_usize;
    let target = report.scope.target.clone();
    let mut apply =
        |rule_id: &str, finding_path: &PathBuf, suppressed: &mut Option<SuppressedBy>| {
            let relative = finding_path.strip_prefix(&target).unwrap_or(finding_path);
            for item in &compiled {
                if item.entry.rule_id != rule_id {
                    continue;
                }
                if !item.matcher.is_match(finding_path) && !item.matcher.is_match(relative) {
                    continue;
                }
                if item.entry.expires < today {
                    expired.insert(format!("{} {}", item.entry.rule_id, item.entry.path));
                    continue;
                }
                *suppressed = Some(SuppressedBy {
                    reason: item.entry.reason.clone(),
                    owner: item.entry.owner.clone(),
                    expires: item.entry.expires.clone(),
                });
                applied += 1;
                break;
            }
        };
    for finding in &mut report.security_findings {
        apply(
            &finding.rule_id.clone(),
            &finding.path.clone(),
            &mut finding.suppressed,
        );
    }
    for finding in &mut report.secret_findings {
        apply(
            finding.rule_id,
            &finding.path.clone(),
            &mut finding.suppressed,
        );
    }
    report.suppressions = SuppressionReport {
        file: Some(path.to_path_buf()),
        applied,
        expired: expired.into_iter().collect(),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn today_is_a_valid_iso_date() {
        let today = today_iso();
        assert!(valid_expiry(&today), "{today}");
        assert!(today.as_str() >= "2026-01-01");
        assert!(today.as_str() < "2100-01-01");
    }

    #[test]
    fn expiry_validation_rejects_bad_shapes() {
        assert!(valid_expiry("2999-12-31"));
        for bad in [
            "",
            "2999-1-1",
            "2999/12/31",
            "2999-13-01",
            "2999-00-10",
            "2999-12-32",
            "2999-12-00",
            "not-a-date",
            "2999-12-311",
        ] {
            assert!(!valid_expiry(bad), "{bad}");
        }
    }

    #[test]
    fn malformed_suppression_files_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let bad_glob = directory.path().join("bad-glob.json");
        std::fs::write(
            &bad_glob,
            r#"{"suppressions": [{"rule_id": "R", "path": "[", "reason": "x", "owner": "y", "expires": "2999-01-01"}]}"#,
        )
        .unwrap();
        let missing_reason = directory.path().join("missing-reason.json");
        std::fs::write(
            &missing_reason,
            r#"{"suppressions": [{"rule_id": "R", "path": "**", "owner": "y", "expires": "2999-01-01"}]}"#,
        )
        .unwrap();
        let bad_date = directory.path().join("bad-date.json");
        std::fs::write(
            &bad_date,
            r#"{"suppressions": [{"rule_id": "R", "path": "**", "reason": "x", "owner": "y", "expires": "tomorrow"}]}"#,
        )
        .unwrap();
        for path in [bad_glob, missing_reason, bad_date] {
            assert!(load(&path).is_err(), "{}", path.display());
        }
        let empty = directory.path().join("empty.json");
        std::fs::write(&empty, "{}").unwrap();
        assert!(load(&empty).unwrap().is_empty());
    }
}
