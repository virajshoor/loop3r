use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::Value;

use crate::fingerprint::{secret_fingerprint, security_fingerprint};
use crate::report::{BaselineSummary, Report, SecretFindingLike, SecurityFindingLike};

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn number(value: &Value, key: &str) -> usize {
    value.get(key).and_then(Value::as_u64).unwrap_or(0) as usize
}

fn security_like(value: &Value) -> SecurityFindingLike {
    SecurityFindingLike {
        rule_id: text(value, "rule_id"),
        path: text(value, "path"),
        line: number(value, "line"),
        column: number(value, "column"),
        callee: text(value, "callee"),
    }
}

fn secret_like(value: &Value) -> SecretFindingLike {
    SecretFindingLike {
        rule_id: text(value, "rule_id"),
        path: text(value, "path"),
        line: number(value, "line"),
        column: number(value, "column"),
        content_fingerprint: text(value, "fingerprint"),
    }
}

pub struct ReportFindings {
    pub security: Vec<Value>,
    pub secrets: Vec<Value>,
}

pub fn load_findings(path: &Path) -> Result<ReportFindings> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let value: Value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    let object = value
        .as_object()
        .with_context(|| format!("{}: expected a JSON object", path.display()))?;
    if object
        .get("schema_version")
        .and_then(Value::as_u64)
        .is_none()
    {
        bail!(
            "{}: not a loop3r source report (missing schema_version)",
            path.display()
        );
    }
    let security = object
        .get("security_findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let secrets = object
        .get("secret_findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if object.get("security_findings").is_none() && object.get("secret_findings").is_none() {
        bail!(
            "{}: not a loop3r source report (no finding lists)",
            path.display()
        );
    }
    Ok(ReportFindings { security, secrets })
}

#[derive(Default)]
pub struct BaselineSets {
    pub security: BTreeSet<String>,
    pub secrets: BTreeSet<String>,
}

pub fn baseline_sets(findings: &ReportFindings) -> BaselineSets {
    BaselineSets {
        security: findings
            .security
            .iter()
            .map(|value| security_fingerprint(&security_like(value)))
            .collect(),
        secrets: findings
            .secrets
            .iter()
            .map(|value| secret_fingerprint(&secret_like(value)))
            .collect(),
    }
}

fn current_sets(report: &Report) -> BaselineSets {
    BaselineSets {
        security: report
            .security_findings
            .iter()
            .map(|finding| security_fingerprint(&SecurityFindingLike::from(finding)))
            .collect(),
        secrets: report
            .secret_findings
            .iter()
            .map(|finding| secret_fingerprint(&SecretFindingLike::from(finding)))
            .collect(),
    }
}

pub fn apply_baseline(report: &mut Report, path: &Path) -> Result<BaselineSets> {
    let baseline = load_findings(path)?;
    let sets = baseline_sets(&baseline);
    let current = current_sets(report);
    report.baseline = Some(BaselineSummary {
        path: path.to_path_buf(),
        new_security: current.security.difference(&sets.security).count(),
        new_secrets: current.secrets.difference(&sets.secrets).count(),
        fixed_security: sets.security.difference(&current.security).count(),
        fixed_secrets: sets.secrets.difference(&current.secrets).count(),
    });
    Ok(sets)
}

pub fn has_unsuppressed_new(report: &Report, sets: Option<&BaselineSets>) -> bool {
    let fresh_security =
        |fingerprint: String| sets.is_none_or(|baseline| !baseline.security.contains(&fingerprint));
    let fresh_secret =
        |fingerprint: String| sets.is_none_or(|baseline| !baseline.secrets.contains(&fingerprint));
    report.security_findings.iter().any(|finding| {
        finding.suppressed.is_none()
            && fresh_security(security_fingerprint(&SecurityFindingLike::from(finding)))
    }) || report.secret_findings.iter().any(|finding| {
        finding.suppressed.is_none()
            && fresh_secret(secret_fingerprint(&SecretFindingLike::from(finding)))
    })
}

#[derive(Serialize)]
pub struct DiffReport {
    pub schema_version: u8,
    pub old: PathBuf,
    pub new: PathBuf,
    pub added_security: Vec<Value>,
    pub fixed_security: Vec<Value>,
    pub added_secrets: Vec<Value>,
    pub fixed_secrets: Vec<Value>,
    pub unchanged_security: usize,
    pub unchanged_secrets: usize,
}

pub fn compare(old_path: &Path, new_path: &Path) -> Result<DiffReport> {
    let old = load_findings(old_path)?;
    let new = load_findings(new_path)?;
    let old_sets = baseline_sets(&old);
    let new_sets = baseline_sets(&new);
    let added_security: Vec<Value> = new
        .security
        .iter()
        .filter(|value| {
            !old_sets
                .security
                .contains(&security_fingerprint(&security_like(value)))
        })
        .cloned()
        .collect();
    let fixed_security: Vec<Value> = old
        .security
        .iter()
        .filter(|value| {
            !new_sets
                .security
                .contains(&security_fingerprint(&security_like(value)))
        })
        .cloned()
        .collect();
    let added_secrets: Vec<Value> = new
        .secrets
        .iter()
        .filter(|value| {
            !old_sets
                .secrets
                .contains(&secret_fingerprint(&secret_like(value)))
        })
        .cloned()
        .collect();
    let fixed_secrets: Vec<Value> = old
        .secrets
        .iter()
        .filter(|value| {
            !new_sets
                .secrets
                .contains(&secret_fingerprint(&secret_like(value)))
        })
        .cloned()
        .collect();
    Ok(DiffReport {
        schema_version: 1,
        old: old_path.to_path_buf(),
        new: new_path.to_path_buf(),
        unchanged_security: new.security.len() - added_security.len(),
        unchanged_secrets: new.secrets.len() - added_secrets.len(),
        added_security,
        fixed_security,
        added_secrets,
        fixed_secrets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loader_tolerates_missing_secret_list() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("v1.json");
        std::fs::write(
            &path,
            r#"{"schema_version": 1, "security_findings": [{"rule_id": "R", "path": "a.py", "line": 1, "column": 1, "callee": "eval"}]}"#,
        )
        .unwrap();
        let findings = load_findings(&path).unwrap();
        assert_eq!(findings.security.len(), 1);
        assert!(findings.secrets.is_empty());
    }

    #[test]
    fn loader_rejects_non_reports() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nope.json");
        std::fs::write(&path, r#"{"hello": "world"}"#).unwrap();
        assert!(load_findings(&path).is_err());
        std::fs::write(&path, r#"{"schema_version": 3}"#).unwrap();
        assert!(load_findings(&path).is_err());
    }
}
