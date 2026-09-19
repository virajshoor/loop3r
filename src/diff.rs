//! Baseline and diff: "what changed between two reports?"
//!
//! Both features rest on fingerprints (`fingerprint.rs`): a baseline records
//! which fingerprints existed before, and `diff` partitions two reports into
//! added/fixed/unchanged sets. Loading is deliberately TOLERANT — any JSON
//! object with a `schema_version` and finding lists loads, missing fields
//! default — so v3 reports still diff against v4 output after the taint
//! upgrade, and hand-written minimal reports work for testing.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::Value;

use crate::fingerprint::{secret_fingerprint, security_fingerprint};
use crate::report::{BaselineSummary, Report, SecretFindingLike, SecurityFindingLike};

/// Lenient string field extraction: missing or non-string values become `""`.
/// Tolerant loading keeps old-schema and minimal reports diffable.
fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

/// Lenient integer field extraction: missing or non-integer values become 0.
fn number(value: &Value, key: &str) -> usize {
    value.get(key).and_then(Value::as_u64).unwrap_or(0) as usize
}

/// Projects a raw JSON security finding onto its fingerprint inputs.
/// Unknown extra fields (e.g. v4 `taint`) are ignored by construction.
fn security_like(value: &Value) -> SecurityFindingLike {
    SecurityFindingLike {
        rule_id: text(value, "rule_id"),
        path: text(value, "path"),
        line: number(value, "line"),
        column: number(value, "column"),
        callee: text(value, "callee"),
    }
}

/// Projects a raw JSON secret finding onto its fingerprint inputs.
fn secret_like(value: &Value) -> SecretFindingLike {
    SecretFindingLike {
        rule_id: text(value, "rule_id"),
        path: text(value, "path"),
        line: number(value, "line"),
        column: number(value, "column"),
        content_fingerprint: text(value, "fingerprint"),
    }
}

/// Raw finding lists from a loaded report, kept as JSON so `diff` can echo
/// the full original objects (whatever schema version they came from).
pub struct ReportFindings {
    /// Raw `security_findings` array (possibly empty, never missing-checked).
    pub security: Vec<Value>,
    /// Raw `secret_findings` array.
    pub secrets: Vec<Value>,
}

/// Loads finding lists from a report file, tolerating schema versions.
///
/// Requires only: a JSON object, a numeric `schema_version` (any value — its
/// presence proves "this is a loop3r report"), and at least one of the two
/// finding lists. Everything else degrades gracefully, which is what makes
/// cross-version diffing and minimal hand-written fixtures work.
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

/// Fingerprint sets for set-difference arithmetic. `BTreeSet` keeps
/// iteration deterministic (used only for counts, but determinism is free).
#[derive(Default)]
pub struct BaselineSets {
    /// Security finding fingerprints.
    pub security: BTreeSet<String>,
    /// Secret finding fingerprints.
    pub secrets: BTreeSet<String>,
}

/// Fingerprints a loaded (JSON) report's findings.
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

/// Fingerprints a live (in-memory) report's findings via the `From` projections.
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

/// Compares a live report against a baseline file, recording the summary.
///
/// Set differences in both directions give new (current − baseline) and
/// fixed (baseline − current) counts; the sets are also returned so the
/// caller can gate the exit code on new findings. Suppressions do NOT affect
/// these counts — baseline math is purely fingerprint-based, and suppression
/// interplay happens in [`has_unsuppressed_new`].
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

/// Whether the report contains any finding that should fail the build: alive
/// (not suppressed) AND new (absent from the baseline, when one exists).
///
/// With no baseline, every unsuppressed finding gates. With a baseline, only
/// unsuppressed findings with fresh fingerprints gate — pre-existing findings
/// (even unsuppressed) are grandfathered until fixed. This is the "ratchet":
/// CI passes on legacy debt but fails on new issues.
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

/// Source-report comparison (schema diff-v1).
///
/// Added/fixed entries are the FULL original JSON objects (not
/// re-serialized structs), preserving whatever schema version each side had.
#[derive(Serialize)]
pub struct DiffReport {
    /// Schema version (`1`).
    pub schema_version: u8,
    /// Old (baseline-side) report path.
    pub old: PathBuf,
    /// New (current-side) report path.
    pub new: PathBuf,
    /// Security findings in new but not old.
    pub added_security: Vec<Value>,
    /// Security findings in old but not new.
    pub fixed_security: Vec<Value>,
    /// Secret findings in new but not old.
    pub added_secrets: Vec<Value>,
    /// Secret findings in old but not new.
    pub fixed_secrets: Vec<Value>,
    /// New-side security findings also present in old.
    pub unchanged_security: usize,
    /// New-side secret findings also present in old.
    pub unchanged_secrets: usize,
}

/// Compares two report files by fingerprint.
///
/// Each side loads tolerantly (mixed versions OK), then added = new − old
/// and fixed = old − new per family, with original JSON objects preserved.
/// Unchanged counts derive from lengths rather than a third pass.
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

    /// A minimal v1-shaped report (only security findings, sparse fields)
    /// loads fine: missing secret list defaults to empty.
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

    /// Non-reports are rejected: arbitrary JSON (no version) and a bare
    /// version with no finding lists both fail.
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
