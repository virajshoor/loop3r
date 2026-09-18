use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::deps::DepsReport;

#[derive(Debug, Deserialize)]
struct AdvisoryEntry {
    id: String,
    ecosystem: String,
    package: String,
    vulnerable_versions: Vec<String>,
    severity: String,
    summary: String,
    reference: String,
}

#[derive(Debug, Deserialize)]
struct AdvisorySnapshot {
    format_version: u8,
    advisories: Vec<AdvisoryEntry>,
}

#[derive(Debug, Serialize)]
pub struct Vulnerability {
    pub advisory_id: String,
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub severity: String,
    pub summary: String,
    pub reference: String,
    pub lockfile: std::path::PathBuf,
}

pub fn apply_advisory_db(report: &mut DepsReport, path: &Path) -> Result<()> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let snapshot: AdvisorySnapshot =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    if snapshot.format_version != 1 {
        bail!(
            "{}: unsupported advisory format_version {}",
            path.display(),
            snapshot.format_version
        );
    }
    for (index, entry) in snapshot.advisories.iter().enumerate() {
        let location = format!("{} advisory {index}", path.display());
        if entry.id.is_empty() {
            bail!("{location}: id is empty");
        }
        if !matches!(entry.ecosystem.as_str(), "cargo" | "npm") {
            bail!("{location}: ecosystem must be cargo or npm");
        }
        if entry.package.is_empty() {
            bail!("{location}: package is empty");
        }
        if entry.vulnerable_versions.is_empty() {
            bail!("{location}: vulnerable_versions is empty");
        }
        if !matches!(
            entry.severity.as_str(),
            "low" | "medium" | "high" | "critical"
        ) {
            bail!("{location}: severity must be low, medium, high, or critical");
        }
        if entry.summary.is_empty() {
            bail!("{location}: summary is empty");
        }
        if !entry.reference.starts_with("https://") {
            bail!("{location}: reference must use https");
        }
    }
    let mut vulnerabilities = Vec::new();
    for package in &report.packages {
        for entry in &snapshot.advisories {
            if entry.ecosystem == package.ecosystem
                && entry.package == package.name
                && entry.vulnerable_versions.contains(&package.version)
            {
                vulnerabilities.push(Vulnerability {
                    advisory_id: entry.id.clone(),
                    ecosystem: entry.ecosystem.clone(),
                    package: package.name.clone(),
                    version: package.version.clone(),
                    severity: entry.severity.clone(),
                    summary: entry.summary.clone(),
                    reference: entry.reference.clone(),
                    lockfile: package.lockfile.clone(),
                });
            }
        }
    }
    vulnerabilities.sort_by(|a, b| {
        (&a.advisory_id, &a.package, &a.version, &a.lockfile).cmp(&(
            &b.advisory_id,
            &b.package,
            &b.version,
            &b.lockfile,
        ))
    });
    report.advisory_db = Some(path.to_path_buf());
    report.vulnerabilities = vulnerabilities;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::Package;
    use std::path::PathBuf;

    const SNAPSHOT: &str = r#"{
        "format_version": 1,
        "advisories": [
            {"id": "TEST-001", "ecosystem": "cargo", "package": "left-pad",
             "vulnerable_versions": ["1.3.0"], "severity": "high",
             "summary": "Test fixture advisory.", "reference": "https://example.invalid/test-001"},
            {"id": "TEST-002", "ecosystem": "npm", "package": "left-pad",
             "vulnerable_versions": ["9.9.9"], "severity": "medium",
             "summary": "Test fixture advisory.", "reference": "https://example.invalid/test-002"}
        ]
    }"#;

    fn report() -> DepsReport {
        DepsReport {
            schema_version: 2,
            target: PathBuf::from("."),
            lockfiles: vec![],
            packages: vec![Package {
                ecosystem: "cargo",
                name: "left-pad".to_owned(),
                version: "1.3.0".to_owned(),
                source: None,
                lockfile: PathBuf::from("Cargo.lock"),
            }],
            unsupported: vec![],
            errors: vec![],
            advisory_db: None,
            vulnerabilities: vec![],
        }
    }

    #[test]
    fn matches_exact_versions_only() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("snapshot.json");
        std::fs::write(&path, SNAPSHOT).unwrap();
        let mut inventory = report();
        apply_advisory_db(&mut inventory, &path).unwrap();
        assert_eq!(inventory.vulnerabilities.len(), 1);
        assert_eq!(inventory.vulnerabilities[0].advisory_id, "TEST-001");
        assert_eq!(inventory.advisory_db, Some(path));
    }

    #[test]
    fn rejects_malformed_snapshots() {
        let directory = tempfile::tempdir().unwrap();
        for (name, body) in [
            ("version", r#"{"format_version": 99, "advisories": []}"#),
            (
                "severity",
                r#"{"format_version": 1, "advisories": [{"id": "T", "ecosystem": "cargo", "package": "p", "vulnerable_versions": ["1"], "severity": "unknown", "summary": "s", "reference": "https://example.invalid"}]}"#,
            ),
            (
                "reference",
                r#"{"format_version": 1, "advisories": [{"id": "T", "ecosystem": "cargo", "package": "p", "vulnerable_versions": ["1"], "severity": "high", "summary": "s", "reference": "http://example.invalid"}]}"#,
            ),
            (
                "ecosystem",
                r#"{"format_version": 1, "advisories": [{"id": "T", "ecosystem": "pypi", "package": "p", "vulnerable_versions": ["1"], "severity": "high", "summary": "s", "reference": "https://example.invalid"}]}"#,
            ),
        ] {
            let path = directory.path().join(format!("{name}.json"));
            std::fs::write(&path, body).unwrap();
            let mut inventory = report();
            assert!(apply_advisory_db(&mut inventory, &path).is_err(), "{name}");
        }
    }
}
