//! Advisory matching: exact-version vulnerability lookup for inventories.
//!
//! loop3r ships NO advisory data — `--advisory-db` points at a snapshot the
//! user supplies (curated by hand or exported from OSV/RustSec/GHSA), and
//! matching is exact `(ecosystem, package, version)` equality against each
//! advisory's `vulnerable_versions` list. No range evaluation: version-range
//! semantics differ per ecosystem and getting them subtly wrong would both
//! miss real exposures and cry wolf, so the matcher refuses to guess.
//!
//! Like suppressions, the snapshot is validated fail-closed (bad version,
//! ecosystem, severity, or reference aborts the command) and indexed by
//! entry for actionable errors.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::deps::DepsReport;

/// One advisory in the snapshot: who is affected and how badly.
///
/// `vulnerable_versions` is an explicit enumeration, NOT a range — the
/// snapshot producer expands ranges, because only the producer knows the
/// ecosystem's versioning rules.
#[derive(Debug, Deserialize)]
struct AdvisoryEntry {
    /// Advisory identifier (CVE, GHSA, RUSTSEC, or local ID).
    id: String,
    /// `cargo` or `npm` — must match an inventoried ecosystem exactly.
    ecosystem: String,
    /// Package name as spelled in the lockfile.
    package: String,
    /// Exact versions considered vulnerable (no ranges, no globs).
    vulnerable_versions: Vec<String>,
    /// `low`, `medium`, `high`, or `critical`.
    severity: String,
    /// Short description of the flaw.
    summary: String,
    /// HTTPS-only reference URL.
    reference: String,
}

/// Top-level snapshot file. `format_version` gates parsing so future schema
/// changes fail loudly instead of misreading new fields as old ones.
#[derive(Debug, Deserialize)]
struct AdvisorySnapshot {
    /// Snapshot schema version; only `1` is accepted today.
    format_version: u8,
    /// Advisories to match against the inventory.
    advisories: Vec<AdvisoryEntry>,
}

/// One confirmed inventory hit: an installed package at an affected version.
///
/// Carries the advisory metadata plus the lockfile that pinned the version,
/// so remediation knows exactly which lockfile to update.
#[derive(Debug, Serialize)]
pub struct Vulnerability {
    /// Advisory that matched.
    pub advisory_id: String,
    /// Ecosystem of the hit (`cargo`/`npm`).
    pub ecosystem: String,
    /// Package name.
    pub package: String,
    /// Installed (vulnerable) version.
    pub version: String,
    /// Advisory severity.
    pub severity: String,
    /// Advisory summary.
    pub summary: String,
    /// Advisory reference.
    pub reference: String,
    /// Lockfile pinning this package@version.
    pub lockfile: std::path::PathBuf,
}

/// Matches an inventory against an advisory snapshot, recording hits.
///
/// Validation first (every entry, indexed errors), then a nested loop over
/// packages × advisories with exact triple equality. The O(packages ×
/// advisories) scan is fine at real-world sizes (thousands × hundreds), and
/// keeps the code obviously correct — no index to keep in sync. Results sort
/// by (advisory, package, version, lockfile) for deterministic reports, and
/// the snapshot path is recorded so readers know what "no vulnerabilities"
/// was measured against (an empty snapshot and a thorough one both yield
/// zero hits; only the recorded path distinguishes them).
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

    /// Two-advisory fixture: a cargo hit (`left-pad` 1.3.0) and an npm
    /// same-name different-ecosystem/version entry that must NOT match the
    /// cargo-only inventory — proving ecosystem AND version both gate.
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

    /// Single-package cargo inventory pinned at the vulnerable version.
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

    /// Exactly one hit (`TEST-001`): the npm entry misses on ecosystem and
    /// the cargo entry hits on the exact version. Snapshot path is recorded.
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

    /// Wrong format version, unknown severity, non-HTTPS reference, and
    /// unsupported ecosystem each fail the whole command (fail closed —
    /// matching against a half-understood snapshot would lie by omission).
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
