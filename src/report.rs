use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::language::LanguageId;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
    Confirmed,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Confirmed => "confirmed",
        }
    }
}

pub fn confidence_scale() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        (
            "confirmed",
            "active observation directly proves reported condition",
        ),
        (
            "high",
            "parser or protocol evidence directly proves reported construct",
        ),
        (
            "medium",
            "exact dangerous construct found; attacker reachability unproven",
        ),
        (
            "low",
            "security boundary needs review; vulnerability not established",
        ),
    ])
}

#[derive(Debug, Serialize)]
pub struct SecurityFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub cwe: String,
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub callee: String,
    pub resolved_callee: Option<String>,
    pub evidence: String,
    pub message: String,
    pub references: Vec<String>,
    pub confidence: Confidence,
    pub taint: Option<crate::taint::TaintFlow>,
    pub suppressed: Option<SuppressedBy>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SuppressedBy {
    pub reason: String,
    pub owner: String,
    pub expires: String,
}

#[derive(Debug, Serialize)]
pub struct BaselineSummary {
    pub path: PathBuf,
    pub new_security: usize,
    pub new_secrets: usize,
    pub fixed_security: usize,
    pub fixed_secrets: usize,
}

#[derive(Debug, Serialize)]
pub struct SuppressionReport {
    pub file: Option<PathBuf>,
    pub applied: usize,
    pub expired: Vec<String>,
}

impl SuppressionReport {
    pub fn none() -> Self {
        Self {
            file: None,
            applied: 0,
            expired: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SecurityFindingLike {
    pub rule_id: String,
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub callee: String,
}

#[derive(Clone, Debug)]
pub struct SecretFindingLike {
    pub rule_id: String,
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub content_fingerprint: String,
}

impl From<&SecurityFinding> for SecurityFindingLike {
    fn from(finding: &SecurityFinding) -> Self {
        Self {
            rule_id: finding.rule_id.clone(),
            path: finding.path.to_string_lossy().into_owned(),
            line: finding.line,
            column: finding.column,
            callee: finding.callee.clone(),
        }
    }
}

impl From<&super::secrets::SecretFinding> for SecretFindingLike {
    fn from(finding: &super::secrets::SecretFinding) -> Self {
        Self {
            rule_id: finding.rule_id.to_owned(),
            path: finding.path.to_string_lossy().into_owned(),
            line: finding.line,
            column: finding.column,
            content_fingerprint: finding.fingerprint.clone(),
        }
    }
}

#[derive(Serialize)]
pub struct Report {
    pub schema_version: u8,
    pub files_parsed: usize,
    pub secret_files_scanned: usize,
    pub files_skipped_oversized: usize,
    pub files_skipped_unsupported: usize,
    pub languages: BTreeMap<LanguageId, usize>,
    pub syntax_findings: Vec<SyntaxFinding>,
    pub security_findings: Vec<SecurityFinding>,
    pub secret_findings: Vec<super::secrets::SecretFinding>,
    pub timed_out: bool,
    pub seed: u64,
    pub scope: super::scope::ScopeReport,
    pub baseline: Option<BaselineSummary>,
    pub suppressions: SuppressionReport,
    pub confidence_scale: BTreeMap<&'static str, &'static str>,
}

#[derive(Serialize)]
pub struct SyntaxFinding {
    pub path: PathBuf,
    pub language: LanguageId,
    pub line: usize,
    pub column: usize,
    pub node_kind: String,
}

#[derive(Debug, Serialize)]
pub struct WebFinding {
    pub rule_id: &'static str,
    pub severity: &'static str,
    pub message: &'static str,
    pub evidence: String,
    pub reference: &'static str,
    pub confidence: Confidence,
}

#[derive(Debug, Serialize)]
pub struct WebReport {
    pub schema_version: u8,
    pub url: String,
    pub status: u16,
    pub duration_ms: u128,
    pub redirect: Option<String>,
    pub findings: Vec<WebFinding>,
    pub confidence_scale: BTreeMap<&'static str, &'static str>,
}

pub fn write_private(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .context("output path has no filename")?
        .to_string_lossy();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(".{name}.{}.{nonce}.tmp", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    if let Err(error) = (|| -> std::io::Result<()> {
        file.write_all(content)?;
        file.sync_all()
    })() {
        let _ = fs::remove_file(&temporary);
        return Err(error).context("writing report");
    }
    fs::rename(&temporary, path)
        .with_context(|| format!("committing report to {}", path.display()))?;
    Ok(())
}
