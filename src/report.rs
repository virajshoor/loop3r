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
    pub evidence: String,
    pub message: String,
    pub references: Vec<String>,
    pub confidence: Confidence,
}

#[derive(Serialize)]
pub struct Report {
    pub schema_version: u8,
    pub files_parsed: usize,
    pub languages: BTreeMap<LanguageId, usize>,
    pub syntax_findings: Vec<SyntaxFinding>,
    pub security_findings: Vec<SecurityFinding>,
    pub timed_out: bool,
    pub seed: u64,
    pub scope: super::scope::ScopeReport,
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
