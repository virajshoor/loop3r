//! Report model: finding structs, confidence scale, and safe output writing.
//!
//! This module defines the in-memory shape of every report the scanner emits
//! (source [`Report`], web [`WebReport`]) plus the [`Confidence`] scale that
//! travels inside each report so consumers never have to guess what a level
//! means. Serialization field names are API: the checked-in JSON schemas in
//! `schema/` pin them, and `schema.rs` conformance tests fail on drift.
//!
//! Two product rules live here. First, severity (impact) and confidence
//! (evidence strength) are always separate fields — a `high`-severity sink
//! with unproven reachability must not look "confirmed". Second, reports may
//! contain source excerpts but never secret values, and [`write_private`]
//! stores them with owner-only permissions via atomic rename.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::language::LanguageId;

/// Evidence strength for a finding, independent of severity.
///
/// Serialized lowercase to match the `confidence_scale` keys and the JSON
/// schemas. `Copy` because findings are cheap to classify and the value is
/// passed around during SARIF mapping.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Security boundary needs human review; no vulnerability established.
    /// Default for AST `review` findings without a taint trace.
    Low,
    /// Exact dangerous construct found, but attacker reachability is unproven.
    /// Default for AST `high` findings and tainted `review` findings.
    Medium,
    /// Parser or protocol evidence directly proves the reported construct
    /// (secrets, header/cookie observations).
    High,
    /// Active observation directly proves the reported condition. Only used
    /// for credentialed CORS reflection, and even then it proves the header
    /// behaviour only — not data exposure.
    Confirmed,
}

impl Confidence {
    /// String form matching the serialized representation, for SARIF
    /// properties and human summaries without a serde round-trip.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Confirmed => "confirmed",
        }
    }
}

/// The confidence scale embedded in every report.
///
/// `BTreeMap` keeps the four levels in alphabetical order for stable output.
/// The wording here is also the contract other docs quote; changing a
/// definition is a semantic version consideration.
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

/// One AST rule match: a dangerous call proven present by the parser.
#[derive(Debug, Serialize)]
pub struct SecurityFinding {
    /// Catalog rule ID, e.g. `CORE-PY-EVAL`.
    pub rule_id: String,
    /// Human title copied from the rule at match time (reports stay
    /// readable even if the catalog later renames the rule).
    pub title: String,
    /// Impact: `high` or `review`. Never conflated with confidence.
    pub severity: String,
    /// Weakness class, e.g. `CWE-78`.
    pub cwe: String,
    /// File containing the match, as discovered (not canonicalized, so
    /// output is stable across machines).
    pub path: PathBuf,
    /// 1-based line of the call node.
    pub line: usize,
    /// 1-based column of the call node.
    pub column: usize,
    /// Callee exactly as written in source.
    pub callee: String,
    /// Canonical callee when an import alias applied (`run` → `os.system`);
    /// `None` when the written name matched directly.
    pub resolved_callee: Option<String>,
    /// Matched node text truncated to 160 chars — enough to locate the sink,
    /// bounded so one giant line cannot bloat the report.
    pub evidence: String,
    /// Remediation guidance copied from the rule.
    pub message: String,
    /// Supporting references copied from the rule.
    pub references: Vec<String>,
    /// Evidence strength; see [`Confidence`].
    pub confidence: Confidence,
    /// Same-function data-flow trace when taint-lite connected a parameter
    /// or input call to this sink. Proves local flow, not attacker control.
    pub taint: Option<crate::taint::TaintFlow>,
    /// Justification attached when a suppression entry matched; the finding
    /// itself is never removed, only annotated.
    pub suppressed: Option<SuppressedBy>,
}

/// Justification attached to a suppressed finding.
///
/// All three fields are required in the suppression file: anonymous or
/// undated suppressions are rejected at load time so audit trails stay
/// complete.
#[derive(Clone, Debug, Serialize)]
pub struct SuppressedBy {
    /// Why this finding is accepted (review note, ticket, rationale).
    pub reason: String,
    /// Person or team accountable for the decision.
    pub owner: String,
    /// `YYYY-MM-DD` expiry; past dates are reported as expired and ignored.
    pub expires: String,
}

/// New/fixed counts after comparing the current scan against a baseline.
///
/// Counts only — the full added/fixed objects live in `diff` reports, while
/// baselines only change which findings gate the exit code.
#[derive(Debug, Serialize)]
pub struct BaselineSummary {
    /// Baseline report path, recorded so readers know what "new" means.
    pub path: PathBuf,
    /// Security findings not present in the baseline.
    pub new_security: usize,
    /// Secret findings not present in the baseline.
    pub new_secrets: usize,
    /// Baseline security findings no longer present.
    pub fixed_security: usize,
    /// Baseline secret findings no longer present.
    pub fixed_secrets: usize,
}

/// Audit trail for `--suppress`: what file applied, to how many findings,
/// and which entries had expired (expired entries never suppress).
#[derive(Debug, Serialize)]
pub struct SuppressionReport {
    /// Suppression file path, or `None` when `--suppress` was not passed.
    pub file: Option<PathBuf>,
    /// Findings that gained a `suppressed` annotation.
    pub applied: usize,
    /// `rule_id path-glob` identifiers of expired entries, for cleanup.
    pub expired: Vec<String>,
}

impl SuppressionReport {
    /// Empty report for scans run without `--suppress`.
    pub fn none() -> Self {
        Self {
            file: None,
            applied: 0,
            expired: Vec::new(),
        }
    }
}

/// Minimal security-finding view used ONLY for fingerprinting.
///
/// The field list is the stability contract: anything added here (evidence,
/// confidence, taint) would churn baselines on scanner upgrades. New inputs
/// require a deliberate decision, not an accidental `#[derive(Hash)]`.
#[derive(Clone, Debug)]
pub struct SecurityFindingLike {
    /// Rule ID — same sink under two rules is two distinct findings.
    pub rule_id: String,
    /// Path as a lossy string; fingerprints must be computable from JSON
    /// reports where paths are already strings.
    pub path: String,
    /// 1-based line; moving code re-fingerprints (honest fixed+new).
    pub line: usize,
    /// 1-based column; distinguishes multiple sinks on one line.
    pub column: usize,
    /// Written callee; distinguishes adjacent different sinks.
    pub callee: String,
}

/// Minimal secret-finding view used ONLY for fingerprinting.
///
/// Carries the content hash (not the secret) so rotation changes the
/// fingerprint while the secret value itself never leaves `secrets.rs`.
#[derive(Clone, Debug)]
pub struct SecretFindingLike {
    /// Rule ID, e.g. `SECRET-AWS-ACCESS-KEY`.
    pub rule_id: String,
    /// Path as a lossy string, for JSON-round-tripped reports.
    pub path: String,
    /// 1-based line of the match.
    pub line: usize,
    /// 1-based column of the match.
    pub column: usize,
    /// FNV hash of the matched material; rotation must re-fingerprint.
    pub content_fingerprint: String,
}

impl From<&SecurityFinding> for SecurityFindingLike {
    /// Projects a live finding onto its fingerprint inputs, dropping
    /// everything (evidence, confidence, taint, suppression) that must not
    /// affect baseline stability.
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
    /// Projects a live secret finding onto its fingerprint inputs. Note the
    /// secret value itself is never touched — only its precomputed hash.
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

/// Top-level source scan report (schema v4).
///
/// Field order and names are pinned by `schema/scan-v4.schema.json`.
/// Finding lists arrive pre-sorted (path, line, rule) so identical inputs
/// produce byte-identical reports under a fixed seed.
#[derive(Serialize)]
pub struct Report {
    /// Schema version (`4`); bumped only for breaking report changes.
    pub schema_version: u8,
    /// Files successfully parsed before the budget expired.
    pub files_parsed: usize,
    /// Config files scanned for secrets without parsing.
    pub secret_files_scanned: usize,
    /// Directory-walk files skipped for exceeding `--max-file-bytes`.
    pub files_skipped_oversized: usize,
    /// Directory-walk files skipped for unknown extensions.
    pub files_skipped_unsupported: usize,
    /// Per-language parsed-file counts; gaps here explain "no findings".
    pub languages: BTreeMap<LanguageId, usize>,
    /// Grammar error/missing nodes — unparseable regions the AST rules
    /// could not see. "No findings" alongside syntax findings is not clean.
    pub syntax_findings: Vec<SyntaxFinding>,
    /// AST rule matches.
    pub security_findings: Vec<SecurityFinding>,
    /// Secret validator matches (redacted evidence only).
    pub secret_findings: Vec<super::secrets::SecretFinding>,
    /// True when the budget expired mid-scan; results are partial by design.
    pub timed_out: bool,
    /// Shuffle seed used for file order (reproduces partial scans).
    pub seed: u64,
    /// The scope this report was produced under (target, caps, filters).
    pub scope: super::scope::ScopeReport,
    /// Baseline comparison, when `--baseline` was passed.
    pub baseline: Option<BaselineSummary>,
    /// Suppression audit trail (empty when `--suppress` was not passed).
    pub suppressions: SuppressionReport,
    /// Confidence definitions; see [`confidence_scale`].
    pub confidence_scale: BTreeMap<&'static str, &'static str>,
}

/// One unparsable region: the grammar reported an error or missing node.
///
/// These are coverage gaps, not vulnerabilities — but they mark code the
/// AST rules could not evaluate, so they ship in the report rather than a log.
#[derive(Serialize)]
pub struct SyntaxFinding {
    /// File containing the syntax error.
    pub path: PathBuf,
    /// Grammar that failed to parse it.
    pub language: LanguageId,
    /// 1-based line of the error node.
    pub line: usize,
    /// 1-based column of the error node.
    pub column: usize,
    /// Tree-sitter node kind (e.g. `ERROR`) for grammar debugging.
    pub node_kind: String,
}

/// One passive web observation from the single loopback GET.
#[derive(Debug, Serialize)]
pub struct WebFinding {
    /// Web rule ID, e.g. `WEB-XCTO`.
    pub rule_id: &'static str,
    /// Impact: `high`, `medium`, or `review`.
    pub severity: &'static str,
    /// Remediation guidance.
    pub message: &'static str,
    /// Header evidence (never bodies or credentials).
    pub evidence: String,
    /// Supporting reference.
    pub reference: &'static str,
    /// Usually `high`; `confirmed` only for observed CORS reflection.
    pub confidence: Confidence,
}

/// Top-level web probe report (schema v1).
#[derive(Debug, Serialize)]
pub struct WebReport {
    /// Schema version (`1`).
    pub schema_version: u8,
    /// Normalized request URL that was probed.
    pub url: String,
    /// HTTP status of the single response.
    pub status: u16,
    /// Request round-trip time in milliseconds.
    pub duration_ms: u128,
    /// Sanitized 3xx `Location`, reported but never followed.
    pub redirect: Option<String>,
    /// Header/cookie/CORS observations.
    pub findings: Vec<WebFinding>,
    /// Confidence definitions; see [`confidence_scale`].
    pub confidence_scale: BTreeMap<&'static str, &'static str>,
}

/// Writes report bytes to `path` atomically with owner-only permissions.
///
/// Protocol: create a uniquely named temp file in the same directory with
/// `O_CREAT|O_EXCL` (no symlink following, no clobber races) and mode `0600`
/// on Unix, write + fsync, then `rename` over the destination. Readers
/// therefore see either the old report or the complete new one — never a
/// partial file — and other users cannot read findings that may quote
/// source code. The temp name embeds the PID and a nanos timestamp so
/// concurrent scans never share it; on any failure the temp file is removed
/// and the destination untouched. The `0600` mode is a Unix-only concept,
/// hence the `cfg(unix)` gate (Windows relies on default ACLs).
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
