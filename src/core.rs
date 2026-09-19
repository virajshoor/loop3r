//! Core AST rule catalog: loading, validation, and argument matching.
//!
//! Rules live in `core/ast-rules.json` and are baked into the binary with
//! `include_str!`, so scanning works offline and the catalog can never drift
//! from the binary at runtime. Each rule names dangerous callees per
//! language plus optional argument matchers that distinguish dangerous from
//! safe spellings (`shell=True` vs `shell=False`).
//!
//! Validation is fail-closed: any malformed rule (duplicate ID, bad CWE,
//! empty matcher, non-HTTPS reference) aborts the whole scan rather than
//! silently running with a degraded catalog. The test suite additionally
//! requires every rule to fire on a real-grammar fixture.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::language::LanguageId;

/// One AST rule from the embedded catalog.
///
/// Matching is two-stage: the canonical callee must exactly equal one of
/// `callees` (see `source.rs`), then [`AstRule::matches_args`] must accept
/// the call's argument list. Rules without argument matchers skip stage two.
#[derive(Deserialize)]
pub struct AstRule {
    /// Stable identifier, e.g. `CORE-PY-EVAL`. Unique across the catalog and
    /// referenced by suppressions, baselines, and SARIF rules.
    pub id: String,
    /// Short human title used in reports and SARIF metadata.
    pub title: String,
    /// Impact level: exactly `high` or `review`. Never `medium` — that level
    /// is reserved for web hardening gaps.
    pub severity: String,
    /// Weakness class in `CWE-NNN` form.
    pub cwe: String,
    /// Languages this rule applies to; matching is skipped for all others.
    pub languages: Vec<LanguageId>,
    /// Canonical callee spellings (post alias-resolution) that trigger.
    pub callees: Vec<String>,
    /// Optional allowlist: at least one entry must appear in the compacted
    /// argument text. Empty means "no constraint".
    #[serde(default)]
    pub args_any: Vec<String>,
    /// Optional blocklist: no entry may appear in the compacted argument
    /// text. Used for safe-spelling carve-outs like `SafeLoader`.
    #[serde(default)]
    pub args_none: Vec<String>,
    /// Remediation guidance shown to the user.
    pub message: String,
    /// HTTPS-only supporting references (CWE entries, advisories, docs).
    pub references: Vec<String>,
}

/// Normalizes text for argument comparison by stripping all whitespace.
///
/// Both rule needles and call-site argument text go through this function,
/// so `shell = True` in source matches a `shell=True` needle regardless of
/// formatting. Case is preserved: `SafeLoader` must not match `safeloader`.
pub fn compact_args(text: &str) -> String {
    text.chars().filter(|ch| !ch.is_whitespace()).collect()
}

impl AstRule {
    /// Checks compacted call-site arguments against this rule's matchers.
    ///
    /// `compacted_args` must already be [`compact_args`]-normalized by the
    /// caller (done once per call node in `source.rs`). Semantics: all of
    /// `args_none` must be absent, and — only when `args_any` is non-empty —
    /// at least one `args_any` entry must be present. Empty needles can never
    /// match, which keeps a degenerate catalog entry from matching
    /// everything (validation rejects such entries anyway).
    pub fn matches_args(&self, compacted_args: &str) -> bool {
        if !self.args_any.is_empty() {
            let mut hit = false;
            for needle in &self.args_any {
                let compacted_needle = compact_args(needle);
                if !compacted_needle.is_empty() && compacted_args.contains(&compacted_needle) {
                    hit = true;
                    break;
                }
            }
            if !hit {
                return false;
            }
        }
        for needle in &self.args_none {
            let compacted_needle = compact_args(needle);
            if !compacted_needle.is_empty() && compacted_args.contains(&compacted_needle) {
                return false;
            }
        }
        true
    }
}

/// Loads and validates the embedded rule catalog.
///
/// The `include_str!` path is relative to this file (`src/`), hence `../core/`.
/// Any validation failure is fatal: a partially trusted catalog would let
/// scans silently miss entire vulnerability classes.
pub fn load_ast_rules() -> Result<Vec<AstRule>> {
    let rules: Vec<AstRule> = serde_json::from_str(include_str!("../core/ast-rules.json"))
        .context("loading embedded Core AST rules")?;
    validate(&rules)?;
    Ok(rules)
}

/// Rejects malformed catalogs before they can weaken a scan.
///
/// Checks, in order: unique IDs (duplicates would double-report or shadow),
/// known severities, well-formed `CWE-NNN` codes, non-empty language and
/// callee lists (an empty list would make the rule dead or universal),
/// sane argument matchers (non-empty after compaction, capped at 128 chars
/// to bound match cost), and HTTPS-only references (reports link users to
/// these; plain HTTP would be a downgrade vector for security guidance).
fn validate(rules: &[AstRule]) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    for rule in rules {
        if !ids.insert(rule.id.as_str()) {
            anyhow::bail!("duplicate AST rule id: {}", rule.id);
        }
        if !matches!(rule.severity.as_str(), "high" | "review") {
            anyhow::bail!("unsupported severity in {}: {}", rule.id, rule.severity);
        }
        let digits = rule
            .cwe
            .strip_prefix("CWE-")
            .context(format!("invalid CWE in {}: {}", rule.id, rule.cwe))?;
        if digits.is_empty() || !digits.chars().all(|ch| ch.is_ascii_digit()) {
            anyhow::bail!("invalid CWE in {}: {}", rule.id, rule.cwe);
        }
        if rule.languages.is_empty() {
            anyhow::bail!("rule {} has no languages", rule.id);
        }
        if rule.callees.is_empty() {
            anyhow::bail!("rule {} has no callees", rule.id);
        }
        for needle in rule.args_any.iter().chain(rule.args_none.iter()) {
            let compacted = compact_args(needle);
            if compacted.is_empty() || compacted.len() > 128 {
                anyhow::bail!("rule {} has an invalid args matcher", rule.id);
            }
        }
        if rule
            .references
            .iter()
            .any(|url| !url.starts_with("https://"))
        {
            anyhow::bail!("rule {} has a non-HTTPS reference", rule.id);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal rule with only the argument matchers varying, so
    /// each test isolates matcher semantics from catalog validation.
    fn rule_with(args_any: Vec<&str>, args_none: Vec<&str>) -> AstRule {
        AstRule {
            id: "TEST".to_owned(),
            title: "t".to_owned(),
            severity: "high".to_owned(),
            cwe: "CWE-78".to_owned(),
            languages: vec![LanguageId::Python],
            callees: vec!["f".to_owned()],
            args_any: args_any.into_iter().map(str::to_owned).collect(),
            args_none: args_none.into_iter().map(str::to_owned).collect(),
            message: "m".to_owned(),
            references: vec!["https://example.invalid".to_owned()],
        }
    }

    /// Needles with spaces match compacted call text; `shell=False` and a
    /// bare call correctly miss a `shell=True` requirement.
    #[test]
    fn args_matching_ignores_whitespace() {
        let rule = rule_with(vec!["shell = True"], vec![]);
        assert!(rule.matches_args("(cmd,shell=True)"));
        assert!(!rule.matches_args("(cmd,shell=False)"));
        assert!(!rule.matches_args("(cmd)"));
    }

    /// A blocklist entry suppresses the match only when present: bare
    /// `yaml.load(data)` fires, the `SafeLoader` spelling does not.
    #[test]
    fn args_none_blocks_matches() {
        let rule = rule_with(vec![], vec!["SafeLoader"]);
        assert!(rule.matches_args("(data)"));
        assert!(!rule.matches_args("(data,Loader=yaml.SafeLoader)"));
    }

    /// Rules without matchers accept every argument list, including empty —
    /// backward compatibility for the original callee-only rules.
    #[test]
    fn empty_matchers_match_everything() {
        let rule = rule_with(vec![], vec![]);
        assert!(rule.matches_args(""));
        assert!(rule.matches_args("(anything)"));
    }
}
