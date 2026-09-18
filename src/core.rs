use anyhow::{Context, Result};
use serde::Deserialize;

use crate::language::LanguageId;

#[derive(Deserialize)]
pub struct AstRule {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub cwe: String,
    pub languages: Vec<LanguageId>,
    pub callees: Vec<String>,
    pub message: String,
    pub references: Vec<String>,
}

pub fn load_ast_rules() -> Result<Vec<AstRule>> {
    let rules: Vec<AstRule> = serde_json::from_str(include_str!("../core/ast-rules.json"))
        .context("loading embedded Core AST rules")?;
    validate(&rules)?;
    Ok(rules)
}

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
