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
    #[serde(default)]
    pub args_any: Vec<String>,
    #[serde(default)]
    pub args_none: Vec<String>,
    pub message: String,
    pub references: Vec<String>,
}

pub fn compact_args(text: &str) -> String {
    text.chars().filter(|ch| !ch.is_whitespace()).collect()
}

impl AstRule {
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

    #[test]
    fn args_matching_ignores_whitespace() {
        let rule = rule_with(vec!["shell = True"], vec![]);
        assert!(rule.matches_args("(cmd,shell=True)"));
        assert!(!rule.matches_args("(cmd,shell=False)"));
        assert!(!rule.matches_args("(cmd)"));
    }

    #[test]
    fn args_none_blocks_matches() {
        let rule = rule_with(vec![], vec!["SafeLoader"]);
        assert!(rule.matches_args("(data)"));
        assert!(!rule.matches_args("(data,Loader=yaml.SafeLoader)"));
    }

    #[test]
    fn empty_matchers_match_everything() {
        let rule = rule_with(vec![], vec![]);
        assert!(rule.matches_args(""));
        assert!(rule.matches_args("(anything)"));
    }
}
