use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tree_sitter::Parser;

use crate::core::AstRule;
use crate::language::LanguageId;
use crate::report::{Confidence, Report, SecurityFinding, SyntaxFinding};
use crate::scope::{Scope, ScopeReport, source_files};

fn child_nodes(node: tree_sitter::Node<'_>) -> Vec<tree_sitter::Node<'_>> {
    let mut cursor = node.walk();
    node.children(&mut cursor).collect()
}

fn is_call(language: LanguageId, kind: &str) -> bool {
    match language {
        LanguageId::Python => kind == "call",
        LanguageId::JavaScript
        | LanguageId::TypeScript
        | LanguageId::Tsx
        | LanguageId::C
        | LanguageId::Go
        | LanguageId::Rust
        | LanguageId::Kotlin
        | LanguageId::Swift => kind == "call_expression",
        LanguageId::Java => kind == "method_invocation",
        LanguageId::CSharp => kind == "invocation_expression",
        LanguageId::Php => matches!(
            kind,
            "function_call_expression"
                | "member_call_expression"
                | "nullsafe_member_call_expression"
                | "scoped_call_expression"
        ),
        LanguageId::Ruby => kind == "call",
        LanguageId::Shell => kind == "command",
        LanguageId::Sql | LanguageId::Html | LanguageId::Css => false,
    }
}

fn callee(node: tree_sitter::Node<'_>, source: &[u8], language: LanguageId) -> Option<String> {
    if language == LanguageId::Shell {
        return node
            .child_by_field_name("name")?
            .utf8_text(source)
            .ok()
            .map(str::to_owned);
    }
    if let Some(arguments) = node.child_by_field_name("arguments") {
        return std::str::from_utf8(&source[node.start_byte()..arguments.start_byte()])
            .ok()
            .map(|text| text.trim().trim_end_matches('(').trim().to_owned());
    }
    let first = node.named_child(0)?;
    first.utf8_text(source).ok().map(str::to_owned)
}

fn callee_matches(actual: &str, expected: &str) -> bool {
    let actual: String = actual.chars().filter(|ch| !ch.is_whitespace()).collect();
    actual == expected
}

#[cfg_attr(test, allow(dead_code))]
fn inspect_tree(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Path,
    language: LanguageId,
    rules: &[AstRule],
    syntax: &mut Vec<SyntaxFinding>,
    security: &mut Vec<SecurityFinding>,
) {
    let mut stack = vec![node];
    let aliases = crate::imports::collect_aliases(node, source, language);
    while let Some(current) = stack.pop() {
        if current.is_error() || current.is_missing() {
            let point = current.start_position();
            syntax.push(SyntaxFinding {
                path: path.to_path_buf(),
                language,
                line: point.row + 1,
                column: point.column + 1,
                node_kind: current.kind().to_owned(),
            });
        }
        if is_call(language, current.kind())
            && let Some(name) = callee(current, source, language)
        {
            let compact: String = name.chars().filter(|ch| !ch.is_whitespace()).collect();
            let canonical = crate::imports::resolve_callee(&compact, &aliases);
            for rule in rules
                .iter()
                .filter(|rule| rule.languages.contains(&language))
            {
                if !rule
                    .callees
                    .iter()
                    .any(|expected| callee_matches(&canonical, expected))
                {
                    continue;
                }
                let point = current.start_position();
                let raw = current.utf8_text(source).unwrap_or("<invalid UTF-8>");
                security.push(SecurityFinding {
                    rule_id: rule.id.clone(),
                    title: rule.title.clone(),
                    severity: rule.severity.clone(),
                    cwe: rule.cwe.clone(),
                    path: path.to_path_buf(),
                    line: point.row + 1,
                    column: point.column + 1,
                    callee: name.clone(),
                    resolved_callee: if canonical != compact {
                        Some(canonical.clone())
                    } else {
                        None
                    },
                    evidence: raw.chars().take(160).collect(),
                    message: rule.message.clone(),
                    references: rule.references.clone(),
                    confidence: if rule.severity == "review" {
                        Confidence::Low
                    } else {
                        Confidence::Medium
                    },
                    suppressed: None,
                });
            }
        }
        stack.extend(child_nodes(current));
    }
}

pub(crate) fn shuffle<T>(items: &mut [T], mut state: u64) {
    for index in (1..items.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        items.swap(index, state as usize % (index + 1));
    }
}

pub fn scan(
    target: &Path,
    max_bytes: u64,
    budget_seconds: u64,
    seed: u64,
    scope: Scope,
) -> Result<Report> {
    if !target.exists() {
        anyhow::bail!("target does not exist: {}", target.display());
    }
    let started = Instant::now();
    let discovery = source_files(target, max_bytes, &scope)?;
    let mut files = discovery.files;
    shuffle(&mut files, seed);
    let mut parser = Parser::new();
    let mut languages = BTreeMap::new();
    let mut syntax_findings = Vec::new();
    let mut security_findings = Vec::new();
    let mut secret_findings = Vec::new();
    let rules = crate::core::load_ast_rules()?;
    let mut files_parsed = 0;
    let mut secret_files_scanned = 0_usize;
    let mut timed_out = false;
    for (path, language) in &files {
        if started.elapsed() >= Duration::from_secs(budget_seconds) {
            timed_out = true;
            break;
        }
        let source = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        secret_findings.extend(crate::secrets::scan_secrets(path, &source));
        parser
            .set_language(&language.grammar())
            .with_context(|| format!("loading {language:?} grammar"))?;
        let tree = parser
            .parse(&source, None)
            .with_context(|| format!("parsing {}", path.display()))?;
        *languages.entry(*language).or_insert(0) += 1;
        files_parsed += 1;
        inspect_tree(
            tree.root_node(),
            &source,
            path,
            *language,
            &rules,
            &mut syntax_findings,
            &mut security_findings,
        );
    }
    for path in &discovery.secret_files {
        if started.elapsed() >= Duration::from_secs(budget_seconds) {
            timed_out = true;
            break;
        }
        let source = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        secret_findings.extend(crate::secrets::scan_secrets(path, &source));
        secret_files_scanned += 1;
    }
    security_findings
        .sort_by(|a, b| (&a.path, a.line, &a.rule_id).cmp(&(&b.path, b.line, &b.rule_id)));
    secret_findings.sort_by(|a, b| (&a.path, a.line, a.rule_id).cmp(&(&b.path, b.line, b.rule_id)));
    syntax_findings.sort_by(|a, b| {
        (&a.path, a.line, a.column, &a.node_kind).cmp(&(&b.path, b.line, b.column, &b.node_kind))
    });
    Ok(Report {
        schema_version: 3,
        files_parsed,
        secret_files_scanned,
        files_skipped_oversized: discovery.skipped_oversized,
        files_skipped_unsupported: discovery.skipped_unsupported,
        languages,
        syntax_findings,
        security_findings,
        secret_findings,
        timed_out,
        seed,
        baseline: None,
        suppressions: crate::report::SuppressionReport::none(),
        scope: ScopeReport {
            target: target.to_path_buf(),
            max_file_bytes: max_bytes,
            budget_seconds,
            include: scope.include_patterns().to_vec(),
            exclude: scope.exclude_patterns().to_vec(),
            languages: scope.languages().to_vec(),
        },
        confidence_scale: crate::report::confidence_scale(),
    })
}

#[cfg(test)]
pub fn inspect_for_tests(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    path: &Path,
    language: LanguageId,
    rules: &[AstRule],
    syntax: &mut Vec<SyntaxFinding>,
    security: &mut Vec<SecurityFinding>,
) {
    inspect_tree(node, source, path, language, rules, syntax, security)
}
