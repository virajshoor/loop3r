//! Source scanning pipeline: parse each file, match AST rules, collect secrets.
//!
//! This is the heart of `loop3r scan`. For every in-scope file the pipeline
//! runs secret validators over the raw bytes first (so secrets are found
//! even in files that fail to parse), then parses with the embedded grammar
//! and walks the tree once, collecting syntax errors and rule matches.
//!
//! Matching is structural, never textual: only real call nodes can trigger,
//! which is what keeps comments and string literals from producing findings.
//! The walk is iterative with an explicit stack (no recursion), because
//! adversarial files can nest deeply enough to overflow the call stack.

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

/// Collects a node's children. A fresh cursor per call keeps the borrow
/// checker happy while walking with an explicit stack.
fn child_nodes(node: tree_sitter::Node<'_>) -> Vec<tree_sitter::Node<'_>> {
    let mut cursor = node.walk();
    node.children(&mut cursor).collect()
}

/// Whether a Tree-sitter node kind represents a call in this language.
///
/// Kind names differ per grammar (`call` in Python/Ruby, `call_expression`
/// in most C-like grammars, `method_invocation` in Java, several shapes in
/// PHP, `command` in shell). SQL/HTML/CSS return false: those grammars exist
/// for syntax coverage only and have no sink semantics.
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
        // PHP has distinct nodes for `f()`, `$o->m()`, `$o?->m()`, and
        // `C::m()`; all four can reach the catalogued sinks.
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

/// Extracts the callee text from a call node.
///
/// For most languages this is the source slice before the `arguments` child
/// (trimmed of the opening paren), which preserves dotted paths like
/// `child_process.exec`. Shell has no argument-list field, so the command
/// `name` field is used instead. The fallback (first named child) covers
/// grammars whose call nodes lack an `arguments` field. `None` means "not a
/// recognizable call" and the node is skipped rather than guessed at.
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

/// Exact callee comparison after whitespace removal.
///
/// Exactness is the false-positive guard: `re.compile` must never match a
/// rule for `compile`, and formatting differences (`a.b (x)` vs `a.b(x)`)
/// must not matter. The rule catalog stores already-compact needles.
fn callee_matches(actual: &str, expected: &str) -> bool {
    let actual: String = actual.chars().filter(|ch| !ch.is_whitespace()).collect();
    actual == expected
}

/// Compacts a call's argument-list text for argument-matcher comparison.
///
/// Mirrors [`callee_matches`] normalization (whitespace stripped) and caps
/// the result at 4096 chars so a pathological single call cannot blow up
/// match cost. Shell has no argument-list field, so the whole command text
/// is used; the shell catalog currently has no argument matchers, making
/// this a harmless fallback.
fn compacted_args(node: tree_sitter::Node<'_>, source: &[u8], language: LanguageId) -> String {
    if language == LanguageId::Shell {
        return node
            .utf8_text(source)
            .unwrap_or("")
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .take(4096)
            .collect();
    }
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return String::new();
    };
    arguments
        .utf8_text(source)
        .unwrap_or("")
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .take(4096)
        .collect()
}

/// Walks one parsed file, collecting syntax errors and AST rule matches.
///
/// Per-file setup runs once: import-alias collection and the taint-lite
/// index (both file-local, so no cross-file state leaks between scans).
/// Then a single iterative pass visits every node:
/// - error/missing nodes become [`SyntaxFinding`]s (coverage gaps, not
///   vulnerabilities — they mark code the rules could not evaluate);
/// - call nodes go through callee resolution, rule filtering by language,
///   exact callee match, optional argument matchers, and taint lookup.
///
/// Confidence: any taint trace upgrades the finding to `Medium` (local flow
/// proven, attacker control still unproven); otherwise `review` rules report
/// `Low` and `high` rules `Medium`. Suppressions attach later in `main.rs`,
/// after all findings exist — matching runs on the complete set.
///
/// The `cfg_attr` silences dead-code warnings in test builds, where this
/// function is only reached through [`inspect_for_tests`].
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
    let taint_index = crate::taint::analyze(node, source, language);
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
            // Compact once, then resolve aliases: `run` becomes `os.system`
            // when the file imported it as such, and rules match the
            // canonical form. Both spellings are recorded on the finding.
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
                // Argument text is extracted lazily: most rules have no
                // matchers, and slicing+compacting every call would waste
                // work on the common path.
                if !rule.args_any.is_empty() || !rule.args_none.is_empty() {
                    let args = compacted_args(current, source, language);
                    if !rule.matches_args(&args) {
                        continue;
                    }
                }
                let point = current.start_position();
                let raw = current.utf8_text(source).unwrap_or("<invalid UTF-8>");
                // Taint lookup uses the RAW argument text (word boundaries
                // intact) with the sink's line; unsupported languages always
                // return `None` from an empty index.
                let sink_args = current
                    .child_by_field_name("arguments")
                    .and_then(|arguments| arguments.utf8_text(source).ok())
                    .unwrap_or("");
                let taint = taint_index.flow_for_sink(point.row + 1, sink_args);
                let confidence = if taint.is_some() {
                    Confidence::Medium
                } else if rule.severity == "review" {
                    Confidence::Low
                } else {
                    Confidence::Medium
                };
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
                    confidence,
                    taint,
                    suppressed: None,
                });
            }
        }
        stack.extend(child_nodes(current));
    }
}

/// In-place Fisher-Yates shuffle driven by a xorshift64 PRNG.
///
/// This is NOT cryptography: determinism is the point. A fixed seed replays
/// the exact same file order, which makes budget-expiry partial scans
/// reproducible. Shuffling (rather than sorted order) spreads deadline
/// expiry fairly across the tree instead of always starving the same tail.
pub(crate) fn shuffle<T>(items: &mut [T], mut state: u64) {
    for index in (1..items.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        items.swap(index, state as usize % (index + 1));
    }
}

/// Scans a target (file or directory) and assembles the source report.
///
/// Order of operations: discover files under the scope, shuffle for fair
/// degradation, then per file — secrets on raw bytes, parse, AST inspect —
/// checking the deadline before each file. Secrets-only configs are scanned
/// after parsed files (also under the deadline). Finding lists are sorted
/// before return so output is deterministic regardless of shuffle order.
///
/// Failure policy: a missing target or unreadable file aborts the scan
/// (fail closed — partial results without the caller knowing would be worse
/// than an error), while per-file grammar failures surface as syntax
/// findings, never as panics.
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
    // One parser is reused across files; only the grammar is swapped per
    // file, which avoids repeated allocator setup.
    let mut parser = Parser::new();
    let mut languages = BTreeMap::new();
    let mut syntax_findings = Vec::new();
    let mut security_findings = Vec::new();
    let mut secret_findings = Vec::new();
    // Loading the catalog here (not per file) also means one validation
    // failure aborts before any file is touched.
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
        // Secrets run on raw bytes BEFORE parsing so unparseable files are
        // still checked for leaked credentials.
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
    // Config files (`.env`, JSON, YAML, …) are never parsed — secrets only.
    for path in &discovery.secret_files {
        if started.elapsed() >= Duration::from_secs(budget_seconds) {
            timed_out = true;
            break;
        }
        let source = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        secret_findings.extend(crate::secrets::scan_secrets(path, &source));
        secret_files_scanned += 1;
    }
    // Deterministic order: identical inputs + seed ⇒ identical reports.
    security_findings
        .sort_by(|a, b| (&a.path, a.line, &a.rule_id).cmp(&(&b.path, b.line, &b.rule_id)));
    secret_findings.sort_by(|a, b| (&a.path, a.line, a.rule_id).cmp(&(&b.path, b.line, b.rule_id)));
    syntax_findings.sort_by(|a, b| {
        (&a.path, a.line, a.column, &a.node_kind).cmp(&(&b.path, b.line, b.column, &b.node_kind))
    });
    Ok(Report {
        schema_version: 4,
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
        // Baseline and suppressions apply after scanning (see `main.rs`) so
        // they operate on the complete finding set.
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

/// Test-only entry point to [`inspect_tree`] for fixture-driven rule tests.
///
/// Lets integration tests parse a snippet and assert matches without going
/// through full discovery, keeping rule tests fast and hermetic.
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
