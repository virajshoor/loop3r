//! Taint-lite: same-function data-flow traces for Python and JavaScript/TS.
//!
//! Full interprocedural taint tracking is explicitly out of scope; this
//! module answers a deliberately narrow question: "does a value from this
//! function's parameters (or an input call) reach this sink through local
//! assignments?" A positive answer upgrades a `review` finding to `medium`
//! confidence and attaches the trace. It proves LOCAL flow only — never
//! attacker control, never cross-function or cross-file flow.
//!
//! Design notes: the analysis is syntactic (identifier tokens in right-hand
//! sides, not a CFG), flow-insensitive within a bounded fixpoint, and every
//! dimension is capped (`MAX_*`) so adversarial files cannot blow up scan
//! time. Unsupported languages get an empty index: no traces, no noise.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::language::LanguageId;

/// Cap on functions analyzed per file; beyond this the file is too
/// machine-generated to yield trustworthy traces anyway.
const MAX_FUNCTIONS: usize = 512;
/// Cap on AST nodes visited while collecting one function's assignments.
/// Bounds work on deeply nested generated code.
const MAX_NODES_PER_FUNCTION: usize = 2000;
/// Cap on tracked variables per function (params + derived).
const MAX_VARS: usize = 256;
/// Fixpoint iterations for propagation chains (`a→b→c→…`). Eight covers
/// realistic local chains; longer ones are rare and still partially traced.
const MAX_PASSES: usize = 8;
/// Cap on identifiers extracted from any single text fragment, bounding the
/// tokenizer on huge expressions.
const MAX_IDENTIFIERS: usize = 64;

/// A proven same-function flow from a source into a sink's argument.
///
/// Serialized into findings (schema v4) and SARIF properties. The `source`
/// string is a human-readable chain (`parameter \`cmd\` flows into \`full\``),
/// not a machine path — consumers must not parse it.
#[derive(Clone, Debug, Serialize)]
pub struct TaintFlow {
    /// 1-based line where the taint originated (parameter list or source call).
    pub source_line: usize,
    /// Human-readable origin + propagation chain description.
    pub source: String,
    /// Tainted variable name as it appears in the sink's arguments.
    pub variable: String,
}

/// One function's analyzed state: its line span plus every variable known
/// tainted, each mapped to its origin (line + description).
#[derive(Clone, Debug)]
struct Scope {
    /// 1-based first line of the function node.
    start_line: usize,
    /// 1-based last line of the function node.
    end_line: usize,
    /// Variable → (origin line, origin description).
    tainted: BTreeMap<String, (usize, String)>,
}

/// Per-file taint database built once in `source.rs`, then queried per sink.
///
/// Empty for unsupported languages, so callers need no language checks.
#[derive(Debug, Default)]
pub struct TaintIndex {
    /// Analyzed function scopes; nested functions appear as separate scopes
    /// and the innermost match wins at query time.
    scopes: Vec<Scope>,
}

/// Languages with taint support: Python and the JS/TS family. These were
/// chosen because they share the alias-resolution investment in `imports.rs`
/// and cover the highest-value sink rules; adding a language needs function,
/// parameter, and assignment node mappings below.
fn is_supported(language: LanguageId) -> bool {
    matches!(
        language,
        LanguageId::Python | LanguageId::JavaScript | LanguageId::TypeScript | LanguageId::Tsx
    )
}

/// Whether a Tree-sitter node kind opens a new taint scope.
///
/// Python has one function form; JS/TS has several (declarations,
/// expressions, arrows, methods, generators) that all bind parameters and
/// therefore all need scopes.
fn is_function_node(language: LanguageId, kind: &str) -> bool {
    match language {
        LanguageId::Python => kind == "function_definition",
        LanguageId::JavaScript | LanguageId::TypeScript | LanguageId::Tsx => matches!(
            kind,
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "generator_function_declaration"
        ),
        _ => false,
    }
}

/// Node source slice, tolerating invalid UTF-8 as empty (a file with bad
/// bytes still scans; only the affected slice loses taint precision).
fn node_text(node: tree_sitter::Node<'_>, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_owned()
}

/// ASCII identifier character test. Unicode identifiers are ignored on
/// purpose: sinks and sources are ASCII, and byte-wise ASCII keeps the
/// tokenizer total without grapheme edge cases.
fn is_identifier_char(ch: char, first: bool) -> bool {
    if first {
        ch == '_' || ch.is_ascii_alphabetic()
    } else {
        ch == '_' || ch.is_ascii_alphanumeric()
    }
}

/// Extracts identifier tokens from a text fragment (capped at 64).
///
/// Used for parameter lists, assignment sides, and sink arguments. Keywords
/// are NOT filtered: a keyword can never be a tainted variable name, so it
/// simply never matches the taint map — filtering would add maintenance for
/// zero precision gain.
fn identifiers(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut current = String::new();
    for ch in text.chars() {
        // Whether `ch` continues the token depends on position: the first
        // character cannot be a digit.
        let continues = if current.is_empty() {
            is_identifier_char(ch, true)
        } else {
            is_identifier_char(ch, false)
        };
        if continues {
            current.push(ch);
            continue;
        }
        // Token boundary: record the finished token if there is room,
        // otherwise discard it (clearing keeps `current` empty so the next
        // identifier-start still begins a fresh token attempt).
        if !current.is_empty() && out.len() < MAX_IDENTIFIERS {
            out.insert(std::mem::take(&mut current));
        } else {
            current.clear();
        }
    }
    if !current.is_empty() && out.len() < MAX_IDENTIFIERS {
        out.insert(current);
    }
    out
}

/// Tree-sitter field name holding a function's parameters.
///
/// Both supported grammars use `parameters` (verified against actual parse
/// trees — the node KIND is `formal_parameters` in JS, but the FIELD is
/// `parameters`). Kept as a function so future languages can diverge.
fn params_field(_language: LanguageId) -> &'static str {
    "parameters"
}

/// Collects a function's parameter names as initial taint sources.
///
/// `self`/`cls`/`this` are excluded: methods flowing their receiver into a
/// sink is near-universal and almost never the vulnerability. Default values
/// and annotations are harmless — extra identifiers in the parameter text
/// (e.g. a default `os.getcwd`) merely seed additional taint, which can only
/// add traces for values that genuinely derive from the signature line.
fn collect_params(
    function: tree_sitter::Node<'_>,
    source: &[u8],
    language: LanguageId,
) -> Vec<(String, usize)> {
    let Some(params) = function.child_by_field_name(params_field(language)) else {
        return Vec::new();
    };
    let text = node_text(params, source);
    let line = params.start_position().row + 1;
    identifiers(&text)
        .into_iter()
        .filter(|name| name != "self" && name != "cls" && name != "this")
        .take(MAX_VARS)
        .map(|name| (name, line))
        .collect()
}

/// Detects a direct input source in an assignment's right-hand side.
///
/// Markers cover stdin (`input(`), CLI args (`sys.argv`, `process.argv`),
/// and web request objects (`req.query/body/params`, `request.`). Substring
/// matching is deliberate: `request.args.get(` contains `request.`, and
/// over-matching here only seeds taint that still must reach a sink to
/// matter. Returns the matched marker for the trace description.
fn direct_source_marker(rhs: &str) -> Option<&'static str> {
    [
        "input(",
        "sys.argv",
        "process.argv",
        "req.query",
        "req.body",
        "req.params",
        "request.",
    ]
    .into_iter()
    .find(|marker| rhs.contains(marker))
}

/// Whether an assignment's right-hand side sanitizes its inputs.
///
/// Currently only `shlex.quote` — the one sanitizer with unambiguous shell
/// semantics. This list grows only with sanitizers that are total for their
/// sink family; a partial sanitizer here would create false negatives.
fn is_sanitized(rhs: &str) -> bool {
    rhs.contains("shlex.quote")
}

/// One simple assignment inside a function: single-identifier target plus
/// the raw right-hand-side text (analyzed textually, not structurally).
#[derive(Clone, Debug)]
struct Assignment {
    /// Target variable name.
    target: String,
    /// Right-hand-side source text, scanned for tainted identifiers.
    rhs: String,
    /// 1-based line, used when this assignment introduces a direct source.
    line: usize,
}

/// Collects simple assignments within a function, skipping nested functions.
///
/// Only single-identifier targets are kept: destructuring, attribute, and
/// subscript targets have aliasing semantics this syntactic analysis cannot
/// model, and guessing would fabricate flows. Traversal is bounded by node
/// count and result size; nested function bodies are skipped because their
/// locals belong to their own scope.
fn collect_assignments(
    function: tree_sitter::Node<'_>,
    source: &[u8],
    language: LanguageId,
) -> Vec<Assignment> {
    let mut out = Vec::new();
    let mut stack = vec![function];
    let mut visited = 0_usize;
    while let Some(node) = stack.pop() {
        visited += 1;
        if visited > MAX_NODES_PER_FUNCTION {
            break;
        }
        // Do not descend into nested functions: their assignments belong to
        // the inner scope, analyzed separately.
        if node.id() != function.id() && is_function_node(language, node.kind()) {
            continue;
        }
        match node.kind() {
            // Python `x = …` and `x += …` (both have left/right fields).
            "assignment" | "augmented_assignment" => {
                let target = node
                    .child_by_field_name("left")
                    .map(|left| node_text(left, source));
                let rhs = node
                    .child_by_field_name("right")
                    .map(|right| node_text(right, source));
                if let (Some(target), Some(rhs)) = (target, rhs) {
                    let target = target.trim().to_owned();
                    // Accept only a lone identifier: the target text must be
                    // exactly one identifier's worth of characters.
                    if target.len() == identifiers(&target).iter().map(String::len).sum::<usize>()
                        && identifiers(&target).len() == 1
                    {
                        out.push(Assignment {
                            target,
                            rhs,
                            line: node.start_position().row + 1,
                        });
                    }
                }
            }
            // JS `const/let/var x = …` (declarations without `value`, like
            // `let x;`, yield no RHS and are skipped).
            "variable_declarator" => {
                let target = node
                    .child_by_field_name("name")
                    .map(|name| node_text(name, source));
                let rhs = node
                    .child_by_field_name("value")
                    .map(|value| node_text(value, source));
                if let (Some(target), Some(rhs)) = (target, rhs) {
                    let target = target.trim().to_owned();
                    if identifiers(&target).len() == 1
                        && target.len() <= 64
                        && is_identifier_char(target.chars().next().unwrap_or('0'), true)
                    {
                        out.push(Assignment {
                            target,
                            rhs,
                            line: node.start_position().row + 1,
                        });
                    }
                }
            }
            // JS `x = …` / `x += …` outside declarations.
            "assignment_expression" => {
                let target = node
                    .child_by_field_name("left")
                    .map(|left| node_text(left, source));
                let rhs = node
                    .child_by_field_name("right")
                    .map(|right| node_text(right, source));
                if let (Some(target), Some(rhs)) = (target, rhs) {
                    let target = target.trim().to_owned();
                    if identifiers(&target).len() == 1 && target.len() <= 64 {
                        out.push(Assignment {
                            target,
                            rhs,
                            line: node.start_position().row + 1,
                        });
                    }
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.children(&mut cursor).collect();
        children.reverse();
        for child in children {
            if out.len() >= MAX_VARS {
                break;
            }
            stack.push(child);
        }
        if out.len() >= MAX_VARS {
            break;
        }
    }
    out
}

/// Analyzes one function into a tainted-variable scope.
///
/// Seeds parameters, then runs a bounded fixpoint over assignments: each
/// pass taints targets whose RHS is sanitized (skipped), contains a direct
/// source (new origin), or mentions an already-tainted variable (propagated
/// origin, extended chain description). Stops early on quiescence. The
/// analysis is flow- and path-insensitive by design — conditionals and loops
/// are ignored — which over-approximates (may trace infeasible paths) but
/// never fabricates a variable that does not textually flow.
fn analyze_function(function: tree_sitter::Node<'_>, source: &[u8], language: LanguageId) -> Scope {
    let start_line = function.start_position().row + 1;
    let end_line = function.end_position().row + 1;
    let mut tainted: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for (name, line) in collect_params(function, source, language) {
        if tainted.len() >= MAX_VARS {
            break;
        }
        tainted.insert(name.clone(), (line, format!("parameter `{name}`")));
    }
    let assignments = collect_assignments(function, source, language);
    for _ in 0..MAX_PASSES {
        let mut changed = false;
        for assignment in &assignments {
            if tainted.contains_key(&assignment.target) || tainted.len() >= MAX_VARS {
                continue;
            }
            if is_sanitized(&assignment.rhs) {
                continue;
            }
            if let Some(marker) = direct_source_marker(&assignment.rhs) {
                tainted.insert(
                    assignment.target.clone(),
                    (
                        assignment.line,
                        format!("call `{marker}` reaches `{}`", assignment.target),
                    ),
                );
                changed = true;
                continue;
            }
            // Propagation: if any tainted variable is mentioned in the RHS,
            // the target inherits its origin with an extended chain. The
            // borrow ends before `insert` via the cloned `flowed` tuple.
            let rhs_idents = identifiers(&assignment.rhs);
            let flowed = tainted
                .iter()
                .find(|(var, _)| rhs_idents.contains(*var))
                .map(|(_, (line, origin))| (*line, origin.clone()));
            if let Some((line, origin)) = flowed {
                tainted.insert(
                    assignment.target.clone(),
                    (line, format!("{origin} flows into `{}`", assignment.target)),
                );
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Scope {
        start_line,
        end_line,
        tainted,
    }
}

/// Builds the per-file taint index by analyzing every function.
///
/// Unsupported languages return an empty index (callers query uniformly).
/// Functions are found with a whole-tree walk; each is analyzed
/// independently, so analysis cost is linear in function count (capped).
pub fn analyze(root: tree_sitter::Node<'_>, source: &[u8], language: LanguageId) -> TaintIndex {
    if !is_supported(language) {
        return TaintIndex::default();
    }
    let mut scopes = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if is_function_node(language, node.kind()) {
            scopes.push(analyze_function(node, source, language));
            if scopes.len() >= MAX_FUNCTIONS {
                break;
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    TaintIndex { scopes }
}

impl TaintIndex {
    /// Returns the taint trace when a sink's arguments mention a tainted var.
    ///
    /// The enclosing scope is the SMALLEST one containing the sink line, so
    /// nested functions resolve against their own locals. The first tainted
    /// argument identifier (alphabetical, via `BTreeSet` order) wins — one
    /// trace per finding keeps reports readable, and the finding already
    /// names the sink.
    pub fn flow_for_sink(&self, sink_line: usize, sink_args: &str) -> Option<TaintFlow> {
        let scope = self
            .scopes
            .iter()
            .filter(|scope| sink_line >= scope.start_line && sink_line <= scope.end_line)
            .min_by_key(|scope| scope.end_line - scope.start_line)?;
        let arg_idents = identifiers(sink_args);
        for ident in &arg_idents {
            if let Some((line, origin)) = scope.tainted.get(ident) {
                return Some(TaintFlow {
                    source_line: *line,
                    source: origin.clone(),
                    variable: ident.clone(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    /// Builds a taint index for a snippet; fixtures must parse cleanly.
    fn index(language: LanguageId, source: &str) -> TaintIndex {
        let mut parser = Parser::new();
        parser.set_language(&language.grammar()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        analyze(tree.root_node(), source.as_bytes(), language)
    }

    /// Parameter taint survives string concatenation into a derived variable
    /// that reaches the sink; the trace names the derived variable and the
    /// parameter origin.
    #[test]
    fn python_parameter_flows_through_assignment() {
        let index = index(
            LanguageId::Python,
            "def f(cmd):\n    full = 'run ' + cmd\n    os.system(full)\n",
        );
        let flow = index.flow_for_sink(3, "(full)").unwrap();
        assert_eq!(flow.variable, "full");
        assert!(flow.source.contains("parameter `cmd`"));
    }

    /// A sink with only constant arguments yields no trace even when the
    /// enclosing function has tainted parameters.
    #[test]
    fn python_unrelated_call_has_no_flow() {
        let index = index(LanguageId::Python, "def f(cmd):\n    os.system('ls')\n");
        assert!(index.flow_for_sink(2, "('ls')").is_none());
    }

    /// `shlex.quote` breaks the chain: the derived variable is clean and the
    /// sink reports no flow.
    #[test]
    fn python_sanitizer_breaks_flow() {
        let index = index(
            LanguageId::Python,
            "def f(cmd):\n    safe = shlex.quote(cmd)\n    os.system(safe)\n",
        );
        assert!(index.flow_for_sink(3, "(safe)").is_none());
    }

    /// JS coverage: `const` declarators propagate parameter taint to the sink.
    #[test]
    fn javascript_parameter_flows_to_sink() {
        let index = index(
            LanguageId::JavaScript,
            "function f(cmd) { const full = 'run ' + cmd; child_process.exec(full); }",
        );
        let flow = index.flow_for_sink(1, "(full)").unwrap();
        assert_eq!(flow.variable, "full");
    }

    /// `input()` seeds taint without any parameters involved.
    #[test]
    fn input_call_is_a_source() {
        let index = index(
            LanguageId::Python,
            "def f():\n    cmd = input()\n    eval(cmd)\n",
        );
        assert!(index.flow_for_sink(3, "(cmd)").is_some());
    }

    /// Unsupported languages analyze to an empty index — never traces, never
    /// panics — so callers need no per-language branching.
    #[test]
    fn unsupported_languages_have_no_scopes() {
        let index = index(LanguageId::Rust, "fn f(x: u32) { println!(\"{x}\"); }");
        assert!(index.flow_for_sink(1, "(x)").is_none());
    }
}
