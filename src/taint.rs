use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::language::LanguageId;

const MAX_FUNCTIONS: usize = 512;
const MAX_NODES_PER_FUNCTION: usize = 2000;
const MAX_VARS: usize = 256;
const MAX_PASSES: usize = 8;
const MAX_IDENTIFIERS: usize = 64;

#[derive(Clone, Debug, Serialize)]
pub struct TaintFlow {
    pub source_line: usize,
    pub source: String,
    pub variable: String,
}

#[derive(Clone, Debug)]
struct Scope {
    start_line: usize,
    end_line: usize,
    tainted: BTreeMap<String, (usize, String)>,
}

#[derive(Debug, Default)]
pub struct TaintIndex {
    scopes: Vec<Scope>,
}

fn is_supported(language: LanguageId) -> bool {
    matches!(
        language,
        LanguageId::Python | LanguageId::JavaScript | LanguageId::TypeScript | LanguageId::Tsx
    )
}

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

fn node_text(node: tree_sitter::Node<'_>, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_owned()
}

fn is_identifier_char(ch: char, first: bool) -> bool {
    if first {
        ch == '_' || ch.is_ascii_alphabetic()
    } else {
        ch == '_' || ch.is_ascii_alphanumeric()
    }
}

fn identifiers(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut current = String::new();
    for ch in text.chars() {
        let continues = if current.is_empty() {
            is_identifier_char(ch, true)
        } else {
            is_identifier_char(ch, false)
        };
        if continues {
            current.push(ch);
            continue;
        }
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

fn params_field(_language: LanguageId) -> &'static str {
    "parameters"
}

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

fn is_sanitized(rhs: &str) -> bool {
    rhs.contains("shlex.quote")
}

#[derive(Clone, Debug)]
struct Assignment {
    target: String,
    rhs: String,
    line: usize,
}

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
        if node.id() != function.id() && is_function_node(language, node.kind()) {
            continue;
        }
        match node.kind() {
            "assignment" | "augmented_assignment" => {
                let target = node
                    .child_by_field_name("left")
                    .map(|left| node_text(left, source));
                let rhs = node
                    .child_by_field_name("right")
                    .map(|right| node_text(right, source));
                if let (Some(target), Some(rhs)) = (target, rhs) {
                    let target = target.trim().to_owned();
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

    fn index(language: LanguageId, source: &str) -> TaintIndex {
        let mut parser = Parser::new();
        parser.set_language(&language.grammar()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        analyze(tree.root_node(), source.as_bytes(), language)
    }

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

    #[test]
    fn python_unrelated_call_has_no_flow() {
        let index = index(LanguageId::Python, "def f(cmd):\n    os.system('ls')\n");
        assert!(index.flow_for_sink(2, "('ls')").is_none());
    }

    #[test]
    fn python_sanitizer_breaks_flow() {
        let index = index(
            LanguageId::Python,
            "def f(cmd):\n    safe = shlex.quote(cmd)\n    os.system(safe)\n",
        );
        assert!(index.flow_for_sink(3, "(safe)").is_none());
    }

    #[test]
    fn javascript_parameter_flows_to_sink() {
        let index = index(
            LanguageId::JavaScript,
            "function f(cmd) { const full = 'run ' + cmd; child_process.exec(full); }",
        );
        let flow = index.flow_for_sink(1, "(full)").unwrap();
        assert_eq!(flow.variable, "full");
    }

    #[test]
    fn input_call_is_a_source() {
        let index = index(
            LanguageId::Python,
            "def f():\n    cmd = input()\n    eval(cmd)\n",
        );
        assert!(index.flow_for_sink(3, "(cmd)").is_some());
    }

    #[test]
    fn unsupported_languages_have_no_scopes() {
        let index = index(LanguageId::Rust, "fn f(x: u32) { println!(\"{x}\"); }");
        assert!(index.flow_for_sink(1, "(x)").is_none());
    }
}
