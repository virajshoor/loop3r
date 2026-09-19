//! Import-alias resolution: map locally renamed calls to canonical callees.
//!
//! Rules name canonical callees (`os.system`, `child_process.exec`), but
//! source often renames them (`from os import system as run`). Without
//! resolution, `run(x)` would miss `CORE-PY-SHELL` — a false negative the
//! fix is to collect each file's import bindings, then rewrite call heads
//! before matching. Only Python and JavaScript/TypeScript/TSX are supported;
//! every other language matches written callees only (a documented gap, not
//! silent behaviour).
//!
//! Soundness rules: last binding wins (mirroring runtime rebinding), while
//! default imports, wildcard imports, plain `import os` (no binding created),
//! and relative modules never resolve — resolving those would guess at
//! meaning the scanner cannot prove.

use std::collections::BTreeMap;

use crate::language::LanguageId;

/// Local name → canonical dotted path, e.g. `run` → `os.system` or
/// `cp` → `child_process` (attribute access on `cp` resolves per-use).
/// `BTreeMap` keeps iteration deterministic for tests and debugging.
pub type AliasMap = BTreeMap<String, String>;

/// Extracts a node's source text, or `None` on invalid UTF-8 (treated as
/// "no binding" rather than an error — one bad slice must not kill the file).
fn text(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    node.utf8_text(source).ok().map(str::to_owned)
}

/// Whether a string is a plausible identifier binding (`_`, letters, digits).
/// Guards against recording operators or garbage as alias names.
fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|char| char == '_' || char.is_ascii_alphanumeric())
}

/// Extracts a dotted module/name path (`os.path`, `system`), compacted and
/// bounded. Rejects empty segments, overlong text (>256 chars), and anything
/// that is not dot-separated identifiers — import positions in weird macro
/// expansions must not become phantom aliases.
fn dotted_name(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    let raw = text(node, source)?;
    let compact: String = raw.chars().filter(|char| !char.is_whitespace()).collect();
    if compact.is_empty() || compact.len() > 256 {
        return None;
    }
    if !compact.split('.').all(|segment| {
        !segment.is_empty()
            && segment
                .chars()
                .all(|char| char == '_' || char.is_ascii_alphanumeric())
    }) {
        return None;
    }
    Some(compact)
}

/// Extracts a JS module specifier from an `import`/`require` string literal.
///
/// Reads the `string_fragment` child (not the raw quotes) and rejects empty,
/// overlong (>128), or whitespace-containing specifiers. Note this records
/// the specifier verbatim — including `./local` — and lets the *resolution*
/// step decide: `resolve_callee` only rewrites heads, so `cp.exec` with
/// `cp` → `./local` becomes `./local.exec`, which matches no rule.
fn module_string(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    let fragment = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "string_fragment")?;
    let value = text(fragment, source)?;
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_whitespace) {
        return None;
    }
    Some(value)
}

/// Collects Python bindings: `import x.y as z` and `from m import n [as a]`.
///
/// Plain `import os` creates no entry (attribute access `os.system` already
/// matches canonically), and `from m import *` is ignored (unresolvable
/// without executing the import). Children are pushed in reverse so the
/// stack pops them in source order — required for last-binding-wins.
fn collect_python(root: tree_sitter::Node<'_>, source: &[u8], aliases: &mut AliasMap) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        let children: Vec<tree_sitter::Node<'_>> = node.children(&mut cursor).collect();
        match node.kind() {
            "import_statement" => {
                for child in children
                    .iter()
                    .filter(|child| child.kind() == "aliased_import")
                {
                    let name = child
                        .child_by_field_name("name")
                        .and_then(|name| dotted_name(name, source));
                    let alias = child
                        .child_by_field_name("alias")
                        .and_then(|alias| text(alias, source));
                    if let (Some(target), Some(local)) = (name, alias)
                        && is_identifier(&local)
                    {
                        aliases.insert(local, target);
                    }
                }
            }
            "import_from_statement" => {
                let module_node = node.child_by_field_name("module_name");
                let module = module_node.and_then(|module| dotted_name(module, source));
                if let (Some(module), Some(module_node)) = (module, module_node) {
                    for child in children {
                        // Skip the module node itself; the remaining children
                        // are the imported names.
                        if child.id() == module_node.id() {
                            continue;
                        }
                        match child.kind() {
                            // `from os import system` → `system` ⇒ `os.system`.
                            "dotted_name" => {
                                if let Some(local) = dotted_name(child, source) {
                                    aliases.insert(local.clone(), format!("{module}.{local}"));
                                }
                            }
                            // `from os import system as run` → `run` ⇒ `os.system`.
                            "aliased_import" => {
                                let name = child
                                    .child_by_field_name("name")
                                    .and_then(|name| dotted_name(name, source));
                                let alias = child
                                    .child_by_field_name("alias")
                                    .and_then(|alias| text(alias, source));
                                if let (Some(name), Some(local)) = (name, alias)
                                    && is_identifier(&local)
                                {
                                    aliases.insert(local, format!("{module}.{name}"));
                                }
                            }
                            _ => {}
                        }
                    }
                    continue;
                }
            }
            _ => {}
        }
        stack.extend(children.into_iter().rev());
    }
}

/// Recognizes `require('<module>')` with exactly one string argument.
///
/// Multi-argument or non-string `require` calls are not module loads, so
/// they yield no binding. This intentionally also matches non-child_process
/// modules — the recorded specifier simply won't match any rule callee.
fn require_module(value: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    if value.kind() != "call_expression" {
        return None;
    }
    let function = value.child_by_field_name("function")?;
    if function.kind() != "identifier" || text(function, source)? != "require" {
        return None;
    }
    let arguments = value.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let mut named = arguments.named_children(&mut cursor);
    let first = named.next()?;
    if named.next().is_some() || first.kind() != "string" {
        return None;
    }
    module_string(first, source)
}

/// Collects JS/TS bindings from `require` and `import` statements.
///
/// Covered: `const cp = require('m')`, `const {a} = require('m')`,
/// `const {a: b} = require('m')`, `import {a[, b as c]} from 'm'`, and
/// `import * as ns from 'm'`. Deliberately NOT covered: default imports
/// (`import cp from 'm'` binds the default export, whose shape is unknown)
/// and side-effect imports. Like Python, traversal is source-ordered for
/// last-binding-wins.
fn collect_javascript(root: tree_sitter::Node<'_>, source: &[u8], aliases: &mut AliasMap) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        let children: Vec<tree_sitter::Node<'_>> = node.children(&mut cursor).collect();
        match node.kind() {
            "variable_declarator" => {
                let name = node.child_by_field_name("name");
                let value = node.child_by_field_name("value");
                if let (Some(name), Some(value)) = (name, value)
                    && let Some(module) = require_module(value, source)
                {
                    match name.kind() {
                        // `const cp = require('child_process')` → `cp` ⇒ module.
                        "identifier" => {
                            if let Some(local) = text(name, source)
                                && is_identifier(&local)
                            {
                                aliases.insert(local, module);
                            }
                        }
                        "object_pattern" => {
                            let mut pattern = name.walk();
                            for child in name.named_children(&mut pattern) {
                                match child.kind() {
                                    // `const {exec} = require(...)` → `exec` ⇒ `m.exec`.
                                    "shorthand_property_identifier_pattern" => {
                                        if let Some(local) = text(child, source)
                                            && is_identifier(&local)
                                        {
                                            let target = format!("{module}.{local}");
                                            aliases.insert(local, target);
                                        }
                                    }
                                    // `const {exec: run} = require(...)` → `run` ⇒ `m.exec`.
                                    "pair_pattern" => {
                                        let key = child
                                            .child_by_field_name("key")
                                            .and_then(|key| text(key, source));
                                        let renamed = child
                                            .child_by_field_name("value")
                                            .and_then(|renamed| text(renamed, source));
                                        if let (Some(key), Some(local)) = (key, renamed)
                                            && is_identifier(&key)
                                            && is_identifier(&local)
                                        {
                                            aliases.insert(local, format!("{module}.{key}"));
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            "import_statement" => {
                let module = node
                    .child_by_field_name("source")
                    .and_then(|source_node| module_string(source_node, source));
                if let Some(module) = module {
                    // Import clauses nest (`import_clause` → specifiers), so
                    // walk the subtree rather than assuming direct children.
                    let mut inner = vec![node];
                    while let Some(current) = inner.pop() {
                        let mut cursor = current.walk();
                        for child in current.named_children(&mut cursor) {
                            match child.kind() {
                                // `import {exec[, as run]} from 'm'`.
                                "import_specifier" => {
                                    let name = child
                                        .child_by_field_name("name")
                                        .and_then(|name| text(name, source));
                                    let alias = child
                                        .child_by_field_name("alias")
                                        .and_then(|alias| text(alias, source));
                                    if let Some(name) = name
                                        && is_identifier(&name)
                                    {
                                        let local = alias.unwrap_or_else(|| name.clone());
                                        if is_identifier(&local) {
                                            let target = format!("{module}.{name}");
                                            aliases.insert(local, target);
                                        }
                                    }
                                }
                                // `import * as cp from 'm'` → `cp` ⇒ module.
                                "namespace_import" => {
                                    let mut cursor = child.walk();
                                    if let Some(local) = child
                                        .named_children(&mut cursor)
                                        .next()
                                        .and_then(|local| text(local, source))
                                        && is_identifier(&local)
                                    {
                                        aliases.insert(local, module.clone());
                                    }
                                }
                                _ => inner.push(child),
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        stack.extend(children.into_iter().rev());
    }
}

/// Builds the alias map for one file, dispatching on language.
///
/// Returns an empty map for languages without import support — callers then
/// match written callees only. File-local by construction: aliases never
/// leak across files (cross-file resolution is explicitly out of scope).
pub fn collect_aliases(
    root: tree_sitter::Node<'_>,
    source: &[u8],
    language: LanguageId,
) -> AliasMap {
    let mut aliases = AliasMap::new();
    match language {
        LanguageId::Python => collect_python(root, source, &mut aliases),
        LanguageId::JavaScript | LanguageId::TypeScript | LanguageId::Tsx => {
            collect_javascript(root, source, &mut aliases);
        }
        _ => {}
    }
    aliases
}

/// Rewrites a call head through the alias map to its canonical form.
///
/// Only the head segment is substituted (`cp.exec` with `cp` → `m` becomes
/// `m.exec`); unaliased names pass through unchanged. Because substitution
/// is purely textual on the head, relative-module bindings (e.g. `./local`)
/// produce non-matching canonical forms rather than false positives.
pub fn resolve_callee(name: &str, aliases: &AliasMap) -> String {
    let head = name.split('.').next().unwrap_or("");
    match aliases.get(head) {
        Some(target) if head.len() == name.len() => target.clone(),
        Some(target) => format!("{target}{}", &name[head.len()..]),
        None => name.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    /// Parses a snippet and returns its alias map, panicking on grammar
    /// failures — fixtures must be valid syntax by construction.
    fn aliases(language: LanguageId, source: &str) -> AliasMap {
        let mut parser = Parser::new();
        parser.set_language(&language.grammar()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        collect_aliases(tree.root_node(), source.as_bytes(), language)
    }

    /// `from` imports (plain, renamed, multi-name) all resolve, and
    /// `resolve_callee` rewrites through them.
    #[test]
    fn resolves_python_from_imports() {
        let map = aliases(
            LanguageId::Python,
            "from os import system\nfrom os import system as run\nfrom pickle import loads, dumps\n",
        );
        assert_eq!(map.get("system").map(String::as_str), Some("os.system"));
        assert_eq!(map.get("run").map(String::as_str), Some("os.system"));
        assert_eq!(map.get("loads").map(String::as_str), Some("pickle.loads"));
        assert_eq!(map.get("dumps").map(String::as_str), Some("pickle.dumps"));
        assert_eq!(resolve_callee("run", &map), "os.system");
    }

    /// `import os.path as osp` binds the module so attribute access
    /// (`osp.join`) resolves through the head substitution.
    #[test]
    fn resolves_python_aliased_module_import() {
        let map = aliases(LanguageId::Python, "import os.path as osp\n");
        assert_eq!(map.get("osp").map(String::as_str), Some("os.path"));
        assert_eq!(resolve_callee("osp.join", &map), "os.path.join");
    }

    /// Plain `import os` binds nothing (attribute access already matches)
    /// and `import *` is unresolvable — both leave the map empty.
    #[test]
    fn ignores_plain_python_imports_and_wildcards() {
        let map = aliases(LanguageId::Python, "import os\nfrom os import *\n");
        assert!(map.is_empty());
    }

    /// All three `require` shapes (namespace, destructured, renamed) bind
    /// correctly, including head substitution on `cp.exec`.
    #[test]
    fn resolves_javascript_require_forms() {
        let map = aliases(
            LanguageId::JavaScript,
            "const cp = require('child_process');\nconst {exec} = require('child_process');\nconst {exec: run} = require('child_process');\n",
        );
        assert_eq!(map.get("cp").map(String::as_str), Some("child_process"));
        assert_eq!(
            map.get("exec").map(String::as_str),
            Some("child_process.exec")
        );
        assert_eq!(
            map.get("run").map(String::as_str),
            Some("child_process.exec")
        );
        assert_eq!(resolve_callee("cp.exec", &map), "child_process.exec");
    }

    /// Named, renamed, and namespace `import` forms all bind.
    #[test]
    fn resolves_javascript_import_forms() {
        let map = aliases(
            LanguageId::JavaScript,
            "import {exec} from 'child_process';\nimport {exec as run} from 'child_process';\nimport * as cp from 'child_process';\n",
        );
        assert_eq!(
            map.get("exec").map(String::as_str),
            Some("child_process.exec")
        );
        assert_eq!(
            map.get("run").map(String::as_str),
            Some("child_process.exec")
        );
        assert_eq!(map.get("cp").map(String::as_str), Some("child_process"));
    }

    /// Default imports (unknown export shape) never bind; relative requires
    /// bind verbatim so resolution yields a non-matching canonical form.
    #[test]
    fn ignores_default_and_relative_javascript_imports() {
        let map = aliases(
            LanguageId::JavaScript,
            "import cp from 'child_process';\nimport './setup';\nconst local = require('./local');\n",
        );
        assert_eq!(map.get("local").map(String::as_str), Some("./local"));
        assert!(!map.contains_key("cp"));
    }

    /// Later imports shadow earlier ones, matching runtime rebinding — the
    /// alias map must reflect what the name means at the call site below.
    #[test]
    fn last_binding_wins_like_runtime_rebinding() {
        let map = aliases(
            LanguageId::Python,
            "from os import system\nfrom fake import system\n",
        );
        assert_eq!(map.get("system").map(String::as_str), Some("fake.system"));
    }
}
