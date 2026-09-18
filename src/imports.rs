use std::collections::BTreeMap;

use crate::language::LanguageId;

pub type AliasMap = BTreeMap<String, String>;

fn text(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    node.utf8_text(source).ok().map(str::to_owned)
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|char| char == '_' || char.is_ascii_alphanumeric())
}

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
                        if child.id() == module_node.id() {
                            continue;
                        }
                        match child.kind() {
                            "dotted_name" => {
                                if let Some(local) = dotted_name(child, source) {
                                    aliases.insert(local.clone(), format!("{module}.{local}"));
                                }
                            }
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
                                    "shorthand_property_identifier_pattern" => {
                                        if let Some(local) = text(child, source)
                                            && is_identifier(&local)
                                        {
                                            let target = format!("{module}.{local}");
                                            aliases.insert(local, target);
                                        }
                                    }
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
                    let mut inner = vec![node];
                    while let Some(current) = inner.pop() {
                        let mut cursor = current.walk();
                        for child in current.named_children(&mut cursor) {
                            match child.kind() {
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

    fn aliases(language: LanguageId, source: &str) -> AliasMap {
        let mut parser = Parser::new();
        parser.set_language(&language.grammar()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        collect_aliases(tree.root_node(), source.as_bytes(), language)
    }

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

    #[test]
    fn resolves_python_aliased_module_import() {
        let map = aliases(LanguageId::Python, "import os.path as osp\n");
        assert_eq!(map.get("osp").map(String::as_str), Some("os.path"));
        assert_eq!(resolve_callee("osp.join", &map), "os.path.join");
    }

    #[test]
    fn ignores_plain_python_imports_and_wildcards() {
        let map = aliases(LanguageId::Python, "import os\nfrom os import *\n");
        assert!(map.is_empty());
    }

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

    #[test]
    fn ignores_default_and_relative_javascript_imports() {
        let map = aliases(
            LanguageId::JavaScript,
            "import cp from 'child_process';\nimport './setup';\nconst local = require('./local');\n",
        );
        assert_eq!(map.get("local").map(String::as_str), Some("./local"));
        assert!(!map.contains_key("cp"));
    }

    #[test]
    fn last_binding_wins_like_runtime_rebinding() {
        let map = aliases(
            LanguageId::Python,
            "from os import system\nfrom fake import system\n",
        );
        assert_eq!(map.get("system").map(String::as_str), Some("fake.system"));
    }
}
