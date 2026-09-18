use std::path::Path;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use tree_sitter::Language;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LanguageId {
    C,
    CSharp,
    Css,
    Go,
    Html,
    Java,
    JavaScript,
    Kotlin,
    Php,
    Python,
    Ruby,
    Rust,
    Shell,
    Sql,
    Swift,
    TypeScript,
    Tsx,
}

impl LanguageId {
    pub fn grammar(self) -> Language {
        match self {
            Self::C => tree_sitter_c::LANGUAGE.into(),
            Self::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
            Self::Css => tree_sitter_css::LANGUAGE.into(),
            Self::Go => tree_sitter_go::LANGUAGE.into(),
            Self::Html => tree_sitter_html::LANGUAGE.into(),
            Self::Java => tree_sitter_java::LANGUAGE.into(),
            Self::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Self::Kotlin => tree_sitter_kotlin_ng::LANGUAGE.into(),
            Self::Php => tree_sitter_php::LANGUAGE_PHP.into(),
            Self::Python => tree_sitter_python::LANGUAGE.into(),
            Self::Ruby => tree_sitter_ruby::LANGUAGE.into(),
            Self::Rust => tree_sitter_rust::LANGUAGE.into(),
            Self::Shell => tree_sitter_bash::LANGUAGE.into(),
            Self::Sql => tree_sitter_sequel::LANGUAGE.into(),
            Self::Swift => tree_sitter_swift::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        }
    }

    pub fn from_path(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
            "c" | "h" => Some(Self::C),
            "cs" => Some(Self::CSharp),
            "css" => Some(Self::Css),
            "go" => Some(Self::Go),
            "htm" | "html" => Some(Self::Html),
            "java" => Some(Self::Java),
            "js" | "jsx" => Some(Self::JavaScript),
            "kt" | "kts" => Some(Self::Kotlin),
            "php" => Some(Self::Php),
            "py" => Some(Self::Python),
            "rb" => Some(Self::Ruby),
            "rs" => Some(Self::Rust),
            "sh" => Some(Self::Shell),
            "sql" => Some(Self::Sql),
            "swift" => Some(Self::Swift),
            "ts" => Some(Self::TypeScript),
            "tsx" => Some(Self::Tsx),
            _ => None,
        }
    }
}
