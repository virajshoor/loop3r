//! Language identity: the single registry mapping files to embedded parsers.
//!
//! Every language loop3r can parse has one [`LanguageId`]. The enum is the
//! choke point for three jobs: picking a Tree-sitter grammar at scan time,
//! routing files by extension during discovery, and labelling findings in
//! reports. Adding a language means adding a variant here, a grammar mapping
//! in [`LanguageId::grammar`], and an extension mapping in
//! [`LanguageId::from_path`] — plus call-node handling in `source.rs` if the
//! language needs AST rules (HTML, CSS, and SQL parse for syntax coverage
//! only and deliberately have no call semantics).

use std::path::Path;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use tree_sitter::Language;

/// Stable identifier for a supported source language.
///
/// Derives are load-bearing:
/// - `ValueEnum` exposes each variant as a `--language` CLI filter.
/// - `Serialize`/`Deserialize` (lowercase) is the on-disk spelling used in
///   reports, scopes, and schemas; renaming a variant is a breaking change.
/// - `Ord` keeps per-language report counts deterministically ordered.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LanguageId {
    /// C (`*.c`, `*.h`).
    C,
    /// C# (`*.cs`).
    CSharp,
    /// CSS. Parses for syntax coverage; has no AST rules.
    Css,
    /// Go (`*.go`).
    Go,
    /// HTML. Parses for syntax coverage; has no AST rules.
    Html,
    /// Java (`*.java`).
    Java,
    /// JavaScript, including JSX (`*.js`, `*.jsx`).
    JavaScript,
    /// Kotlin (`*.kt`, `*.kts`).
    Kotlin,
    /// PHP (`*.php`).
    Php,
    /// Python (`*.py`).
    Python,
    /// Ruby (`*.rb`).
    Ruby,
    /// Rust (`*.rs`).
    Rust,
    /// Shell via the Bash grammar (`*.sh`).
    Shell,
    /// SQL. Parses for syntax coverage; has no AST rules.
    Sql,
    /// Swift (`*.swift`).
    Swift,
    /// TypeScript (`*.ts`).
    TypeScript,
    /// TSX (`*.tsx`): TypeScript grammar with JSX support.
    Tsx,
}

impl LanguageId {
    /// Returns the embedded Tree-sitter grammar for this language.
    ///
    /// Grammars ship inside the binary (`tree-sitter-*` crates), so parsing
    /// works fully offline. The PHP crate exposes several dialects; loop3r
    /// pins `LANGUAGE_PHP` (plain PHP, not HTML-mixed templates).
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

    /// Detects the language from a file extension (case-insensitive).
    ///
    /// Returns `None` for unknown or missing extensions; callers treat that
    /// as "unsupported file" (counted, never an error during directory
    /// walks). Extension matching is intentionally the only heuristic —
    /// content sniffing would add misclassification risk for polyglot files.
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
