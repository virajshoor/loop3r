//! Scan scope: which files are in, which are out, and why.
//!
//! Discovery turns a target path plus include/exclude globs and language
//! filters into three buckets: parsed sources, secrets-only configs, and
//! skip counts. Two security properties matter here: symlinks are never
//! followed (a malicious checkout must not pull `/etc` into a scan), and
//! single-file targets fail closed on oversized/unsupported input while
//! directory walks count and continue (one giant vendored file must not
//! abort a whole-tree audit, but an explicitly named bad target is caller
//! error, not a skip).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Serialize;
use walkdir::{DirEntry, WalkDir};

use crate::language::LanguageId;

/// Serialized scope echo stored in every report, so readers can see exactly
/// which target, caps, and filters produced the results.
#[derive(Serialize)]
pub struct ScopeReport {
    /// Target path as passed on the command line.
    pub target: PathBuf,
    /// Per-file byte cap (`--max-file-bytes`).
    pub max_file_bytes: u64,
    /// Deadline in seconds (`--budget-seconds`).
    pub budget_seconds: u64,
    /// Include globs as passed (empty means "everything").
    pub include: Vec<String>,
    /// Exclude globs as passed.
    pub exclude: Vec<String>,
    /// Language filter (`--language`); empty means "all languages".
    pub languages: Vec<LanguageId>,
}

/// Compiled include/exclude/language filters for one scan.
///
/// Holds both the original pattern strings (echoed into reports) and the
/// compiled glob sets (used for matching). Construction validates every glob
/// up front so a typo fails before any file is read.
pub struct Scope {
    /// Raw include patterns, kept for the report echo.
    include_patterns: Vec<String>,
    /// Raw exclude patterns, kept for the report echo.
    exclude_patterns: Vec<String>,
    /// Compiled include matchers.
    include: GlobSet,
    /// Compiled exclude matchers.
    exclude: GlobSet,
    /// Language allowlist; empty allows all.
    languages: Vec<LanguageId>,
}

impl Scope {
    /// Builds a scope, rejecting invalid globs immediately (fail closed on
    /// caller error rather than silently matching nothing — or everything).
    pub fn new(
        include: Vec<String>,
        exclude: Vec<String>,
        languages: Vec<LanguageId>,
    ) -> Result<Self> {
        fn build(patterns: &[String]) -> Result<GlobSet> {
            let mut builder = GlobSetBuilder::new();
            for pattern in patterns {
                builder.add(
                    Glob::new(pattern).with_context(|| format!("invalid scope glob: {pattern}"))?,
                );
            }
            builder.build().context("building scope globs")
        }
        Ok(Self {
            include: build(&include)?,
            exclude: build(&exclude)?,
            include_patterns: include,
            exclude_patterns: exclude,
            languages,
        })
    }

    /// Whether a parsed source file (matched by its target-relative path)
    /// survives all three filters: include (vacuous when empty), exclude
    /// (always wins), and language allowlist (vacuous when empty).
    pub fn allows(&self, relative: &Path, language: LanguageId) -> bool {
        (self.include_patterns.is_empty() || self.include.is_match(relative))
            && !self.exclude.is_match(relative)
            && (self.languages.is_empty() || self.languages.contains(&language))
    }

    /// Whether a secrets-only config file survives glob filters.
    ///
    /// Deliberately ignores `--language`: secrets hide in every config
    /// format, and a language filter like `--language rust` must never
    /// silently drop `.env` files from secret scanning.
    pub fn allows_secret_file(&self, relative: &Path) -> bool {
        (self.include_patterns.is_empty() || self.include.is_match(relative))
            && !self.exclude.is_match(relative)
    }

    /// Raw include patterns for the report echo.
    pub fn include_patterns(&self) -> &[String] {
        &self.include_patterns
    }

    /// Raw exclude patterns for the report echo.
    pub fn exclude_patterns(&self) -> &[String] {
        &self.exclude_patterns
    }

    /// Language allowlist for the report echo.
    pub fn languages(&self) -> &[LanguageId] {
        &self.languages
    }
}

/// Directories pruned before descent: version control, dependency trees, and
/// build output. Matching is by exact directory name (not substring), so a
/// source directory named `my-target` is still scanned. `pub(crate)` so the
/// dependency walker in `deps.rs` shares the identical ignore list.
pub(crate) fn ignored(entry: &DirEntry) -> bool {
    entry.file_type().is_dir()
        && matches!(
            entry.file_name().to_str(),
            Some(".git" | ".hg" | ".svn" | "node_modules" | "target" | "vendor" | ".venv")
        )
}

/// Discovery result: the three file buckets plus skip accounting.
///
/// Skip counts are first-class report fields — "no findings" alongside large
/// skip counts means "barely scanned", and hiding that would be dishonest.
pub struct Discovery {
    /// Sources to parse, each paired with its detected language.
    pub files: Vec<(PathBuf, LanguageId)>,
    /// Configs to secret-scan without parsing.
    pub secret_files: Vec<PathBuf>,
    /// Walked files dropped for exceeding the byte cap.
    pub skipped_oversized: usize,
    /// Walked files with unrecognized extensions.
    pub skipped_unsupported: usize,
}

/// Whether a path is a secrets-only config: `.env` variants by exact file
/// name, or a config extension (case-insensitive). These files are never
/// parsed — only secret-scanned — because they have no useful AST.
pub fn is_secret_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if name == ".env" || name == ".envrc" || name.starts_with(".env.") {
        return true;
    }
    matches!(
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str(),
        "json" | "yaml" | "yml" | "toml" | "ini" | "cfg" | "conf" | "properties"
    )
}

/// Empty discovery for single-file targets that the scope filters out: not
/// an error, just a scan with nothing to do.
fn empty_discovery() -> Discovery {
    Discovery {
        files: Vec::new(),
        secret_files: Vec::new(),
        skipped_oversized: 0,
        skipped_unsupported: 0,
    }
}

/// Discovers in-scope files for a file or directory target.
///
/// Single-file targets: symlinks are refused outright (a scanner that
/// follows an attacker-planted symlink reads attacker-chosen paths), and
/// oversized/unsupported files are hard errors — explicitly naming a file
/// the scanner cannot handle is caller error. The bare file name (not a
/// target-relative path) is scope-checked since there is no tree to be
/// relative to.
///
/// Directory targets: walked without following any symlinks, with ignored
/// trees pruned before descent. Oversized/unsupported files are counted, not
/// errors. Both output lists are sorted so discovery order is deterministic
/// before the seeded shuffle in `source.rs`.
pub fn source_files(target: &Path, max_bytes: u64, scope: &Scope) -> Result<Discovery> {
    if target.is_file() {
        // `symlink_metadata` (not `metadata`) is the check that sees the
        // link itself instead of its target.
        if std::fs::symlink_metadata(target)?.file_type().is_symlink() {
            anyhow::bail!("refusing symlink target: {}", target.display());
        }
        if target.metadata()?.len() > max_bytes {
            anyhow::bail!("target exceeds max-file-bytes: {}", target.display());
        }
        let file_name = Path::new(target.file_name().context("target has no filename")?);
        if is_secret_file(target) {
            if !scope.allows_secret_file(file_name) {
                return Ok(empty_discovery());
            }
            let mut discovery = empty_discovery();
            discovery.secret_files.push(target.to_path_buf());
            return Ok(discovery);
        }
        let language = LanguageId::from_path(target).context("unsupported source extension")?;
        if !scope.allows(file_name, language) {
            return Ok(empty_discovery());
        }
        let mut discovery = empty_discovery();
        discovery.files.push((target.to_path_buf(), language));
        return Ok(discovery);
    }
    let mut files = Vec::new();
    let mut secret_files = Vec::new();
    let mut skipped_oversized = 0_usize;
    let mut skipped_unsupported = 0_usize;
    for entry in WalkDir::new(target)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !ignored(entry))
    {
        let entry = entry.with_context(|| format!("walking {}", target.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.metadata()?.len() > max_bytes {
            skipped_oversized += 1;
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(target)
            .context("resolving scoped path")?;
        if let Some(language) = LanguageId::from_path(entry.path()) {
            if scope.allows(relative, language) {
                files.push((entry.into_path(), language));
            }
        } else if is_secret_file(entry.path()) {
            if scope.allows_secret_file(relative) {
                secret_files.push(entry.into_path());
            }
        } else {
            skipped_unsupported += 1;
        }
    }
    files.sort();
    secret_files.sort();
    Ok(Discovery {
        files,
        secret_files,
        skipped_oversized,
        skipped_unsupported,
    })
}
