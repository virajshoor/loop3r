use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Serialize;
use walkdir::{DirEntry, WalkDir};

use crate::language::LanguageId;

#[derive(Serialize)]
pub struct ScopeReport {
    pub target: PathBuf,
    pub max_file_bytes: u64,
    pub budget_seconds: u64,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub languages: Vec<LanguageId>,
}

pub struct Scope {
    include_patterns: Vec<String>,
    exclude_patterns: Vec<String>,
    include: GlobSet,
    exclude: GlobSet,
    languages: Vec<LanguageId>,
}

impl Scope {
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

    pub fn allows(&self, relative: &Path, language: LanguageId) -> bool {
        (self.include_patterns.is_empty() || self.include.is_match(relative))
            && !self.exclude.is_match(relative)
            && (self.languages.is_empty() || self.languages.contains(&language))
    }

    pub fn allows_secret_file(&self, relative: &Path) -> bool {
        (self.include_patterns.is_empty() || self.include.is_match(relative))
            && !self.exclude.is_match(relative)
    }

    pub fn include_patterns(&self) -> &[String] {
        &self.include_patterns
    }

    pub fn exclude_patterns(&self) -> &[String] {
        &self.exclude_patterns
    }

    pub fn languages(&self) -> &[LanguageId] {
        &self.languages
    }
}

pub(crate) fn ignored(entry: &DirEntry) -> bool {
    entry.file_type().is_dir()
        && matches!(
            entry.file_name().to_str(),
            Some(".git" | ".hg" | ".svn" | "node_modules" | "target" | "vendor" | ".venv")
        )
}

pub struct Discovery {
    pub files: Vec<(PathBuf, LanguageId)>,
    pub secret_files: Vec<PathBuf>,
    pub skipped_oversized: usize,
    pub skipped_unsupported: usize,
}

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

fn empty_discovery() -> Discovery {
    Discovery {
        files: Vec::new(),
        secret_files: Vec::new(),
        skipped_oversized: 0,
        skipped_unsupported: 0,
    }
}

pub fn source_files(target: &Path, max_bytes: u64, scope: &Scope) -> Result<Discovery> {
    if target.is_file() {
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
