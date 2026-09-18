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

fn ignored(entry: &DirEntry) -> bool {
    entry.file_type().is_dir()
        && matches!(
            entry.file_name().to_str(),
            Some(".git" | ".hg" | ".svn" | "node_modules" | "target" | "vendor" | ".venv")
        )
}

pub fn source_files(
    target: &Path,
    max_bytes: u64,
    scope: &Scope,
) -> Result<Vec<(PathBuf, LanguageId)>> {
    if target.is_file() {
        if std::fs::symlink_metadata(target)?.file_type().is_symlink() {
            anyhow::bail!("refusing symlink target: {}", target.display());
        }
        if target.metadata()?.len() > max_bytes {
            anyhow::bail!("target exceeds max-file-bytes: {}", target.display());
        }
        let language = LanguageId::from_path(target).context("unsupported source extension")?;
        if !scope.allows(
            Path::new(target.file_name().context("target has no filename")?),
            language,
        ) {
            return Ok(Vec::new());
        }
        return Ok(vec![(target.to_path_buf(), language)]);
    }
    let mut files = Vec::new();
    for entry in WalkDir::new(target)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !ignored(entry))
    {
        let entry = entry.with_context(|| format!("walking {}", target.display()))?;
        if !entry.file_type().is_file() || entry.metadata()?.len() > max_bytes {
            continue;
        }
        if let Some(language) = LanguageId::from_path(entry.path()) {
            let relative = entry
                .path()
                .strip_prefix(target)
                .context("resolving scoped path")?;
            if scope.allows(relative, language) {
                files.push((entry.into_path(), language));
            }
        }
    }
    files.sort();
    Ok(files)
}
