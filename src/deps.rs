use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use walkdir::WalkDir;

use crate::scope::ignored;

pub const MAX_LOCKFILE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct Package {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub lockfile: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct LockfileError {
    pub lockfile: PathBuf,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct DepsReport {
    pub schema_version: u8,
    pub target: PathBuf,
    pub lockfiles: Vec<PathBuf>,
    pub packages: Vec<Package>,
    pub unsupported: Vec<PathBuf>,
    pub errors: Vec<LockfileError>,
    pub advisory_db: Option<PathBuf>,
    pub vulnerabilities: Vec<super::advisory::Vulnerability>,
}

fn file_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
}

fn is_supported_lockfile(path: &Path) -> bool {
    matches!(file_name(path), "Cargo.lock" | "package-lock.json")
}

fn is_recognized_unsupported(path: &Path) -> bool {
    matches!(
        file_name(path),
        "pnpm-lock.yaml"
            | "yarn.lock"
            | "poetry.lock"
            | "Pipfile.lock"
            | "Gemfile.lock"
            | "composer.lock"
            | "go.sum"
            | "Package.resolved"
            | "packages.lock.json"
            | "gradle.lockfile"
    )
}

fn parse_quoted(value: &str, line_number: usize) -> Result<String> {
    let inner = value
        .trim()
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .with_context(|| format!("line {line_number}: expected quoted string"))?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(char) = chars.next() {
        if char == '\\' {
            let escaped = chars.next().context(format!(
                "line {line_number}: dangling escape in quoted string"
            ))?;
            out.push(match escaped {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '\\' => '\\',
                '"' => '"',
                other => bail!("line {line_number}: unsupported escape \\{other}"),
            });
        } else {
            out.push(char);
        }
    }
    Ok(out)
}

struct PackageDraft {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    line: usize,
}

fn flush_draft(
    path: &Path,
    current: &mut Option<PackageDraft>,
    packages: &mut Vec<Package>,
) -> Result<()> {
    if let Some(draft) = current.take() {
        let name = draft.name.with_context(|| {
            format!(
                "{} line {}: [[package]] is missing name",
                path.display(),
                draft.line
            )
        })?;
        let version = draft.version.with_context(|| {
            format!(
                "{} line {}: [[package]] is missing version",
                path.display(),
                draft.line
            )
        })?;
        packages.push(Package {
            ecosystem: "cargo",
            name,
            version,
            source: draft.source,
            lockfile: path.to_path_buf(),
        });
    }
    Ok(())
}

fn parse_cargo_lock(path: &Path, text: &str) -> Result<Vec<Package>> {
    let mut packages = Vec::new();
    let mut current: Option<PackageDraft> = None;
    let mut saw_section = false;

    for (index, raw) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[package]]" {
            flush_draft(path, &mut current, &mut packages)?;
            saw_section = true;
            current = Some(PackageDraft {
                name: None,
                version: None,
                source: None,
                line: line_number,
            });
            continue;
        }
        if line.starts_with('[') {
            flush_draft(path, &mut current, &mut packages)?;
            current = None;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Some(entry) = current.as_mut() else {
            continue;
        };
        match key.trim() {
            "name" => entry.name = Some(parse_quoted(value, line_number)?),
            "version" => entry.version = Some(parse_quoted(value, line_number)?),
            "source" => entry.source = Some(parse_quoted(value, line_number)?),
            _ => {}
        }
    }
    flush_draft(path, &mut current, &mut packages)?;
    if !saw_section {
        bail!("{}: no [[package]] sections found", path.display());
    }
    Ok(packages)
}

fn npm_name(entry: &str) -> Option<String> {
    let stripped = entry.strip_prefix("node_modules/")?;
    if stripped.is_empty() || stripped.contains("node_modules/") {
        return None;
    }
    Some(stripped.to_owned())
}

fn parse_package_lock(path: &Path, text: &str) -> Result<Vec<Package>> {
    let value: serde_json::Value =
        serde_json::from_str(text).with_context(|| format!("{}: invalid JSON", path.display()))?;
    let root = value
        .as_object()
        .with_context(|| format!("{}: expected a JSON object", path.display()))?;
    let mut packages = Vec::new();
    if let Some(entries) = root.get("packages").and_then(serde_json::Value::as_object) {
        for (entry, detail) in entries {
            if entry.is_empty() {
                continue;
            }
            let Some(name) = npm_name(entry) else {
                continue;
            };
            let detail = detail
                .as_object()
                .with_context(|| format!("{}: entry {entry} is not an object", path.display()))?;
            if detail.get("link").and_then(serde_json::Value::as_bool) == Some(true) {
                continue;
            }
            let Some(version) = detail.get("version").and_then(serde_json::Value::as_str) else {
                continue;
            };
            packages.push(Package {
                ecosystem: "npm",
                name,
                version: version.to_owned(),
                source: None,
                lockfile: path.to_path_buf(),
            });
        }
        return Ok(packages);
    }
    if let Some(dependencies) = root
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
    {
        for (name, detail) in dependencies {
            let Some(version) = detail
                .as_object()
                .and_then(|entry| entry.get("version"))
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            packages.push(Package {
                ecosystem: "npm",
                name: name.clone(),
                version: version.to_owned(),
                source: None,
                lockfile: path.to_path_buf(),
            });
        }
        return Ok(packages);
    }
    bail!(
        "{}: neither packages nor dependencies found",
        path.display()
    );
}

fn parse_lockfile(path: &Path) -> Result<Vec<Package>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("refusing symlink lockfile: {}", path.display());
    }
    if metadata.len() > MAX_LOCKFILE_BYTES {
        bail!(
            "{}: lockfile exceeds {} bytes",
            path.display(),
            MAX_LOCKFILE_BYTES
        );
    }
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    match file_name(path) {
        "Cargo.lock" => parse_cargo_lock(path, &text),
        "package-lock.json" => parse_package_lock(path, &text),
        other => bail!("{}: unsupported lockfile {other}", path.display()),
    }
}

pub fn inventory(target: &Path) -> Result<DepsReport> {
    if !target.exists() {
        bail!("target does not exist: {}", target.display());
    }
    let mut lockfiles = Vec::new();
    let mut packages = Vec::new();
    let mut unsupported = Vec::new();
    let mut errors = Vec::new();

    if target.is_file() {
        if is_recognized_unsupported(target) {
            unsupported.push(target.to_path_buf());
        } else {
            let parsed =
                parse_lockfile(target).with_context(|| format!("parsing {}", target.display()))?;
            lockfiles.push(target.to_path_buf());
            packages.extend(parsed);
        }
    } else {
        let mut discovered = Vec::new();
        for entry in WalkDir::new(target)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| !ignored(entry))
        {
            let entry = entry.with_context(|| format!("walking {}", target.display()))?;
            if !entry.file_type().is_file() {
                continue;
            }
            if is_supported_lockfile(entry.path()) || is_recognized_unsupported(entry.path()) {
                discovered.push(entry.into_path());
            }
        }
        discovered.sort();
        for path in discovered {
            if is_recognized_unsupported(&path) {
                unsupported.push(path);
                continue;
            }
            match parse_lockfile(&path) {
                Ok(parsed) => {
                    lockfiles.push(path);
                    packages.extend(parsed);
                }
                Err(error) => errors.push(LockfileError {
                    lockfile: path,
                    message: format!("{error:#}"),
                }),
            }
        }
    }

    packages.sort_by(|a, b| {
        (&a.ecosystem, &a.name, &a.version, &a.lockfile).cmp(&(
            &b.ecosystem,
            &b.name,
            &b.version,
            &b.lockfile,
        ))
    });
    errors.sort_by(|a, b| a.lockfile.cmp(&b.lockfile));
    Ok(DepsReport {
        schema_version: 2,
        target: target.to_path_buf(),
        lockfiles,
        packages,
        unsupported,
        errors,
        advisory_db: None,
        vulnerabilities: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARGO_LOCK: &str = r#"# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "anyhow"
version = "1.0.99"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "20427f64429982def081a17a2572d1eb5d5165425be4ff3b9e473ed7f2ed682105"

[[package]]
name = "loop3r"
version = "0.1.0"
dependencies = [
 "anyhow",
]
"#;

    #[test]
    fn parses_cargo_lock_inventory() {
        let path = Path::new("Cargo.lock");
        let packages = parse_cargo_lock(path, CARGO_LOCK).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "anyhow");
        assert_eq!(packages[0].version, "1.0.99");
        assert_eq!(
            packages[0].source.as_deref(),
            Some("registry+https://github.com/rust-lang/crates.io-index")
        );
        assert_eq!(packages[1].name, "loop3r");
        assert!(packages[1].source.is_none());
    }

    #[test]
    fn rejects_cargo_lock_without_packages() {
        let error = parse_cargo_lock(Path::new("Cargo.lock"), "version = 3\n").unwrap_err();
        assert!(error.to_string().contains("no [[package]] sections"));
    }

    #[test]
    fn rejects_package_section_missing_version() {
        let text = "[[package]]\nname = \"broken\"\n";
        let error = parse_cargo_lock(Path::new("Cargo.lock"), text).unwrap_err();
        assert!(error.to_string().contains("missing version"));
    }

    #[test]
    fn parses_package_lock_v3_packages() {
        let text = r#"{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "fixture"},
    "node_modules/left-pad": {"version": "1.3.0"},
    "node_modules/@scope/name": {"version": "2.0.1"},
    "node_modules/workspace": {"resolved": "workspace:*", "link": true},
    "node_modules/no-version": {}
  }
}"#;
        let packages = parse_package_lock(Path::new("package-lock.json"), text).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().any(|item| item.name == "left-pad"
            && item.version == "1.3.0"
            && item.ecosystem == "npm"));
        assert!(
            packages
                .iter()
                .any(|item| item.name == "@scope/name" && item.version == "2.0.1")
        );
    }

    #[test]
    fn parses_package_lock_v1_dependencies() {
        let text = r#"{
  "name": "fixture",
  "lockfileVersion": 1,
  "dependencies": {
    "left-pad": {"version": "1.3.0"},
    "broken": {}
  }
}"#;
        let packages = parse_package_lock(Path::new("package-lock.json"), text).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "left-pad");
    }

    #[test]
    fn rejects_unrecognized_package_lock() {
        let error =
            parse_package_lock(Path::new("package-lock.json"), "{\"name\":\"x\"}").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("neither packages nor dependencies")
        );
    }
}
