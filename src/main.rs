//! loop3r: self-contained source security auditor (CLI entry point).
//!
//! This crate root only declares modules, defines the clap CLI (`scan`,
//! `web`, `deps`, `diff`, `validate`), dispatches to the analysis modules,
//! and maps outcomes onto exit codes: `0` clean (or success for
//! `deps`/`diff`), `1` gated findings / schema errors, `2` scanner or
//! configuration errors. All analysis lives in the sibling modules —
//! `main.rs` orchestrates and renders, nothing more.
//!
//! The `tests` module below holds the cross-module integration suite:
//! grammar fixtures, rule-matching semantics, filesystem scope, baseline /
//! diff / suppression flows, and real loopback HTTP probes. Unit tests for
//! individual modules live next to their code.

mod advisory;
mod core;
mod deps;
mod diff;
mod fingerprint;
mod imports;
mod language;
mod report;
mod sarif;
mod sbom;
mod schema;
mod scope;
mod secrets;
mod source;
mod suppress;
mod taint;
mod web;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser as ClapParser, Subcommand};

use crate::language::LanguageId;
use crate::report::write_private;
use crate::scope::Scope;

/// Output format for `scan` and `web`: native JSON or SARIF 2.1.0.
/// `Copy` because the value is matched repeatedly during rendering.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum ReportFormat {
    /// loop3r's native versioned JSON report.
    Json,
    /// SARIF 2.1.0 for GitHub code scanning and IDE ingestion.
    Sarif,
}

impl std::fmt::Display for ReportFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(formatter, "json"),
            Self::Sarif => write!(formatter, "sarif"),
        }
    }
}

/// Output format for `deps`: native JSON inventory or CycloneDX SBOM.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum DepsFormat {
    /// loop3r's native versioned JSON inventory.
    Json,
    /// CycloneDX 1.6 SBOM rendered from the inventory.
    Sbom,
}
impl std::fmt::Display for DepsFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(formatter, "json"),
            Self::Sbom => write!(formatter, "sbom"),
        }
    }
}

/// Which embedded schema `validate` checks a report file against.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum SchemaKind {
    /// Latest source scan report schema.
    Scan,
    /// Dependency inventory schema.
    Deps,
    /// Web probe report schema.
    Web,
    /// Diff comparison schema.
    Diff,
}

impl SchemaKind {
    /// Short schema name understood by `schema::load_schema`.
    fn name(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Deps => "deps",
            Self::Web => "web",
            Self::Diff => "diff",
        }
    }
}

#[derive(ClapParser)]
#[command(
    name = "loop3r",
    version,
    about = "Self-contained source security auditor"
)]
struct Cli {
    /// The single required subcommand; loop3r has no bare mode.
    #[command(subcommand)]
    command: Command,
}

/// Subcommands. Each renders machine output (`--json`/`--output`/non-default
/// `--format`) or a one-line human summary, and returns its exit code.
#[derive(Subcommand)]
enum Command {
    /// Parse source with embedded grammars and report syntax coverage.
    Scan {
        /// File or directory to audit.
        target: PathBuf,
        /// Per-file byte cap; larger files are refused (single target) or
        /// counted as skipped (directory walk). Default 1 MB.
        #[arg(long, default_value_t = 1_000_000)]
        max_file_bytes: u64,
        /// Print the machine report to stdout instead of the human summary.
        #[arg(long)]
        json: bool,
        /// Write the machine report atomically (mode 0600 on Unix).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Deadline in seconds; expiry marks `timed_out`, never silently
        /// drops work. Default 600.
        #[arg(long, default_value_t = 600)]
        budget_seconds: u64,
        /// Shuffle seed for file order; defaults to time-derived nanos.
        /// Fixed seeds reproduce budget-expiry partial scans exactly.
        #[arg(long)]
        seed: Option<u64>,
        /// Include globs (repeatable); empty means everything.
        #[arg(long)]
        include: Vec<String>,
        /// Exclude globs (repeatable); always wins over includes.
        #[arg(long)]
        exclude: Vec<String>,
        /// Language filter (repeatable); empty means all. Never excludes
        /// secrets-only configs from secret scanning.
        #[arg(long, value_enum)]
        language: Vec<LanguageId>,
        /// Report rendering: native JSON or SARIF 2.1.0.
        #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
        format: ReportFormat,
        /// Baseline report: gates the exit code on NEW findings only.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Suppression file: annotates findings, never deletes them.
        #[arg(long)]
        suppress: Option<PathBuf>,
    },
    /// Run read-only HTTP checks against an authorized loopback website.
    Web {
        /// URL to probe; must be loopback http/https without credentials.
        url: String,
        /// Explicit authorization flag — probing requires opt-in even for
        /// loopback, so accidental scans in scripts fail loudly.
        #[arg(long)]
        authorized: bool,
        /// Request timeout in seconds (1–120). Default 10.
        #[arg(long, default_value_t = 10)]
        timeout_seconds: u64,
        /// Print the machine report to stdout instead of the human summary.
        #[arg(long)]
        json: bool,
        /// Write the machine report atomically (mode 0600 on Unix).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Report rendering: native JSON or SARIF 2.1.0.
        #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
        format: ReportFormat,
    },
    /// Inventory exact dependency versions from lockfiles, optionally matched advisories.
    Deps {
        /// File or directory to inventory.
        target: PathBuf,
        /// Print the machine report to stdout instead of the human summary.
        #[arg(long)]
        json: bool,
        /// Write the machine report atomically (mode 0600 on Unix).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Rendering: native JSON inventory or CycloneDX SBOM.
        #[arg(long, value_enum, default_value_t = DepsFormat::Json)]
        format: DepsFormat,
        /// Advisory snapshot for exact-version vulnerability matching.
        #[arg(long)]
        advisory_db: Option<PathBuf>,
    },
    /// Compare two source scan reports by finding fingerprint.
    Diff {
        /// Older (baseline-side) report.
        old: PathBuf,
        /// Newer (current-side) report.
        new: PathBuf,
        /// Print the machine report to stdout instead of the human summary.
        #[arg(long)]
        json: bool,
        /// Write the machine report atomically (mode 0600 on Unix).
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Validate a report file against its embedded JSON schema.
    Validate {
        /// Report file to check.
        file: PathBuf,
        /// Which schema to check against (scan/deps/web/diff).
        #[arg(long, value_enum)]
        schema: SchemaKind,
    },
}

/// Dispatches the CLI: parses flags, runs the analysis, renders output,
/// and returns the process exit code (0/1). Hard failures return `Err` and
/// become exit code 2 in [`main`].
fn run() -> Result<u8> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan {
            target,
            max_file_bytes,
            json,
            output,
            budget_seconds,
            seed,
            include,
            exclude,
            language,
            format,
            baseline,
            suppress,
        } => {
            // Zero budget or zero cap would scan nothing while reporting
            // success — reject instead.
            if budget_seconds == 0 || max_file_bytes == 0 {
                bail!("budget-seconds and max-file-bytes must be positive");
            }
            // Default seed is time-derived so repeated budget-limited scans
            // cover different files; explicit `--seed` replays exactly.
            let seed = seed.unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64
            });
            // Scope compiles (and validates globs) before any I/O, so a bad
            // pattern fails fast instead of after a long scan.
            let scope = Scope::new(include, exclude, language)?;
            let mut report = source::scan(&target, max_file_bytes, budget_seconds, seed, scope)?;
            // Suppressions apply before baselining so `has_unsuppressed_new`
            // sees settled suppression state when gating the exit code.
            if let Some(path) = &suppress {
                suppress::apply_suppressions(&mut report, path)?;
            }
            let mut baseline_sets = None;
            if let Some(path) = &baseline {
                baseline_sets = Some(diff::apply_baseline(&mut report, path)?);
            }
            let rendered = match format {
                ReportFormat::Json => serde_json::to_vec_pretty(&report)?,
                ReportFormat::Sarif => serde_json::to_vec_pretty(&sarif::source_to_sarif(&report))?,
            };
            // Machine output whenever the user asked for a file, JSON, or a
            // non-default format; otherwise a one-line human summary.
            let machine = output.is_some() || json || !matches!(format, ReportFormat::Json);
            if let Some(path) = output {
                write_private(&path, &rendered)?;
                println!("{}", path.display());
            } else if machine {
                println!(
                    "{}",
                    String::from_utf8(rendered).context("serializing report")?
                );
            } else {
                println!(
                    "{} files parsed ({} secret-only scanned); {} syntax findings; {} security findings; {} secret findings",
                    report.files_parsed,
                    report.secret_files_scanned,
                    report.syntax_findings.len(),
                    report.security_findings.len(),
                    report.secret_findings.len()
                );
                if report.files_skipped_oversized > 0 || report.files_skipped_unsupported > 0 {
                    println!(
                        "skipped {} oversized and {} unsupported files",
                        report.files_skipped_oversized, report.files_skipped_unsupported
                    );
                }
                if let Some(summary) = &report.baseline {
                    println!(
                        "baseline {}: {} new security, {} new secrets ({} fixed)",
                        summary.path.display(),
                        summary.new_security,
                        summary.new_secrets,
                        summary.fixed_security + summary.fixed_secrets
                    );
                }
                if let Some(file) = &report.suppressions.file {
                    println!(
                        "suppressions from {}: {} applied, {} expired",
                        file.display(),
                        report.suppressions.applied,
                        report.suppressions.expired.len()
                    );
                    for expired in &report.suppressions.expired {
                        println!("  expired: {expired}");
                    }
                }
            }
            // Exit 1 only for live, unsuppressed, non-baselined findings:
            // suppressed or already-known findings never fail CI.
            Ok(u8::from(diff::has_unsuppressed_new(
                &report,
                baseline_sets.as_ref(),
            )))
        }
        Command::Web {
            url,
            authorized,
            timeout_seconds,
            json,
            output,
            format,
        } => {
            // The authorization gate lives in the CLI (not the library) so
            // tests can probe loopback without the flag while every real
            // invocation must opt in.
            if !authorized {
                bail!("--authorized required for web checks");
            }
            let report = web::web_scan(&url, timeout_seconds)?;
            let rendered = match format {
                ReportFormat::Json => serde_json::to_vec_pretty(&report)?,
                ReportFormat::Sarif => serde_json::to_vec_pretty(&sarif::web_to_sarif(&report))?,
            };
            let machine = output.is_some() || json || !matches!(format, ReportFormat::Json);
            if let Some(path) = output {
                write_private(&path, &rendered)?;
                println!("{}", path.display());
            } else if machine {
                println!(
                    "{}",
                    String::from_utf8(rendered).context("serializing report")?
                );
            } else {
                println!("HTTP {}; {} findings", report.status, report.findings.len());
                if let Some(location) = &report.redirect {
                    println!("redirects disabled; Location: {location}");
                }
            }
            // Any web finding fails: probes have no baseline or suppression
            // model, so every observation is actionable.
            Ok(u8::from(!report.findings.is_empty()))
        }
        Command::Deps {
            target,
            json,
            output,
            format,
            advisory_db,
        } => {
            let mut report = deps::inventory(&target)?;
            if let Some(path) = &advisory_db {
                advisory::apply_advisory_db(&mut report, path)?;
            }
            let rendered = match format {
                DepsFormat::Json => serde_json::to_vec_pretty(&report)?,
                DepsFormat::Sbom => serde_json::to_vec_pretty(&sbom::deps_to_cyclonedx(&report))?,
            };
            let machine = output.is_some() || json || !matches!(format, DepsFormat::Json);
            if let Some(path) = output {
                write_private(&path, &rendered)?;
                println!("{}", path.display());
            } else if machine {
                println!(
                    "{}",
                    String::from_utf8(rendered).context("serializing report")?
                );
            // The human summary names the advisory DB whenever matching ran,
            // so "0 vulnerabilities" is never ambiguous about what ran.
            } else if let Some(path) = &report.advisory_db {
                println!(
                    "{} packages from {} lockfiles; {} unsupported; {} errors; {} vulnerabilities (db {})",
                    report.packages.len(),
                    report.lockfiles.len(),
                    report.unsupported.len(),
                    report.errors.len(),
                    report.vulnerabilities.len(),
                    path.display()
                );
            } else {
                println!(
                    "{} packages from {} lockfiles; {} unsupported; {} errors",
                    report.packages.len(),
                    report.lockfiles.len(),
                    report.unsupported.len(),
                    report.errors.len()
                );
            }
            // Inventory itself never gates: `deps` reports facts, and policy
            // (advisory severity gates) lives in the consumer.
            Ok(0)
        }
        Command::Diff {
            old,
            new,
            json,
            output,
        } => {
            let report = diff::compare(&old, &new)?;
            let rendered = serde_json::to_vec_pretty(&report)?;
            if let Some(path) = output {
                write_private(&path, &rendered)?;
                println!("{}", path.display());
            } else if json {
                println!(
                    "{}",
                    String::from_utf8(rendered).context("serializing report")?
                );
            } else {
                println!(
                    "+{} -{} security, +{} -{} secrets ({} unchanged)",
                    report.added_security.len(),
                    report.fixed_security.len(),
                    report.added_secrets.len(),
                    report.fixed_secrets.len(),
                    report.unchanged_security + report.unchanged_secrets
                );
            }
            Ok(0)
        }
        Command::Validate { file, schema } => {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let report: serde_json::Value = serde_json::from_str(&text)
                .with_context(|| format!("parsing {}", file.display()))?;
            let schema_value = schema::load_schema(schema.name())?;
            let errors = schema::conformance_errors(&report, &schema_value);
            if errors.is_empty() {
                println!("{} conforms to {} schema", file.display(), schema.name());
                Ok(0)
            } else {
                for error in &errors {
                    println!("{error}");
                }
                Ok(1)
            }
        }
    }
}

/// Entry point: finding-gate exits (0/1) pass through, while any `Err`
/// (bad flags, I/O, validation failures) prints the full error chain to
/// stderr and exits 2 — distinguishing "findings found" from "scan broken".
fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("loop3r: {error:#}");
            ExitCode::from(2)
        }
    }
}

/// Cross-module integration suite: no mocks anywhere — real grammars,
/// real tempdir filesystems, and real loopback TCP servers. Fixture
/// snippets are minimal but must parse WITHOUT grammar errors, so a
/// fixture failure always means a regression, never a bad fixture.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::AstRule;
    use crate::language::LanguageId;
    use crate::scope::Scope;
    use std::path::Path;
    use tree_sitter::Parser;

    /// Smoke test for every embedded grammar: one idiomatic snippet each,
    /// all must parse error-free. Catches grammar/ABI breakage on upgrade.
    #[test]
    fn every_language_parses_real_syntax() {
        let fixtures = [
            (LanguageId::C, "int main(void) { return 0; }"),
            (
                LanguageId::CSharp,
                "class A { static void Main() { System.Console.WriteLine(1); } }",
            ),
            (LanguageId::Css, "body { color: #123; }"),
            (LanguageId::Go, "package main\nfunc main() {}"),
            (LanguageId::Html, "<!doctype html><title>x</title>"),
            (
                LanguageId::Java,
                "class A { public static void main(String[] a) {} }",
            ),
            (LanguageId::JavaScript, "const x = (n) => n + 1;"),
            (LanguageId::Kotlin, "fun main() { println(1) }"),
            (LanguageId::Php, "<?php echo 'x'; ?>"),
            (
                LanguageId::Python,
                "def f(x: int) -> int:\n    return x + 1\n",
            ),
            (LanguageId::Ruby, "def f(x)\n  x + 1\nend\n"),
            (LanguageId::Rust, "fn main() { println!(\"x\"); }"),
            (LanguageId::Shell, "#!/bin/sh\nset -eu\nprintf '%s\\n' x\n"),
            (LanguageId::Sql, "SELECT id FROM users WHERE active = TRUE;"),
            (LanguageId::Swift, "func f(_ x: Int) -> Int { x + 1 }"),
            (LanguageId::TypeScript, "const x: number = 1;"),
            (LanguageId::Tsx, "const x = <div>safe</div>;"),
        ];
        for (language, source) in fixtures {
            let mut parser = Parser::new();
            parser.set_language(&language.grammar()).unwrap();
            let tree = parser.parse(source, None).unwrap();
            assert!(
                !tree.root_node().has_error(),
                "{language:?}: {}",
                tree.root_node().to_sexp()
            );
        }
    }

    /// The structural-matching guarantee: `eval(user)` in a comment and in
    /// a string literal are silent; only the real call on line 3 fires.
    /// A text-grep scanner would report three hits.
    #[test]
    fn ast_rule_ignores_comments_and_strings() {
        let rules = crate::core::load_ast_rules().unwrap();
        let source = b"# eval(user)\ns = 'eval(user)'\neval(user)\n";
        let mut parser = Parser::new();
        parser.set_language(&LanguageId::Python.grammar()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut syntax = Vec::new();
        let mut security = Vec::new();
        crate::source::inspect_for_tests(
            tree.root_node(),
            source,
            Path::new("x.py"),
            LanguageId::Python,
            &rules,
            &mut syntax,
            &mut security,
        );
        assert_eq!(security.len(), 1);
        assert_eq!(security[0].line, 3);
        assert_eq!(security[0].rule_id, "CORE-PY-EVAL");
    }

    /// Test helper: parses one snippet with the real grammar and returns
    /// its security findings. Panics on grammar ERRORS so fixtures stay
    /// valid — findings assertions then test rules, not parsing.
    fn findings(language: LanguageId, source: &str) -> Vec<crate::report::SecurityFinding> {
        let rules = crate::core::load_ast_rules().unwrap();
        let mut parser = Parser::new();
        parser.set_language(&language.grammar()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let mut syntax = Vec::new();
        let mut security = Vec::new();
        crate::source::inspect_for_tests(
            tree.root_node(),
            source.as_bytes(),
            Path::new("fixture"),
            language,
            &rules,
            &mut syntax,
            &mut security,
        );
        security
    }

    /// One canonical dangerous call per language family fires its rule:
    /// proves each language's call-shape extraction works end to end.
    #[test]
    fn language_specific_calls_are_structural() {
        let cases = [
            (
                LanguageId::C,
                "int f(char *d, char *s) { strcpy(d, s); return 0; }",
                "CORE-C-BOUNDS",
            ),
            (
                LanguageId::JavaScript,
                "child_process.exec(user);",
                "CORE-JS-SHELL",
            ),
            (
                LanguageId::Java,
                "class A { void f(String x) throws Exception { Runtime.getRuntime().exec(x); } }",
                "CORE-JAVA-SHELL",
            ),
            (
                LanguageId::CSharp,
                "class A { void F(string x) { System.Diagnostics.Process.Start(x); } }",
                "CORE-CS-PROCESS",
            ),
            (
                LanguageId::Go,
                "package p\nimport \"os/exec\"\nfunc f(x string) { exec.Command(x) }",
                "CORE-GO-PROCESS",
            ),
            (
                LanguageId::Php,
                "<?php unserialize($x); ?>",
                "CORE-PHP-DESERIALIZE",
            ),
            (
                LanguageId::Ruby,
                "Marshal.load(input)\n",
                "CORE-RB-DESERIALIZE",
            ),
            (
                LanguageId::Rust,
                "fn f(x: u32) -> f32 { unsafe { std::mem::transmute(x) } }",
                "CORE-RUST-TRANSMUTE",
            ),
            (LanguageId::Shell, "eval \"$input\"\n", "CORE-SH-EVAL"),
            (
                LanguageId::Swift,
                "import Foundation\nfunc f(_ x: String) { Process.launchedProcess(launchPath: x, arguments: []) }",
                "CORE-SWIFT-PROCESS",
            ),
        ];
        for (language, source, expected) in cases {
            let found = findings(language, source);
            assert!(
                found.iter().any(|item| item.rule_id == expected),
                "{language:?}: {found:?}"
            );
        }
    }

    /// Import resolution end to end: `from` imports, `as` aliases,
    /// destructured and namespace `require`, and ESM imports all fire the
    /// canonical rule AND record the resolved callee (`os.system`, …).
    #[test]
    fn imported_aliases_resolve_to_canonical_callees() {
        let cases = [
            (
                LanguageId::Python,
                "from os import system\nsystem(x)\n",
                "CORE-PY-SHELL",
                "os.system",
            ),
            (
                LanguageId::Python,
                "from os import system as run\nrun(x)\n",
                "CORE-PY-SHELL",
                "os.system",
            ),
            (
                LanguageId::Python,
                "from pickle import loads\nloads(x)\n",
                "CORE-PY-DESERIALIZE",
                "pickle.loads",
            ),
            (
                LanguageId::JavaScript,
                "const {exec} = require('child_process');\nexec(x);\n",
                "CORE-JS-SHELL",
                "child_process.exec",
            ),
            (
                LanguageId::JavaScript,
                "const {exec: run} = require('child_process');\nrun(x);\n",
                "CORE-JS-SHELL",
                "child_process.exec",
            ),
            (
                LanguageId::JavaScript,
                "const cp = require('child_process');\ncp.exec(x);\n",
                "CORE-JS-SHELL",
                "child_process.exec",
            ),
            (
                LanguageId::JavaScript,
                "import {exec} from 'child_process';\nexec(x);\n",
                "CORE-JS-SHELL",
                "child_process.exec",
            ),
            (
                LanguageId::JavaScript,
                "import * as cp from 'child_process';\ncp.exec(x);\n",
                "CORE-JS-SHELL",
                "child_process.exec",
            ),
            (
                LanguageId::TypeScript,
                "import {exec} from 'child_process';\nexec(x);\n",
                "CORE-JS-SHELL",
                "child_process.exec",
            ),
        ];
        for (language, source, expected_rule, expected_canonical) in cases {
            let found = findings(language, source);
            let matched = found
                .iter()
                .find(|item| item.rule_id == expected_rule)
                .unwrap_or_else(|| panic!("{language:?}: {found:?}"));
            assert_eq!(
                matched.resolved_callee.as_deref(),
                Some(expected_canonical),
                "{language:?}"
            );
        }
    }

    /// Resolution negatives: bare names, locals, and same-named imports
    /// from unrelated modules (`./local`) must NOT fire import-gated rules.
    #[test]
    fn unimported_and_unrelated_names_do_not_resolve() {
        let cases = [
            (LanguageId::Python, "system = 1\nsystem(x)\n"),
            (LanguageId::Python, "from os import path\npath(x)\n"),
            (
                LanguageId::JavaScript,
                "const {exec} = require('./local');\nexec(x);\n",
            ),
            (LanguageId::JavaScript, "exec(x);\n"),
        ];
        for (language, source) in cases {
            assert!(findings(language, source).is_empty(), "{language:?}");
        }
    }

    /// Argument matchers: `shell=True` (any spacing, direct or aliased),
    /// bare `yaml.load`, `{shell: true}`, and PHP `eval` fire; `shell=False`,
    /// missing shell flags, and `SafeLoader` stay silent.
    #[test]
    fn arg_aware_rules_fire_only_on_dangerous_arguments() {
        let positive = [
            (
                LanguageId::Python,
                "subprocess.run(cmd, shell=True)\n",
                "CORE-PY-SUBPROCESS-SHELL",
            ),
            (
                LanguageId::Python,
                "subprocess.run(cmd, shell = True)\n",
                "CORE-PY-SUBPROCESS-SHELL",
            ),
            (
                LanguageId::Python,
                "from subprocess import run\nrun(cmd, shell=True)\n",
                "CORE-PY-SUBPROCESS-SHELL",
            ),
            (LanguageId::Python, "yaml.load(data)\n", "CORE-PY-YAML-LOAD"),
            (
                LanguageId::JavaScript,
                "child_process.spawn(cmd, { shell: true });\n",
                "CORE-JS-SPAWN-SHELL",
            ),
            (
                LanguageId::JavaScript,
                "const {spawn} = require('child_process');\nspawn(cmd, { shell: true });\n",
                "CORE-JS-SPAWN-SHELL",
            ),
            (LanguageId::Php, "<?php eval($x); ?>", "CORE-PHP-EVAL"),
        ];
        for (language, source, expected) in positive {
            let found = findings(language, source);
            let matched = found
                .iter()
                .find(|item| item.rule_id == expected)
                .unwrap_or_else(|| panic!("{language:?} {expected}: {found:?}"));
            if expected == "CORE-PY-SUBPROCESS-SHELL" && source.contains("from subprocess") {
                assert_eq!(matched.resolved_callee.as_deref(), Some("subprocess.run"));
            }
            if expected == "CORE-JS-SPAWN-SHELL" && source.contains("require") {
                assert_eq!(
                    matched.resolved_callee.as_deref(),
                    Some("child_process.spawn")
                );
            }
        }
        let negative = [
            (LanguageId::Python, "subprocess.run(cmd, shell=False)\n"),
            (LanguageId::Python, "subprocess.run(cmd)\n"),
            (
                LanguageId::Python,
                "yaml.load(data, Loader=yaml.SafeLoader)\n",
            ),
            (LanguageId::JavaScript, "child_process.spawn(cmd);\n"),
            (
                LanguageId::JavaScript,
                "child_process.spawn(cmd, { shell: false });\n",
            ),
        ];
        for (language, source) in negative {
            assert!(
                findings(language, source).is_empty(),
                "{language:?} {source}"
            );
        }
    }

    /// Taint-lite contract: a parameter-to-sink flow records the trace and
    /// upgrades `review` rules from low to medium; literals, direct flows on
    /// non-review rules, and `shlex.quote`-sanitized flows behave exactly as
    /// specified; JavaScript parameters flow too.
    #[test]
    fn taint_flow_is_reported_and_upgrades_review_confidence() {
        let found = findings(
            LanguageId::Python,
            "def f(cmd):\n    full = cmd + ' x'\n    os.system(full)\n",
        );
        let matched = found
            .iter()
            .find(|item| item.rule_id == "CORE-PY-SHELL")
            .unwrap();
        assert_eq!(serde_json::to_value(matched.confidence).unwrap(), "medium");
        let taint = matched.taint.as_ref().unwrap();
        assert_eq!(taint.variable, "full");
        assert!(taint.source.contains("parameter `cmd`"), "{}", taint.source);

        let found = findings(LanguageId::Python, "def f(cmd):\n    os.system('ls')\n");
        let matched = found
            .iter()
            .find(|item| item.rule_id == "CORE-PY-SHELL")
            .unwrap();
        assert_eq!(serde_json::to_value(matched.confidence).unwrap(), "low");
        assert!(matched.taint.is_none());

        let found = findings(LanguageId::Python, "def f(cmd):\n    eval(cmd)\n");
        let matched = found
            .iter()
            .find(|item| item.rule_id == "CORE-PY-EVAL")
            .unwrap();
        assert_eq!(serde_json::to_value(matched.confidence).unwrap(), "medium");
        assert!(matched.taint.is_some());

        let found = findings(
            LanguageId::Python,
            "def f(cmd):\n    safe = shlex.quote(cmd)\n    os.system(safe)\n",
        );
        let matched = found
            .iter()
            .find(|item| item.rule_id == "CORE-PY-SHELL")
            .unwrap();
        assert!(matched.taint.is_none());

        let found = findings(
            LanguageId::JavaScript,
            "function f(cmd) { child_process.exec(cmd); }\n",
        );
        let matched = found
            .iter()
            .find(|item| item.rule_id == "CORE-JS-SHELL")
            .unwrap();
        assert_eq!(serde_json::to_value(matched.confidence).unwrap(), "medium");
        assert!(matched.taint.is_some());
    }

    /// Rule-catalog coverage: the fixture set must fire EVERY catalog rule
    /// (found == catalog, so new rules require new fixtures), and each hit
    /// carries the specified default confidence (`low` for review, `medium`
    /// otherwise) before any taint upgrade.
    #[test]
    fn every_ast_rule_has_a_real_parse_tree_fixture() {
        let fixtures = [
            (
                LanguageId::C,
                "void f(char*d,char*s){strcpy(d,s);system(s);}",
            ),
            (
                LanguageId::Python,
                "eval(x)\nos.system(x)\npickle.loads(x)\nsubprocess.run(cmd, shell=True)\nyaml.load(data)\n",
            ),
            (
                LanguageId::JavaScript,
                "eval(x);\nchild_process.exec(x);\nchild_process.spawn(cmd, { shell: true });\n",
            ),
            (
                LanguageId::Php,
                "<?php system($x); unserialize($x); eval($x); ?>",
            ),
            (LanguageId::Ruby, "eval(x)\nsystem(x)\nMarshal.load(x)\n"),
            (
                LanguageId::Rust,
                "fn f(x:u32)->f32{unsafe{std::mem::transmute(x)}}",
            ),
            (LanguageId::Shell, "eval \"$x\"\n"),
            (
                LanguageId::Java,
                "class A{void f(String x)throws Exception{Runtime.getRuntime().exec(x);}}",
            ),
            (
                LanguageId::CSharp,
                "class A{void F(string x){System.Diagnostics.Process.Start(x);}}",
            ),
            (
                LanguageId::Go,
                "package p\nimport \"os/exec\"\nfunc f(x string){exec.Command(x)}",
            ),
            (
                LanguageId::Swift,
                "import Foundation\nfunc f(_ x:String){Process.launchedProcess(launchPath:x,arguments:[])}",
            ),
        ];
        let rules: Vec<AstRule> = crate::core::load_ast_rules().unwrap();
        let mut found = std::collections::BTreeSet::new();
        for (language, source) in fixtures {
            for finding in findings(language, source) {
                let expected_confidence = if finding.severity == "review" {
                    "low"
                } else {
                    "medium"
                };
                assert_eq!(
                    serde_json::to_value(finding.confidence).unwrap(),
                    expected_confidence,
                    "{}",
                    finding.rule_id
                );
                found.insert(finding.rule_id);
            }
        }
        let expected: std::collections::BTreeSet<_> =
            rules.into_iter().map(|rule| rule.id).collect();
        assert_eq!(found, expected);
    }

    /// Catalog size pin: exactly 22 AST rules. Update deliberately when
    /// adding rules — the number guards against accidental drops.
    #[test]
    fn core_rule_catalog_is_well_formed() {
        let rules = crate::core::load_ast_rules().unwrap();
        assert_eq!(rules.len(), 22);
    }

    /// Filesystem scope end to end: include globs + language filter select
    /// exactly one file from two, the 4-key confidence scale serializes into
    /// the report, and `write_private` lands a 0600 file on Unix.
    #[test]
    fn real_filesystem_scope_and_private_report() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("src")).unwrap();
        std::fs::create_dir(directory.path().join("ignored")).unwrap();
        std::fs::write(directory.path().join("src/app.py"), "eval(user)\n").unwrap();
        std::fs::write(directory.path().join("ignored/app.js"), "eval(user);\n").unwrap();
        let scope = Scope::new(vec!["src/**".into()], vec![], vec![LanguageId::Python]).unwrap();
        let report = crate::source::scan(directory.path(), 1_000_000, 600, 42, scope).unwrap();
        assert_eq!(report.files_parsed, 1);
        assert_eq!(report.security_findings.len(), 1);
        let serialized = serde_json::to_value(&report).unwrap();
        assert_eq!(serialized["confidence_scale"].as_object().unwrap().len(), 4);
        assert_eq!(serialized["security_findings"][0]["confidence"], "medium");
        let output = directory.path().join("report.json");
        write_private(&output, &serde_json::to_vec(&report).unwrap()).unwrap();
        assert!(output.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                output.metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    /// Secret redaction guarantee: the AWS key fires from inside a `.py`
    /// file, but the SERIALIZED report never contains the raw key — only
    /// the `AKIA[redacted]ZZZZ` evidence form.
    #[test]
    fn filesystem_scan_redacts_embedded_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let key = format!("AKIA{}", "Z".repeat(16));
        std::fs::write(
            directory.path().join("app.py"),
            format!("key = \"{key}\"\n"),
        )
        .unwrap();
        let scope = Scope::new(vec![], vec![], vec![]).unwrap();
        let report = crate::source::scan(directory.path(), 1_000_000, 600, 42, scope).unwrap();
        assert_eq!(report.secret_findings.len(), 1);
        assert_eq!(report.secret_findings[0].rule_id, "SECRET-AWS-ACCESS-KEY");
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains(&key));
        assert!(serialized.contains("AKIA[redacted]ZZZZ"));
    }

    /// Inventory across ecosystems: Cargo + npm lockfiles parse into
    /// sorted packages (cargo before npm), while `yarn.lock` lands in
    /// `unsupported` — counted, never silent.
    #[test]
    fn dependency_inventory_reports_packages_and_unsupported() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("Cargo.lock"),
            "version = 3\n\n[[package]]\nname = \"anyhow\"\nversion = \"1.0.99\"\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("package-lock.json"),
            r#"{"lockfileVersion": 3, "packages": {"": {}, "node_modules/left-pad": {"version": "1.3.0"}}}"#,
        )
        .unwrap();
        std::fs::write(directory.path().join("yarn.lock"), "# yarn\n").unwrap();
        let report = crate::deps::inventory(directory.path()).unwrap();
        assert_eq!(report.schema_version, 2);
        assert_eq!(report.lockfiles.len(), 2);
        assert_eq!(report.packages.len(), 2);
        assert_eq!(report.unsupported.len(), 1);
        assert!(report.errors.is_empty());
        assert_eq!(report.packages[0].ecosystem, "cargo");
        assert_eq!(report.packages[1].ecosystem, "npm");
    }

    /// A garbage `Cargo.lock` during a directory walk records one error and
    /// zero lockfiles — the inventory survives, and the failure is visible.
    #[test]
    fn dependency_inventory_records_malformed_lockfile() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("Cargo.lock"), "not toml [[[\n").unwrap();
        let report = crate::deps::inventory(directory.path()).unwrap();
        assert!(report.lockfiles.is_empty());
        assert_eq!(report.errors.len(), 1);
    }

    /// Advisory matching on a real inventory: the exact-version entry hits,
    /// the wrong-version entry misses, and the SBOM renders the package.
    #[test]
    fn advisory_db_matches_exact_inventory_versions() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("Cargo.lock"),
            "[[package]]\nname = \"left-pad\"\nversion = \"1.3.0\"\n",
        )
        .unwrap();
        let db = directory.path().join("snapshot.json");
        std::fs::write(
            &db,
            r#"{"format_version": 1, "advisories": [
                {"id": "TEST-001", "ecosystem": "cargo", "package": "left-pad",
                 "vulnerable_versions": ["1.3.0"], "severity": "high",
                 "summary": "Test fixture.", "reference": "https://example.invalid/t1"},
                {"id": "TEST-002", "ecosystem": "cargo", "package": "left-pad",
                 "vulnerable_versions": ["9.9.9"], "severity": "critical",
                 "summary": "Test fixture.", "reference": "https://example.invalid/t2"}
            ]}"#,
        )
        .unwrap();
        let mut report = crate::deps::inventory(directory.path()).unwrap();
        crate::advisory::apply_advisory_db(&mut report, &db).unwrap();
        assert_eq!(report.vulnerabilities.len(), 1);
        assert_eq!(report.vulnerabilities[0].advisory_id, "TEST-001");
        assert_eq!(report.vulnerabilities[0].version, "1.3.0");
        let sbom = crate::sbom::deps_to_cyclonedx(&report);
        assert_eq!(sbom["components"].as_array().unwrap().len(), 1);
    }

    /// Skip accounting with a 7-byte cap: one parsed, one oversized, one
    /// unsupported (`.md`) — every input file lands in exactly one bucket.
    #[test]
    fn scan_reports_oversized_and_unsupported_skips() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("ok.py"), "x = 1\n").unwrap();
        std::fs::write(directory.path().join("big.py"), "x = 1\ny = 2\n").unwrap();
        std::fs::write(directory.path().join("notes.md"), "# docs\n").unwrap();
        let scope = Scope::new(vec![], vec![], vec![]).unwrap();
        let report = crate::source::scan(directory.path(), 7, 600, 42, scope).unwrap();
        assert_eq!(report.files_parsed, 1);
        assert_eq!(report.files_skipped_oversized, 1);
        assert_eq!(report.files_skipped_unsupported, 1);
    }

    /// Config handling: `.env` + `config.json` count as secret-scanned (not
    /// parsed), the `.md` file is unsupported, the `.env` key fires without
    /// leaking into the serialized report.
    #[test]
    fn config_files_are_scanned_for_secrets_only() {
        let directory = tempfile::tempdir().unwrap();
        let key = format!("AKIA{}", "Z".repeat(16));
        std::fs::write(directory.path().join("app.py"), "x = 1\n").unwrap();
        std::fs::write(directory.path().join(".env"), format!("AWS_KEY={key}\n")).unwrap();
        std::fs::write(
            directory.path().join("config.json"),
            "{\"note\": \"no secrets here\"}\n",
        )
        .unwrap();
        std::fs::write(directory.path().join("notes.md"), "# docs\n").unwrap();
        let scope = Scope::new(vec![], vec![], vec![]).unwrap();
        let report = crate::source::scan(directory.path(), 1_000_000, 600, 42, scope).unwrap();
        assert_eq!(report.files_parsed, 1);
        assert_eq!(report.secret_files_scanned, 2);
        assert_eq!(report.files_skipped_unsupported, 1);
        assert_eq!(report.secret_findings.len(), 1);
        assert_eq!(report.secret_findings[0].rule_id, "SECRET-AWS-ACCESS-KEY");
        assert!(report.secret_findings[0].path.ends_with(".env"));
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains(&key));
    }

    /// Single-file secret target: scanning a `.toml` directly yields zero
    /// parsed files, one secret-scanned file, and the GitHub token finding.
    #[test]
    fn single_secret_file_target_scans() {
        let directory = tempfile::tempdir().unwrap();
        let token = format!("ghp_{}", "b".repeat(36));
        let path = directory.path().join("settings.toml");
        std::fs::write(&path, format!("token = \"{token}\"\n")).unwrap();
        let scope = Scope::new(vec![], vec![], vec![]).unwrap();
        let report = crate::source::scan(&path, 1_000_000, 600, 42, scope).unwrap();
        assert_eq!(report.files_parsed, 0);
        assert_eq!(report.secret_files_scanned, 1);
        assert_eq!(report.secret_findings.len(), 1);
        assert_eq!(report.secret_findings[0].rule_id, "SECRET-GITHUB-TOKEN");
    }

    /// Language filters gate PARSING only: with `--language rust`, the
    /// Python file is unparsed (no AST findings) yet `.env` still scans.
    #[test]
    fn language_filter_does_not_exclude_secret_files() {
        let directory = tempfile::tempdir().unwrap();
        let key = format!("AKIA{}", "Z".repeat(16));
        std::fs::write(directory.path().join("app.py"), "eval(x)\n").unwrap();
        std::fs::write(directory.path().join(".env"), format!("K={key}\n")).unwrap();
        let scope = Scope::new(vec![], vec![], vec![LanguageId::Rust]).unwrap();
        let report = crate::source::scan(directory.path(), 1_000_000, 600, 42, scope).unwrap();
        assert_eq!(report.files_parsed, 0);
        assert!(report.security_findings.is_empty());
        assert_eq!(report.secret_files_scanned, 1);
        assert_eq!(report.secret_findings.len(), 1);
    }

    /// Suppression flow: the live entry marks the finding (reason + owner),
    /// the gate goes quiet, SARIF shows kind `external`, and the expired
    /// non-matching entry stays out of the expired list (correctly — expiry
    /// is reported for entries that WOULD match).
    #[test]
    fn suppressions_mark_findings_and_report_expired() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("app.py"), "eval(x)\n").unwrap();
        let suppressions = directory.path().join("suppress.json");
        std::fs::write(
            &suppressions,
            r#"{"suppressions": [
                {"rule_id": "CORE-PY-EVAL", "path": "**/app.py", "reason": "reviewed", "owner": "team", "expires": "2999-01-01"},
                {"rule_id": "CORE-PY-EVAL", "path": "**/other.py", "reason": "stale", "owner": "team", "expires": "2000-01-01"}
            ]}"#,
        )
        .unwrap();
        let scope = Scope::new(vec![], vec![], vec![]).unwrap();
        let mut report = crate::source::scan(directory.path(), 1_000_000, 600, 42, scope).unwrap();
        crate::suppress::apply_suppressions(&mut report, &suppressions).unwrap();
        assert_eq!(report.security_findings.len(), 1);
        let suppressed = report.security_findings[0].suppressed.as_ref().unwrap();
        assert_eq!(suppressed.reason, "reviewed");
        assert_eq!(suppressed.owner, "team");
        assert_eq!(report.suppressions.applied, 1);
        assert!(report.suppressions.expired.is_empty());
        assert!(!crate::diff::has_unsuppressed_new(&report, None));
        let sarif = crate::sarif::source_to_sarif(&report);
        assert_eq!(
            sarif["runs"][0]["results"][0]["suppressions"][0]["kind"],
            "external"
        );
    }

    /// Expired entries never suppress: the finding stays unmarked, applied
    /// is 0, the gate stays loud, and the stale entry is named for cleanup.
    #[test]
    fn expired_suppressions_do_not_apply() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("app.py"), "eval(x)\n").unwrap();
        let suppressions = directory.path().join("suppress.json");
        std::fs::write(
            &suppressions,
            r#"{"suppressions": [
                {"rule_id": "CORE-PY-EVAL", "path": "**", "reason": "stale", "owner": "team", "expires": "2000-01-01"}
            ]}"#,
        )
        .unwrap();
        let scope = Scope::new(vec![], vec![], vec![]).unwrap();
        let mut report = crate::source::scan(directory.path(), 1_000_000, 600, 42, scope).unwrap();
        crate::suppress::apply_suppressions(&mut report, &suppressions).unwrap();
        assert!(report.security_findings[0].suppressed.is_none());
        assert_eq!(report.suppressions.applied, 0);
        assert_eq!(report.suppressions.expired, vec!["CORE-PY-EVAL **"]);
        assert!(crate::diff::has_unsuppressed_new(&report, None));
    }

    /// Baseline lifecycle: renaming `a.py`→`b.py` yields one new + one
    /// fixed finding (fingerprints include paths) with a loud gate; renaming
    /// back yields zero new and a quiet gate.
    #[test]
    fn baseline_computes_new_and_fixed_findings() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("a.py"), "eval(x)\n").unwrap();
        let scope = Scope::new(vec![], vec![], vec![]).unwrap();
        let baseline_report =
            crate::source::scan(directory.path(), 1_000_000, 600, 42, scope).unwrap();
        let baseline_path = directory.path().join("baseline.json");
        std::fs::write(
            &baseline_path,
            serde_json::to_vec(&baseline_report).unwrap(),
        )
        .unwrap();
        std::fs::remove_file(directory.path().join("a.py")).unwrap();
        std::fs::write(directory.path().join("b.py"), "eval(x)\n").unwrap();
        let scope = Scope::new(vec![], vec![], vec![]).unwrap();
        let mut report = crate::source::scan(directory.path(), 1_000_000, 600, 42, scope).unwrap();
        // Baseline file itself is a secret-scanned JSON file; it must not affect counts.
        let sets = crate::diff::apply_baseline(&mut report, &baseline_path).unwrap();
        let summary = report.baseline.as_ref().unwrap();
        assert_eq!(summary.new_security, 1);
        assert_eq!(summary.fixed_security, 1);
        assert_eq!(summary.new_secrets, 0);
        assert!(crate::diff::has_unsuppressed_new(&report, Some(&sets)));
        std::fs::remove_file(directory.path().join("b.py")).unwrap();
        std::fs::write(directory.path().join("a.py"), "eval(x)\n").unwrap();
        let scope = Scope::new(vec![], vec![], vec![]).unwrap();
        let mut report = crate::source::scan(directory.path(), 1_000_000, 600, 42, scope).unwrap();
        let sets = crate::diff::apply_baseline(&mut report, &baseline_path).unwrap();
        let summary = report.baseline.as_ref().unwrap();
        assert_eq!(summary.new_security, 0);
        assert!(!crate::diff::has_unsuppressed_new(&report, Some(&sets)));
    }

    /// Diff between two real scans: adding `b.py` reports one added, zero
    /// fixed, one unchanged, with the added finding's rule ID intact.
    #[test]
    fn diff_reports_added_fixed_and_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("a.py"), "eval(x)\n").unwrap();
        let scope = Scope::new(vec![], vec![], vec![]).unwrap();
        let old_report = crate::source::scan(directory.path(), 1_000_000, 600, 42, scope).unwrap();
        let old_path = directory.path().join("old.json");
        std::fs::write(&old_path, serde_json::to_vec(&old_report).unwrap()).unwrap();
        std::fs::write(directory.path().join("b.py"), "eval(x)\n").unwrap();
        let scope = Scope::new(vec![], vec![], vec![]).unwrap();
        let new_report = crate::source::scan(directory.path(), 1_000_000, 600, 42, scope).unwrap();
        let new_path = directory.path().join("new.json");
        std::fs::write(&new_path, serde_json::to_vec(&new_report).unwrap()).unwrap();
        let diff = crate::diff::compare(&old_path, &new_path).unwrap();
        assert_eq!(diff.schema_version, 1);
        assert_eq!(diff.added_security.len(), 1);
        assert!(diff.fixed_security.is_empty());
        assert_eq!(diff.unchanged_security, 1);
        assert_eq!(diff.added_security[0]["rule_id"], "CORE-PY-EVAL");
    }

    /// Full web probe against a real loopback TCP server (no mocks): the
    /// server asserts the `Origin` test header arrives, responds with the
    /// hostile header set, and the probe reports exactly the six expected
    /// rule IDs with CORS-credentials alone at `confirmed`.
    #[test]
    fn real_loopback_http_probe() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() <= 4096);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request
                    .lines()
                    .any(|line| { line.eq_ignore_ascii_case("origin: https://loop3r.invalid") })
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nAccess-Control-Allow-Origin: https://loop3r.invalid\r\nAccess-Control-Allow-Credentials: true\r\nSet-Cookie: session=example\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let report = crate::web::web_scan(&format!("http://{address}/"), 2).unwrap();
        server.join().unwrap();
        let serialized = serde_json::to_value(&report).unwrap();
        assert_eq!(serialized["confidence_scale"].as_object().unwrap().len(), 4);
        for finding in serialized["findings"].as_array().unwrap() {
            let expected = if finding["rule_id"] == "WEB-CORS-CREDENTIALS" {
                "confirmed"
            } else {
                "high"
            };
            assert_eq!(finding["confidence"], expected);
        }
        let ids: std::collections::BTreeSet<_> =
            report.findings.iter().map(|item| item.rule_id).collect();
        assert_eq!(
            ids,
            [
                "WEB-CACHE",
                "WEB-CORS-CREDENTIALS",
                "WEB-COOKIE-HTTPONLY",
                "WEB-COOKIE-SAMESITE",
                "WEB-CSP",
                "WEB-XCTO"
            ]
            .into()
        );
    }

    /// Cookie anti-spoofing end to end: `trick=httponly-samesite-secure`
    /// still fires HttpOnly + SameSite (value text is not attributes) while
    /// the properly-flagged cookie stays silent.
    #[test]
    fn cookie_values_cannot_suppress_flag_findings() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() <= 4096);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nSet-Cookie: trick=httponly-samesite-secure; Path=/\r\nSet-Cookie: good=x; HttpOnly; SameSite=Strict\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let report = crate::web::web_scan(&format!("http://{address}/"), 2).unwrap();
        server.join().unwrap();
        let ids: Vec<_> = report.findings.iter().map(|item| item.rule_id).collect();
        assert_eq!(ids, ["WEB-COOKIE-HTTPONLY", "WEB-COOKIE-SAMESITE"]);
        for finding in &report.findings {
            assert!(finding.evidence.contains("trick"));
        }
    }

    /// Robustness fuzz-lite: empty, hostile (NUL bytes, deep nesting,
    /// non-UTF8), and maximal-Unicode inputs across every grammar must parse
    /// and inspect without panicking, and emit no secret findings.
    #[test]
    fn malformed_and_binary_inputs_never_panic() {
        use crate::language::LanguageId;
        let languages = [
            LanguageId::C,
            LanguageId::CSharp,
            LanguageId::Css,
            LanguageId::Go,
            LanguageId::Html,
            LanguageId::Java,
            LanguageId::JavaScript,
            LanguageId::Kotlin,
            LanguageId::Php,
            LanguageId::Python,
            LanguageId::Ruby,
            LanguageId::Rust,
            LanguageId::Shell,
            LanguageId::Sql,
            LanguageId::Swift,
            LanguageId::TypeScript,
            LanguageId::Tsx,
        ];
        let inputs: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"\n".to_vec(),
            b"(((((((((".to_vec(),
            b"\x00\xff\xfe\xfd".to_vec(),
            "eval(".repeat(500).into_bytes(),
            "héllo wörld eval(x) ——— \u{10ffff}".as_bytes().to_vec(),
        ];
        let rules = crate::core::load_ast_rules().unwrap();
        for language in languages {
            for input in &inputs {
                let mut parser = Parser::new();
                parser.set_language(&language.grammar()).unwrap();
                if let Some(tree) = parser.parse(input, None) {
                    let mut syntax = Vec::new();
                    let mut security = Vec::new();
                    crate::source::inspect_for_tests(
                        tree.root_node(),
                        input,
                        Path::new("malformed"),
                        language,
                        &rules,
                        &mut syntax,
                        &mut security,
                    );
                    assert!(crate::secrets::scan_secrets(Path::new("malformed"), input).is_empty());
                }
            }
        }
    }

    /// Shuffle contract: same seed → identical order; output is a true
    /// permutation (sorted == input), so budget-limited scans replay exactly.
    #[test]
    fn shuffle_is_deterministic_per_seed() {
        let input: Vec<u32> = (0..50).collect();
        let mut first = input.clone();
        let mut second = input.clone();
        crate::source::shuffle(&mut first, 42);
        crate::source::shuffle(&mut second, 42);
        assert_eq!(first, second);
        let mut sorted = first.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, input);
    }

    /// Redirect discipline: a 301's `Location` is recorded verbatim while
    /// the probe issues no second request (the one-shot test server would
    /// hang a follower — `join` proves exactly one request happened).
    #[test]
    fn web_probe_reports_redirect_location_without_following() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() <= 4096);
            }
            stream
                .write_all(b"HTTP/1.1 301 Moved Permanently\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let report = crate::web::web_scan(&format!("http://{address}/"), 2).unwrap();
        server.join().unwrap();
        assert_eq!(report.status, 301);
        assert_eq!(report.redirect.as_deref(), Some("/elsewhere"));
    }

    /// Loopback enforcement: a public URL is refused before any socket
    /// opens — this test makes zero network requests by construction.
    #[test]
    fn web_probe_rejects_remote_target() {
        let error = crate::web::web_scan("https://example.com", 2).unwrap_err();
        assert!(error.to_string().contains("loopback"));
    }
}
