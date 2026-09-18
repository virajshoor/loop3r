mod core;
mod language;
mod report;
mod scope;
mod source;
mod web;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser as ClapParser, Subcommand};

use crate::language::LanguageId;
use crate::report::write_private;
use crate::scope::Scope;

#[derive(ClapParser)]
#[command(
    name = "loop3r",
    version,
    about = "Self-contained source security auditor"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse source with embedded grammars and report syntax coverage.
    Scan {
        target: PathBuf,
        #[arg(long, default_value_t = 1_000_000)]
        max_file_bytes: u64,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, default_value_t = 600)]
        budget_seconds: u64,
        #[arg(long)]
        seed: Option<u64>,
        #[arg(long)]
        include: Vec<String>,
        #[arg(long)]
        exclude: Vec<String>,
        #[arg(long, value_enum)]
        language: Vec<LanguageId>,
    },
    /// Run read-only HTTP checks against an authorized loopback website.
    Web {
        url: String,
        #[arg(long)]
        authorized: bool,
        #[arg(long, default_value_t = 10)]
        timeout_seconds: u64,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

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
        } => {
            if budget_seconds == 0 || max_file_bytes == 0 {
                bail!("budget-seconds and max-file-bytes must be positive");
            }
            let seed = seed.unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64
            });
            let scope = Scope::new(include, exclude, language)?;
            let report = source::scan(&target, max_file_bytes, budget_seconds, seed, scope)?;
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
                    "{} files parsed; {} syntax findings; {} security findings",
                    report.files_parsed,
                    report.syntax_findings.len(),
                    report.security_findings.len()
                );
            }
            Ok(u8::from(!report.security_findings.is_empty()))
        }
        Command::Web {
            url,
            authorized,
            timeout_seconds,
            json,
            output,
        } => {
            if !authorized {
                bail!("--authorized required for web checks");
            }
            let report = web::web_scan(&url, timeout_seconds)?;
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
                println!("HTTP {}; {} findings", report.status, report.findings.len());
            }
            Ok(u8::from(!report.findings.is_empty()))
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("loop3r: {error:#}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::AstRule;
    use crate::language::LanguageId;
    use crate::scope::Scope;
    use std::path::Path;
    use tree_sitter::Parser;

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

    #[test]
    fn every_ast_rule_has_a_real_parse_tree_fixture() {
        let fixtures = [
            (
                LanguageId::C,
                "void f(char*d,char*s){strcpy(d,s);system(s);}",
            ),
            (
                LanguageId::Python,
                "eval(x)\nos.system(x)\npickle.loads(x)\n",
            ),
            (LanguageId::JavaScript, "eval(x);\nchild_process.exec(x);\n"),
            (LanguageId::Php, "<?php system($x); unserialize($x); ?>"),
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

    #[test]
    fn core_rule_catalog_is_well_formed() {
        let rules = crate::core::load_ast_rules().unwrap();
        assert_eq!(rules.len(), 18);
    }

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
                "WEB-CORS-CREDENTIALS",
                "WEB-COOKIE-HTTPONLY",
                "WEB-COOKIE-SAMESITE",
                "WEB-CSP",
                "WEB-XCTO"
            ]
            .into()
        );
    }

    #[test]
    fn web_probe_rejects_remote_target() {
        let error = crate::web::web_scan("https://example.com", 2).unwrap_err();
        assert!(error.to_string().contains("loopback"));
    }
}
