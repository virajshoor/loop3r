//! SARIF 2.1.0 output: maps loop3r reports onto the static-analysis
//! interchange format consumed by GitHub code scanning, VS Code, and CI.
//!
//! The mapping is lossless for finding identity (rule IDs, locations,
//! severities) and preserves loop3r-specific data (CWE, confidence, callee,
//! taint) under result `properties`, where SARIF allows tool-defined keys.
//! Two deliberate omissions: no `codeFlows` (taint-lite traces a single
//! same-function hop — emitting multi-hop flows would fabricate precision
//! the engine does not have), and rules are built only for rules that
//! actually fired (keeps output small and avoids advertising unfired rules
//! as "checked").
//!
//! Severity maps to SARIF levels (`high`→`error`, `medium`→`warning`, else
//! `note`); suppressed findings become `suppressions` with kind `external`
//! so hosts display them as acknowledged rather than hiding them.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::report::{Report, WebReport};

/// Schemastore SARIF schema URI stamped on every document.
const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
/// SARIF format version emitted.
const VERSION: &str = "2.1.0";
/// Tool driver name shown by SARIF hosts.
const TOOL: &str = "loop3r";
/// Tool information URI for the driver metadata.
const INFORMATION_URI: &str = "https://github.com/virajshoor/loop3r";
/// Synthetic rule ID for grammar diagnostics, which have no catalog rule.
/// Exported to tests so the suite pins the spelling hosts will key on.
const SYNTAX_RULE_ID: &str = "LOOP3R-SYNTAX";

/// Maps loop3r severity onto SARIF levels.
///
/// `review` (and anything unknown) becomes `note`: SARIF hosts render notes
/// as informational, which matches "needs human review, not established".
/// Unknown severities degrade to `note` rather than erroring so a future
/// severity never breaks SARIF emission.
fn level(severity: &str) -> &'static str {
    match severity {
        "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

/// Builds a SARIF `message`-style `{text}` object. Written with an explicit
/// `Map` (not nested constructor calls) after a paren-balance bug proved the
/// clever version unreadable.
fn text_object(text: &str) -> Value {
    let mut map = Map::new();
    map.insert("text".to_owned(), Value::String(text.to_owned()));
    Value::Object(map)
}

/// Builds one driver rule descriptor, returning (id, descriptor) so callers
/// can insert into the dedup map. `helpUri` is the finding's first reference
/// (or the docs page for synthetic rules); descriptions come from the
/// finding's remediation message so hosts show actionable text.
fn rule_entry(id: &str, name: &str, description: &str, help_uri: Option<&str>) -> (String, Value) {
    let mut rule = Map::from_iter([
        ("id".to_owned(), Value::String(id.to_owned())),
        ("name".to_owned(), Value::String(name.to_owned())),
        ("shortDescription".to_owned(), text_object(description)),
    ]);
    if let Some(uri) = help_uri {
        rule.insert("helpUri".to_owned(), Value::String(uri.to_owned()));
    }
    (id.to_owned(), Value::Object(rule))
}

/// Builds a SARIF location: file/URL plus an optional start line/column.
///
/// Source findings always carry a region; web findings carry the request URL
/// with no region (a URL is not a file, and inventing line numbers would be
/// dishonest). Both line AND column are required for a region — a partial
/// region would mislead hosts about precision.
fn location(uri: &str, line: Option<usize>, column: Option<usize>) -> Value {
    let mut physical = Map::from_iter([(
        "artifactLocation".to_owned(),
        Value::Object(Map::from_iter([(
            "uri".to_owned(),
            Value::String(uri.to_owned()),
        )])),
    )]);
    if let (Some(line), Some(column)) = (line, column) {
        physical.insert(
            "region".to_owned(),
            Value::Object(Map::from_iter([
                ("startLine".to_owned(), Value::from(line)),
                ("startColumn".to_owned(), Value::from(column)),
            ])),
        );
    }
    Value::Object(Map::from_iter([(
        "physicalLocation".to_owned(),
        Value::Object(physical),
    )]))
}

/// Builds one SARIF result: rule reference, level, message, locations,
/// tool properties, and an optional external suppression.
///
/// Suppressions use kind `external` with the reason/owner/expiry folded into
/// the justification string — SARIF hosts understand this as "acknowledged
/// outside the tool" and keep the result visible but marked.
fn result(
    rule_id: &str,
    severity: &str,
    message: &str,
    locations: Vec<Value>,
    properties: Map<String, Value>,
    suppressed: Option<&crate::report::SuppressedBy>,
) -> Value {
    let mut result = Map::from_iter([
        ("ruleId".to_owned(), Value::String(rule_id.to_owned())),
        (
            "level".to_owned(),
            Value::String(level(severity).to_owned()),
        ),
        ("message".to_owned(), text_object(message)),
        ("locations".to_owned(), Value::Array(locations)),
        ("properties".to_owned(), Value::Object(properties)),
    ]);
    if let Some(suppressed) = suppressed {
        result.insert(
            "suppressions".to_owned(),
            Value::Array(vec![Value::Object(Map::from_iter([
                ("kind".to_owned(), Value::String("external".to_owned())),
                (
                    "justification".to_owned(),
                    Value::String(format!(
                        "{} (owner {}, expires {})",
                        suppressed.reason, suppressed.owner, suppressed.expires
                    )),
                ),
            ]))]),
        );
    }
    Value::Object(result)
}

/// Assembles the final SARIF document: schema stamp, version, and a single
/// run whose driver names loop3r with the compile-time crate version.
///
/// The `BTreeMap` of rules is drained in key order, so rule descriptors are
/// deterministic across runs. Tool version comes from `CARGO_PKG_VERSION`,
/// tying every SARIF file to the exact binary that produced it.
fn run(rules: BTreeMap<String, Value>, results: Vec<Value>) -> Value {
    Value::Object(Map::from_iter([
        ("$schema".to_owned(), Value::String(SCHEMA.to_owned())),
        ("version".to_owned(), Value::String(VERSION.to_owned())),
        (
            "runs".to_owned(),
            Value::Array(vec![Value::Object(Map::from_iter([
                (
                    "tool".to_owned(),
                    Value::Object(Map::from_iter([(
                        "driver".to_owned(),
                        Value::Object(Map::from_iter([
                            ("name".to_owned(), Value::String(TOOL.to_owned())),
                            (
                                "version".to_owned(),
                                Value::String(env!("CARGO_PKG_VERSION").to_owned()),
                            ),
                            (
                                "informationUri".to_owned(),
                                Value::String(INFORMATION_URI.to_owned()),
                            ),
                            (
                                "rules".to_owned(),
                                Value::Array(rules.into_values().collect()),
                            ),
                        ])),
                    )])),
                ),
                ("results".to_owned(), Value::Array(results)),
            ]))]),
        ),
    ]))
}

/// Converts a source report to SARIF.
///
/// Three finding families map in order: security findings (with CWE,
/// confidence, severity, callee, evidence, plus `resolvedCallee` and a
/// `taint` object when present), secret findings (same core fields plus the
/// content `fingerprint`; evidence is already redacted upstream), and syntax
/// findings (under the synthetic `LOOP3R-SYNTAX` rule at `note` level, since
/// unparsable regions are coverage gaps, not vulnerabilities). Rule
/// descriptors dedupe via `or_insert_with`: the first finding defines the
/// rule, later ones reuse it.
pub fn source_to_sarif(report: &Report) -> Value {
    let mut rules: BTreeMap<String, Value> = BTreeMap::new();
    let mut results = Vec::new();

    for finding in &report.security_findings {
        rules.entry(finding.rule_id.clone()).or_insert_with(|| {
            rule_entry(
                &finding.rule_id,
                &finding.title,
                &finding.message,
                finding.references.first().map(String::as_str),
            )
            .1
        });
        let mut properties = Map::from_iter([
            ("cwe".to_owned(), Value::String(finding.cwe.clone())),
            (
                "confidence".to_owned(),
                Value::String(finding.confidence.as_str().to_owned()),
            ),
            (
                "severity".to_owned(),
                Value::String(finding.severity.clone()),
            ),
            ("callee".to_owned(), Value::String(finding.callee.clone())),
            (
                "evidence".to_owned(),
                Value::String(finding.evidence.clone()),
            ),
        ]);
        if let Some(resolved) = &finding.resolved_callee {
            properties.insert("resolvedCallee".to_owned(), Value::String(resolved.clone()));
        }
        // Taint travels as a property object, NOT a codeFlow: one hop is a
        // hint, and SARIF codeFlows imply proven multi-hop paths.
        if let Some(taint) = &finding.taint {
            properties.insert(
                "taint".to_owned(),
                Value::Object(Map::from_iter([
                    ("sourceLine".to_owned(), Value::from(taint.source_line)),
                    ("source".to_owned(), Value::String(taint.source.clone())),
                    ("variable".to_owned(), Value::String(taint.variable.clone())),
                ])),
            );
        }
        results.push(result(
            &finding.rule_id,
            &finding.severity,
            &format!("{}: {}", finding.title, finding.message),
            vec![location(
                &finding.path.to_string_lossy(),
                Some(finding.line),
                Some(finding.column),
            )],
            properties,
            finding.suppressed.as_ref(),
        ));
    }

    for finding in &report.secret_findings {
        rules.entry(finding.rule_id.to_owned()).or_insert_with(|| {
            rule_entry(
                finding.rule_id,
                finding.title,
                finding.message,
                Some(finding.reference),
            )
            .1
        });
        results.push(result(
            finding.rule_id,
            finding.severity,
            &format!("{}: {}", finding.title, finding.message),
            vec![location(
                &finding.path.to_string_lossy(),
                Some(finding.line),
                Some(finding.column),
            )],
            Map::from_iter([
                ("cwe".to_owned(), Value::String(finding.cwe.to_owned())),
                (
                    "confidence".to_owned(),
                    Value::String(finding.confidence.as_str().to_owned()),
                ),
                (
                    "severity".to_owned(),
                    Value::String(finding.severity.to_owned()),
                ),
                (
                    "fingerprint".to_owned(),
                    Value::String(finding.fingerprint.clone()),
                ),
                (
                    "evidence".to_owned(),
                    Value::String(finding.evidence.clone()),
                ),
            ]),
            finding.suppressed.as_ref(),
        ));
    }

    for finding in &report.syntax_findings {
        rules.entry(SYNTAX_RULE_ID.to_owned()).or_insert_with(|| {
            rule_entry(
                SYNTAX_RULE_ID,
                "Unparsable syntax",
                "The embedded grammar reported an error or missing node at this location.",
                Some("https://github.com/virajshoor/loop3r/blob/main/docs/reports.md"),
            )
            .1
        });
        results.push(result(
            SYNTAX_RULE_ID,
            "review",
            &format!(
                "unparsable {:?} syntax near node {}",
                finding.language, finding.node_kind
            ),
            vec![location(
                &finding.path.to_string_lossy(),
                Some(finding.line),
                Some(finding.column),
            )],
            Map::from_iter([(
                "language".to_owned(),
                Value::String(format!("{:?}", finding.language)),
            )]),
            None,
        ));
    }

    run(rules, results)
}

/// Converts a web report to SARIF.
///
/// Simpler than source: every finding points at the probed URL with no
/// region, and web findings are never suppressed (no suppression model for
/// probes), so the suppression slot is always `None`. Rule names reuse the
/// rule ID since web rules have no separate title field.
pub fn web_to_sarif(report: &WebReport) -> Value {
    let mut rules: BTreeMap<String, Value> = BTreeMap::new();
    let mut results = Vec::new();
    for finding in &report.findings {
        rules.entry(finding.rule_id.to_owned()).or_insert_with(|| {
            rule_entry(
                finding.rule_id,
                finding.rule_id,
                finding.message,
                Some(finding.reference),
            )
            .1
        });
        results.push(result(
            finding.rule_id,
            finding.severity,
            &format!("{}: {}", finding.rule_id, finding.message),
            vec![location(&report.url, None, None)],
            Map::from_iter([
                (
                    "confidence".to_owned(),
                    Value::String(finding.confidence.as_str().to_owned()),
                ),
                (
                    "severity".to_owned(),
                    Value::String(finding.severity.to_owned()),
                ),
                (
                    "evidence".to_owned(),
                    Value::String(finding.evidence.clone()),
                ),
            ]),
            None,
        ));
    }
    run(rules, results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::language::LanguageId;
    use crate::report::{Confidence, SecurityFinding, SyntaxFinding, confidence_scale};
    use crate::secrets::SecretFinding;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// Minimal security finding with only identity-relevant fields varying;
    /// everything else is a fixed placeholder to keep tests focused.
    fn security_finding(rule_id: &str, severity: &str, evidence: &str) -> SecurityFinding {
        SecurityFinding {
            rule_id: rule_id.to_owned(),
            title: "Title".to_owned(),
            severity: severity.to_owned(),
            cwe: "CWE-78".to_owned(),
            path: PathBuf::from("src/app.py"),
            line: 3,
            column: 1,
            callee: "eval".to_owned(),
            resolved_callee: None,
            evidence: evidence.to_owned(),
            message: "Message".to_owned(),
            references: vec!["https://example.invalid/rule".to_owned()],
            confidence: Confidence::Medium,
            taint: None,
            suppressed: None,
        }
    }

    /// Full source mapping: schema/version stamps, 4 deduped rules from 5
    /// findings (two share `CORE-PY-EVAL`), level mapping (`high`→error,
    /// `review`→note), file URI + region, secret fingerprint passthrough,
    /// and the synthetic syntax rule last.
    #[test]
    fn maps_source_findings_with_levels_and_deduped_rules() {
        let report = Report {
            schema_version: 4,
            files_parsed: 1,
            secret_files_scanned: 0,
            files_skipped_oversized: 0,
            files_skipped_unsupported: 0,
            languages: BTreeMap::from([(LanguageId::Python, 1)]),
            syntax_findings: vec![SyntaxFinding {
                path: PathBuf::from("src/app.py"),
                language: LanguageId::Python,
                line: 9,
                column: 2,
                node_kind: "ERROR".to_owned(),
            }],
            security_findings: vec![
                security_finding("CORE-PY-EVAL", "high", "eval(x)"),
                security_finding("CORE-PY-EVAL", "high", "eval(y)"),
                security_finding("CORE-PY-SHELL", "review", "os.system(x)"),
            ],
            secret_findings: vec![SecretFinding {
                rule_id: "SECRET-AWS-ACCESS-KEY",
                title: "AWS access key ID in source",
                severity: "high",
                cwe: "CWE-798",
                path: PathBuf::from("src/app.py"),
                line: 5,
                column: 7,
                evidence: "AKIA[redacted]ZZZZ".to_owned(),
                fingerprint: "0123456789abcdef".to_owned(),
                message: "Message",
                reference: "https://example.invalid/aws",
                confidence: Confidence::High,
                suppressed: None,
            }],
            timed_out: false,
            seed: 42,
            baseline: None,
            suppressions: crate::report::SuppressionReport::none(),
            scope: crate::scope::ScopeReport {
                target: PathBuf::from("."),
                max_file_bytes: 1_000_000,
                budget_seconds: 600,
                include: vec![],
                exclude: vec![],
                languages: vec![],
            },
            confidence_scale: confidence_scale(),
        };
        let sarif = source_to_sarif(&report);
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["$schema"], SCHEMA);
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 4);
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 5);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[2]["level"], "note");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/app.py"
        );
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            3
        );
        assert_eq!(results[3]["properties"]["fingerprint"], "0123456789abcdef");
        assert_eq!(results[4]["ruleId"], SYNTAX_RULE_ID);
    }

    /// Hostile evidence (HTML/JS metacharacters) is JSON-escaped in the
    /// rendered document (never interpolated raw) yet round-trips exactly —
    /// SARIF consumers must see the finding text, not execute it.
    #[test]
    fn sarif_evidence_round_trips_through_json_escaping() {
        let tricky = "<script>alert('x') & \"y\"</script>";
        let report = Report {
            schema_version: 4,
            files_parsed: 1,
            secret_files_scanned: 0,
            files_skipped_oversized: 0,
            files_skipped_unsupported: 0,
            languages: BTreeMap::new(),
            syntax_findings: vec![],
            security_findings: vec![security_finding("CORE-PY-EVAL", "high", tricky)],
            secret_findings: vec![],
            timed_out: false,
            seed: 1,
            baseline: None,
            suppressions: crate::report::SuppressionReport::none(),
            scope: crate::scope::ScopeReport {
                target: PathBuf::from("."),
                max_file_bytes: 1,
                budget_seconds: 1,
                include: vec![],
                exclude: vec![],
                languages: vec![],
            },
            confidence_scale: confidence_scale(),
        };
        let rendered = serde_json::to_string(&source_to_sarif(&report)).unwrap();
        assert!(!rendered.contains(tricky));
        let parsed: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(
            parsed["runs"][0]["results"][0]["properties"]["evidence"],
            tricky
        );
    }

    /// Web mapping: one result at `warning` for `medium` severity, URL
    /// location with NO region (probes are not files).
    #[test]
    fn maps_web_findings_to_url_locations() {
        let report = WebReport {
            schema_version: 1,
            url: "http://127.0.0.1:3000/".to_owned(),
            status: 200,
            duration_ms: 3,
            redirect: None,
            findings: vec![crate::report::WebFinding {
                rule_id: "WEB-XCTO",
                severity: "medium",
                message: "Set header.",
                evidence: "header absent".to_owned(),
                reference: "https://example.invalid/xcto",
                confidence: Confidence::High,
            }],
            confidence_scale: confidence_scale(),
        };
        let sarif = web_to_sarif(&report);
        assert_eq!(sarif["version"], "2.1.0");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["level"], "warning");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "http://127.0.0.1:3000/"
        );
        assert!(
            results[0]["locations"][0]["physicalLocation"]
                .get("region")
                .is_none()
        );
    }

    /// Empty reports produce valid SARIF with empty rules and results —
    /// hosts must accept a clean scan, not choke on missing arrays.
    #[test]
    fn empty_reports_yield_empty_results() {
        let report = Report {
            schema_version: 4,
            files_parsed: 0,
            secret_files_scanned: 0,
            files_skipped_oversized: 0,
            files_skipped_unsupported: 0,
            languages: BTreeMap::new(),
            syntax_findings: vec![],
            security_findings: vec![],
            secret_findings: vec![],
            timed_out: false,
            seed: 1,
            baseline: None,
            suppressions: crate::report::SuppressionReport::none(),
            scope: crate::scope::ScopeReport {
                target: PathBuf::from("."),
                max_file_bytes: 1,
                budget_seconds: 1,
                include: vec![],
                exclude: vec![],
                languages: vec![],
            },
            confidence_scale: confidence_scale(),
        };
        let sarif = source_to_sarif(&report);
        assert!(sarif["runs"][0]["results"].as_array().unwrap().is_empty());
        assert!(
            sarif["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}
