//! JSON Schema conformance checking for loop3r reports.
//!
//! The schemas in `schema/` (draft 2020-12) pin every report's shape, and
//! this module implements just enough of the spec to validate against them:
//! `const`, `enum`, `type` (single or union), `properties` + `required` +
//! `additionalProperties`, `items`, and `anyOf`. A hand-rolled checker (not a
//! validation crate) keeps the dependency tree small and error messages
//! loop3r-specific (`$.security_findings[0]: missing required key taint`).
//! Anything unsupported in a schema is ignored rather than rejected, so the
//! checker stays forward-compatible with schema additions it doesn't model
//! (minimums, patterns, formats are documentation, not gates).

use anyhow::Context;
use serde_json::Value;

/// JSON Schema type predicate over a value. Unknown type names return true
/// (ignore, don't fail) per the forward-compatibility rule above.
fn matches_type(value: &Value, kind: &str) -> bool {
    match kind {
        "string" => value.is_string(),
        // `as_i64` restricts integers to the i64 range; report counts and
        // versions always fit, and floats like 1.5 correctly fail.
        "integer" => value.as_i64().is_some(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        _ => true,
    }
}

/// Recursively checks a value against a schema node, accumulating errors.
///
/// `path` is a jq-style breadcrumb (`$.security_findings[0].taint`) so users
/// can locate failures in large reports. Non-object schemas are vacuous
/// (boolean schemas are not used by loop3r schemas). Check order: `const`,
/// `enum`, `type` (a type miss returns early — deeper checks would cascade
/// noise), then object properties (required keys + per-key recursion +
/// undocumented-key rejection unless `additionalProperties: true`), array
/// items, and finally `anyOf` (passes when ANY branch is error-free).
fn check_value(value: &Value, schema: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(object) = schema.as_object() else {
        return;
    };
    if let Some(expected) = object.get("const")
        && value != expected
    {
        errors.push(format!("{path}: expected const {expected}, got {value}"));
    }
    if let Some(allowed) = object.get("enum").and_then(Value::as_array)
        && !allowed.iter().any(|option| option == value)
    {
        errors.push(format!("{path}: {value} is not an allowed enum value"));
    }
    if let Some(kind) = object.get("type") {
        let kinds: Vec<&str> = match kind {
            Value::String(one) => vec![one.as_str()],
            Value::Array(many) => many.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if !kinds.iter().any(|kind| matches_type(value, kind)) {
            errors.push(format!("{path}: {value} does not match type {kind}"));
            return;
        }
    }
    if let Some(properties) = object.get("properties").and_then(Value::as_object)
        && let Some(map) = value.as_object()
    {
        if let Some(required) = object.get("required").and_then(Value::as_array) {
            for key in required.iter().filter_map(Value::as_str) {
                if !map.contains_key(key) {
                    errors.push(format!("{path}: missing required key {key}"));
                }
            }
        }
        for (key, item) in map {
            match properties.get(key) {
                Some(subschema) => {
                    check_value(item, subschema, &format!("{path}.{key}"), errors);
                }
                None => {
                    let allow_extra =
                        object.get("additionalProperties").and_then(Value::as_bool) == Some(true);
                    if !allow_extra {
                        errors.push(format!("{path}: undocumented key {key}"));
                    }
                }
            }
        }
    }
    if let Some(items) = object.get("items")
        && let Some(list) = value.as_array()
    {
        for (index, item) in list.iter().enumerate() {
            check_value(item, items, &format!("{path}[{index}]"), errors);
        }
    }
    if let Some(branches) = object.get("anyOf").and_then(Value::as_array) {
        let mut matched = false;
        for branch in branches {
            // Branch errors are discarded: `anyOf` reports only the overall
            // failure, since per-branch noise (e.g. "expected null, got
            // object" for the null branch) would confuse more than help.
            let mut branch_errors = Vec::new();
            check_value(value, branch, path, &mut branch_errors);
            if branch_errors.is_empty() {
                matched = true;
                break;
            }
        }
        if !matched {
            errors.push(format!("{path}: matches no anyOf branch: {value}"));
        }
    }
}

/// Returns all conformance errors for a report, or empty when it conforms.
/// Collecting (not failing fast) shows users every problem in one run.
pub fn conformance_errors(report: &Value, schema: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    check_value(report, schema, "$", &mut errors);
    errors
}

/// Loads an embedded schema by short name (`scan`, `deps`, `web`, `diff`).
///
/// Schemas ship in the binary via `include_str!`, so `validate` works
/// offline and can never disagree with the emitting code. `scan` always
/// means the LATEST scan schema (v4); older `scan-v3.schema.json` stays on
/// disk for reading historical reports but is not addressable here.
pub fn load_schema(name: &str) -> anyhow::Result<Value> {
    let text = match name {
        "scan" => include_str!("../schema/scan-v4.schema.json"),
        "deps" => include_str!("../schema/deps-v2.schema.json"),
        "web" => include_str!("../schema/web-v1.schema.json"),
        "diff" => include_str!("../schema/diff-v1.schema.json"),
        other => anyhow::bail!("unknown schema {other}: expected scan, deps, web, or diff"),
    };
    serde_json::from_str(text).context("parsing embedded schema")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-local schema loader mirroring [`load_schema`] (tests cannot call
    /// it for the version-pinning assertion without circularity of intent —
    /// pinning the files directly is the stronger check).
    fn schema(name: &str) -> Value {
        let text = match name {
            "scan" => include_str!("../schema/scan-v4.schema.json"),
            "deps" => include_str!("../schema/deps-v2.schema.json"),
            "web" => include_str!("../schema/web-v1.schema.json"),
            "diff" => include_str!("../schema/diff-v1.schema.json"),
            _ => unreachable!(),
        };
        serde_json::from_str(text).unwrap()
    }

    /// Every schema declares draft 2020-12 and pins its expected
    /// `schema_version` const — bumping a schema without updating the
    /// emitter (or vice versa) fails here.
    #[test]
    fn schemas_pin_expected_versions() {
        for (name, version) in [("scan", 4), ("deps", 2), ("web", 1), ("diff", 1)] {
            let schema = schema(name);
            assert_eq!(
                schema["$schema"],
                "https://json-schema.org/draft/2020-12/schema"
            );
            assert_eq!(schema["properties"]["schema_version"]["const"], version);
        }
    }

    /// The checker reports missing required keys, undocumented keys, and
    /// const mismatches with actionable paths.
    #[test]
    fn checker_reports_missing_required_and_unknown_keys() {
        let schema = schema("deps");
        let missing: Value = serde_json::from_str(r#"{"schema_version": 2}"#).unwrap();
        let errors = conformance_errors(&missing, &schema);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing required key"))
        );
        let extra: Value = serde_json::from_str(
            r#"{"schema_version": 2, "target": ".", "lockfiles": [], "packages": [],
                "unsupported": [], "errors": [], "advisory_db": null, "vulnerabilities": [],
                "surprise": 1}"#,
        )
        .unwrap();
        let errors = conformance_errors(&extra, &schema);
        assert_eq!(errors, vec!["$: undocumented key surprise"]);
        let wrong_version: Value = serde_json::from_str(
            r#"{"schema_version": 99, "target": ".", "lockfiles": [], "packages": [],
                "unsupported": [], "errors": [], "advisory_db": null, "vulnerabilities": []}"#,
        )
        .unwrap();
        let errors = conformance_errors(&wrong_version, &schema);
        assert!(errors.iter().any(|error| error.contains("expected const")));
    }

    /// End-to-end: a real scan (with syntax error, secret, suppression, and
    /// baseline all exercised) conforms to the embedded scan schema. This is
    /// the anti-drift test — any new report field must be added to the
    /// schema or this fails on "undocumented key".
    #[test]
    fn scan_report_conforms_to_schema() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("app.py"), "eval(x)\n").unwrap();
        std::fs::write(directory.path().join("broken.py"), "def broken(:\n").unwrap();
        let key = format!("AKIA{}", "Z".repeat(16));
        std::fs::write(directory.path().join(".env"), format!("K={key}\n")).unwrap();
        let scope = crate::scope::Scope::new(vec![], vec![], vec![]).unwrap();
        let baseline_report =
            crate::source::scan(directory.path(), 1_000_000, 600, 42, scope).unwrap();
        let baseline_path = directory.path().join("baseline.json");
        std::fs::write(
            &baseline_path,
            serde_json::to_vec(&baseline_report).unwrap(),
        )
        .unwrap();
        std::fs::write(directory.path().join("extra.py"), "eval(y)\n").unwrap();
        let suppressions = directory.path().join("suppress.json");
        std::fs::write(
            &suppressions,
            r#"{"suppressions": [{"rule_id": "CORE-PY-EVAL", "path": "**/app.py", "reason": "r", "owner": "o", "expires": "2999-01-01"}]}"#,
        )
        .unwrap();
        let scope = crate::scope::Scope::new(vec![], vec![], vec![]).unwrap();
        let mut report = crate::source::scan(directory.path(), 1_000_000, 600, 42, scope).unwrap();
        crate::suppress::apply_suppressions(&mut report, &suppressions).unwrap();
        crate::diff::apply_baseline(&mut report, &baseline_path).unwrap();
        assert!(!report.security_findings.is_empty());
        assert!(!report.secret_findings.is_empty());
        assert!(!report.syntax_findings.is_empty());
        assert!(report.baseline.is_some());
        assert_eq!(report.suppressions.applied, 1);
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(
            conformance_errors(&value, &schema("scan")),
            Vec::<String>::new()
        );
    }

    /// End-to-end: a real inventory (valid + malformed lockfiles, unsupported
    /// file, advisory match) conforms to the embedded deps schema.
    #[test]
    fn deps_report_conforms_to_schema() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("Cargo.lock"),
            "[[package]]\nname = \"left-pad\"\nversion = \"1.3.0\"\n",
        )
        .unwrap();
        std::fs::create_dir(directory.path().join("nested")).unwrap();
        std::fs::write(directory.path().join("nested/Cargo.lock"), "garbage\n").unwrap();
        std::fs::write(directory.path().join("yarn.lock"), "# yarn\n").unwrap();
        let db = directory.path().join("snapshot.json");
        std::fs::write(
            &db,
            r#"{"format_version": 1, "advisories": [{"id": "TEST-1", "ecosystem": "cargo", "package": "left-pad", "vulnerable_versions": ["1.3.0"], "severity": "high", "summary": "s", "reference": "https://example.invalid/t"}]}"#,
        )
        .unwrap();
        let mut report = crate::deps::inventory(directory.path()).unwrap();
        crate::advisory::apply_advisory_db(&mut report, &db).unwrap();
        assert!(!report.packages.is_empty());
        assert!(!report.unsupported.is_empty());
        assert!(!report.errors.is_empty());
        assert!(!report.vulnerabilities.is_empty());
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(
            conformance_errors(&value, &schema("deps")),
            Vec::<String>::new()
        );
    }

    /// End-to-end: a real loopback probe (3xx redirect) and a real diff both
    /// conform. The HTTP server is a raw `TcpListener` speaking just enough
    /// HTTP for one response — no mocks, no external services, bounded reads.
    #[test]
    fn web_and_diff_reports_conform_to_schema() {
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
                .write_all(b"HTTP/1.1 301 Moved\r\nLocation: /x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let web = crate::web::web_scan(&format!("http://{address}/"), 2).unwrap();
        server.join().unwrap();
        assert!(web.redirect.is_some());
        let value = serde_json::to_value(&web).unwrap();
        assert_eq!(
            conformance_errors(&value, &schema("web")),
            Vec::<String>::new()
        );

        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("a.py"), "eval(x)\n").unwrap();
        let scope = crate::scope::Scope::new(vec![], vec![], vec![]).unwrap();
        let old = crate::source::scan(directory.path(), 1_000_000, 600, 42, scope).unwrap();
        let old_path = directory.path().join("old.json");
        std::fs::write(&old_path, serde_json::to_vec(&old).unwrap()).unwrap();
        std::fs::write(directory.path().join("b.py"), "eval(y)\n").unwrap();
        let scope = crate::scope::Scope::new(vec![], vec![], vec![]).unwrap();
        let new = crate::source::scan(directory.path(), 1_000_000, 600, 42, scope).unwrap();
        let new_path = directory.path().join("new.json");
        std::fs::write(&new_path, serde_json::to_vec(&new).unwrap()).unwrap();
        let diff = crate::diff::compare(&old_path, &new_path).unwrap();
        let value = serde_json::to_value(&diff).unwrap();
        assert_eq!(
            conformance_errors(&value, &schema("diff")),
            Vec::<String>::new()
        );
    }
}
