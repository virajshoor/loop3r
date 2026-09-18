use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use crate::deps::DepsReport;

fn timestamp_utc() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let day_seconds = seconds % 86_400;
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        crate::suppress::today_iso(),
        day_seconds / 3600,
        (day_seconds % 3600) / 60,
        day_seconds % 60
    )
}

fn purl(ecosystem: &str, name: &str, version: &str) -> String {
    let encoded = if ecosystem == "npm" {
        name.replacen('@', "%40", 1)
    } else {
        name.to_owned()
    };
    format!("pkg:{ecosystem}/{encoded}@{version}")
}

pub fn deps_to_cyclonedx(report: &DepsReport) -> Value {
    let components: Vec<Value> = report
        .packages
        .iter()
        .map(|package| {
            let reference = purl(package.ecosystem, &package.name, &package.version);
            Value::Object(Map::from_iter([
                ("type".to_owned(), Value::String("library".to_owned())),
                ("name".to_owned(), Value::String(package.name.clone())),
                ("version".to_owned(), Value::String(package.version.clone())),
                ("bom-ref".to_owned(), Value::String(reference.clone())),
                ("purl".to_owned(), Value::String(reference)),
            ]))
        })
        .collect();
    Value::Object(Map::from_iter([
        (
            "bomFormat".to_owned(),
            Value::String("CycloneDX".to_owned()),
        ),
        ("specVersion".to_owned(), Value::String("1.6".to_owned())),
        ("version".to_owned(), Value::from(1)),
        (
            "metadata".to_owned(),
            Value::Object(Map::from_iter([
                ("timestamp".to_owned(), Value::String(timestamp_utc())),
                (
                    "tools".to_owned(),
                    Value::Object(Map::from_iter([(
                        "components".to_owned(),
                        Value::Array(vec![Value::Object(Map::from_iter([
                            ("type".to_owned(), Value::String("application".to_owned())),
                            ("name".to_owned(), Value::String("loop3r".to_owned())),
                            (
                                "version".to_owned(),
                                Value::String(env!("CARGO_PKG_VERSION").to_owned()),
                            ),
                        ]))]),
                    )])),
                ),
            ])),
        ),
        ("components".to_owned(), Value::Array(components)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::Package;
    use std::path::PathBuf;

    fn report(packages: Vec<Package>) -> DepsReport {
        DepsReport {
            schema_version: 1,
            target: PathBuf::from("."),
            lockfiles: vec![],
            packages,
            unsupported: vec![],
            errors: vec![],
            advisory_db: None,
            vulnerabilities: vec![],
        }
    }

    #[test]
    fn emits_minimal_cyclonedx_with_purls() {
        let sbom = deps_to_cyclonedx(&report(vec![
            Package {
                ecosystem: "cargo",
                name: "anyhow".to_owned(),
                version: "1.0.99".to_owned(),
                source: None,
                lockfile: PathBuf::from("Cargo.lock"),
            },
            Package {
                ecosystem: "npm",
                name: "@scope/name".to_owned(),
                version: "2.0.1".to_owned(),
                source: None,
                lockfile: PathBuf::from("package-lock.json"),
            },
        ]));
        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["specVersion"], "1.6");
        assert_eq!(sbom["metadata"]["tools"]["components"][0]["name"], "loop3r");
        let timestamp = sbom["metadata"]["timestamp"].as_str().unwrap();
        assert!(
            timestamp.ends_with('Z') && timestamp.len() == 20,
            "{timestamp}"
        );
        let components = sbom["components"].as_array().unwrap();
        assert_eq!(components.len(), 2);
        assert_eq!(components[0]["purl"], "pkg:cargo/anyhow@1.0.99");
        assert_eq!(components[0]["bom-ref"], "pkg:cargo/anyhow@1.0.99");
        assert_eq!(components[1]["purl"], "pkg:npm/%40scope/name@2.0.1");
    }

    #[test]
    fn empty_inventory_yields_empty_components() {
        let sbom = deps_to_cyclonedx(&report(vec![]));
        assert!(sbom["components"].as_array().unwrap().is_empty());
    }
}
