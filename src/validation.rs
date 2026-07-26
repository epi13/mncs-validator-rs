//! Offline manifest and bundle validation without evidence execution.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::Value;
use walkdir::WalkDir;

use crate::{canonical, json};

const MAX_FILES: usize = 4_000;

#[derive(Debug, Clone, Serialize)]
pub struct ValidationReport {
    pub valid: bool,
    pub schema_version: Option<String>,
    pub computed_status: Option<String>,
    pub checked_files: usize,
    pub issues: Vec<String>,
    pub unsupported: Vec<String>,
}

fn safe_path(root: &Path, relative: &str) -> Result<PathBuf> {
    if relative.is_empty() || relative.contains('\\') {
        bail!("unsafe relative path: {relative}");
    }
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        bail!("unsafe relative path: {relative}");
    }
    let mut current = root.to_path_buf();
    for component in path.components() {
        let Component::Normal(part) = component else {
            bail!("unsafe relative path: {relative}");
        };
        current.push(part);
        if current.exists()
            && std::fs::symlink_metadata(&current)?
                .file_type()
                .is_symlink()
        {
            bail!("symlink path is forbidden: {relative}");
        }
    }
    Ok(current)
}

fn verify_reference(
    root: &Path,
    reference: &serde_json::Map<String, Value>,
    issues: &mut Vec<String>,
) -> Option<PathBuf> {
    let relative = reference
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expected = reference
        .get("sha256")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let path = match safe_path(root, relative) {
        Ok(path) => path,
        Err(error) => {
            issues.push(error.to_string());
            return None;
        }
    };
    match canonical::hash_file(&path) {
        Ok(actual) if actual == expected => Some(path),
        Ok(actual) => {
            issues.push(format!(
                "hash mismatch for {relative}: expected {expected}, found {actual}"
            ));
            None
        }
        Err(error) => {
            issues.push(format!("cannot hash {relative}: {error}"));
            None
        }
    }
}

fn status_rank(status: &str) -> Option<u8> {
    match status {
        "PASS" => Some(0),
        "UNKNOWN" => Some(1),
        "FAIL" => Some(2),
        _ => None,
    }
}

fn index_records(
    root: &Path,
    manifest: &Value,
    issues: &mut Vec<String>,
) -> BTreeMap<String, Value> {
    let Some(reference) = manifest.get("evidence_index").and_then(Value::as_object) else {
        return BTreeMap::new();
    };
    let Some(path) = verify_reference(root, reference, issues) else {
        return BTreeMap::new();
    };
    let content = match canonical::read_regular(&path, canonical::MAX_JSON_BYTES) {
        Ok(content) => content,
        Err(error) => {
            issues.push(error.to_string());
            return BTreeMap::new();
        }
    };
    let index = match json::parse_slice(&content) {
        Ok(value) => value,
        Err(error) => {
            issues.push(format!("invalid evidence index: {error}"));
            return BTreeMap::new();
        }
    };
    let mut records = BTreeMap::new();
    for record in index
        .get("records")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
    {
        let Some(identifier) = record.get("id").and_then(Value::as_str) else {
            continue;
        };
        if records
            .insert(identifier.to_owned(), Value::Object(record.clone()))
            .is_some()
        {
            issues.push(format!("duplicate evidence ID: {identifier}"));
        }
        let _ = verify_reference(root, record, issues);
    }
    records
}

fn derive_status(root: &Path, manifest: &Value, records: &BTreeMap<String, Value>) -> String {
    let mut statuses = Vec::new();
    for (gate, identifiers) in manifest
        .get("gate_results")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|gates| gates.iter())
        .filter_map(|(gate, identifiers)| identifiers.as_array().map(|values| (gate, values)))
    {
        for identifier in identifiers.iter().filter_map(Value::as_str) {
            let Some(record) = records.get(identifier).and_then(Value::as_object) else {
                statuses.push("UNKNOWN".to_owned());
                continue;
            };
            let Some(relative) = record.get("path").and_then(Value::as_str) else {
                statuses.push("UNKNOWN".to_owned());
                continue;
            };
            let Ok(path) = safe_path(root, relative) else {
                statuses.push("UNKNOWN".to_owned());
                continue;
            };
            let Ok(content) = canonical::read_regular(&path, canonical::MAX_JSON_BYTES) else {
                statuses.push("UNKNOWN".to_owned());
                continue;
            };
            let Ok(value) = json::parse_slice(&content) else {
                statuses.push("UNKNOWN".to_owned());
                continue;
            };
            if let Some(status) = value.get("status").and_then(Value::as_str) {
                statuses.push(status.to_owned());
            } else if let Some(status) = value
                .get(match gate.as_str() {
                    "measurement_valid" => "measurement_validity",
                    "benefit_threshold" => "benefit_threshold",
                    "worst_regression" => "worst_regression",
                    _ => "",
                })
                .and_then(Value::as_object)
                .and_then(|result| {
                    result
                        .get("status")
                        .or_else(|| result.get("claimed_status"))
                })
                .and_then(Value::as_str)
            {
                statuses.push(status.to_owned());
            } else if let Some(derived) = value
                .get("derived_gate_statuses")
                .and_then(Value::as_object)
            {
                statuses.extend(
                    derived
                        .values()
                        .filter_map(Value::as_str)
                        .map(str::to_owned),
                );
            } else {
                statuses.push("UNKNOWN".to_owned());
            }
        }
    }
    statuses
        .into_iter()
        .max_by_key(|status| status_rank(status).unwrap_or(1))
        .unwrap_or_else(|| {
            manifest
                .get("final_status")
                .and_then(Value::as_str)
                .unwrap_or("UNKNOWN")
                .to_owned()
        })
}

pub fn validate_manifest(path: &Path) -> Result<ValidationReport> {
    let content = canonical::read_regular(path, canonical::MAX_JSON_BYTES)?;
    let manifest = json::parse_slice(&content)?;
    let object = manifest.as_object().context("manifest must be an object")?;
    let version = object
        .get("schema_version")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut issues = Vec::new();
    if !matches!(version.as_deref(), Some("0.1" | "0.1.1" | "0.2")) {
        issues.push("unsupported schema version".to_owned());
    }
    let declared = object
        .get("final_status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if status_rank(declared).is_none() {
        issues.push("final_status must be PASS, FAIL, or UNKNOWN".to_owned());
    }
    let root = path.parent().context("manifest has no parent")?;
    let mut checked = 0;
    let required_references: &[&str] = if version.as_deref() == Some("0.1") {
        &["reference", "machine"]
    } else {
        &["contract", "reference", "machine"]
    };
    for name in required_references {
        if let Some(reference) = object.get(*name).and_then(Value::as_object) {
            if verify_reference(root, reference, &mut issues).is_some() {
                checked += 1;
            }
        } else {
            issues.push(format!("missing file reference: {name}"));
        }
    }
    let records = index_records(root, &manifest, &mut issues);
    checked += records.len();
    let computed = if version.as_deref() == Some("0.1") {
        declared.to_owned()
    } else {
        derive_status(root, &manifest, &records)
    };
    if computed != declared {
        issues.push(format!(
            "declared status {declared} differs from derived {computed}"
        ));
    }
    issues.sort();
    issues.dedup();
    Ok(ValidationReport {
        valid: issues.is_empty(),
        schema_version: version,
        computed_status: status_rank(&computed).map(|_| computed),
        checked_files: checked,
        issues,
        unsupported: Vec::new(),
    })
}

pub fn validate_bundle(path: &Path) -> Result<ValidationReport> {
    if !path.is_dir() {
        bail!("bundle is not a directory: {}", path.display());
    }
    let mut layout_issues = Vec::new();
    for required in [
        "specification",
        "reference",
        "machine",
        "evidence",
        "provenance",
    ] {
        if !path.join(required).is_dir() {
            layout_issues.push(format!("missing bundle directory: {required}"));
        }
    }
    let mut files = 0_usize;
    for entry in WalkDir::new(path).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            layout_issues.push(format!(
                "bundle symlink is forbidden: {}",
                entry.path().display()
            ));
        } else if entry.file_type().is_file() {
            files += 1;
        } else if !entry.file_type().is_dir() {
            layout_issues.push(format!(
                "unsafe bundle file type: {}",
                entry.path().display()
            ));
        }
    }
    if files > MAX_FILES {
        layout_issues.push(format!("bundle exceeds {MAX_FILES} files"));
    }
    let mut report = validate_manifest(&path.join("manifest.json"))?;
    report.issues.extend(layout_issues);
    report.issues.sort();
    report.issues.dedup();
    report.valid = report.issues.is_empty();
    Ok(report)
}

pub fn safe_relative_path(value: &str) -> bool {
    safe_path(Path::new("."), value).is_ok()
}

pub fn supported_versions() -> BTreeSet<&'static str> {
    ["0.1", "0.1.1", "0.2"].into_iter().collect()
}
