//! Bounded verification of the deterministic `mncs-zip-0.1` profile.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use zip::{CompressionMethod, ZipArchive};

use crate::{canonical, json};

const INDEX_PATH: &str = "mncs-package-index.json";
const MAX_FILES: usize = 4_001;
const MAX_DEPTH: usize = 24;
const MAX_MEMBER: u64 = 64 * 1024 * 1024;
const MAX_TOTAL: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct PackageReport {
    pub valid: bool,
    pub package_sha256: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub evidence_index_sha256: Option<String>,
    pub issues: Vec<String>,
    pub index: Option<Value>,
}

fn safe_name(name: &str) -> bool {
    if name.is_empty()
        || name.starts_with('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.ends_with('/')
    {
        return false;
    }
    let parts = name.split('/').collect::<Vec<_>>();
    parts.len() <= MAX_DEPTH
        && parts
            .iter()
            .all(|part| !part.is_empty() && *part != "." && *part != "..")
}

fn unsafe_mode(mode: Option<u32>) -> bool {
    mode.is_some_and(|value| {
        let file_type = value & 0o170_000;
        file_type != 0 && file_type != 0o100_000
    })
}

fn read_index(path: &Path) -> Result<Vec<u8>> {
    let mut archive = ZipArchive::new(File::open(path)?)?;
    let mut file = archive
        .by_name(INDEX_PATH)
        .context("package index is missing")?;
    if file.size() > MAX_MEMBER {
        anyhow::bail!("package index is oversized");
    }
    let mut content = Vec::with_capacity(usize::try_from(file.size())?);
    file.read_to_end(&mut content)?;
    Ok(content)
}

pub fn verify(path: &Path, verify_content: bool) -> Result<PackageReport> {
    let package_content = canonical::read_regular(path, MAX_TOTAL + 16 * 1024 * 1024)?;
    let package_sha256 = canonical::mncs_sha256(&package_content);
    let mut archive = ZipArchive::new(File::open(path)?)?;
    let file_count = archive.len();
    let mut issues = Vec::new();
    if file_count > MAX_FILES {
        issues.push("file-count limit exceeded".to_owned());
    }
    let mut names = Vec::new();
    let mut seen = BTreeSet::new();
    let mut total_bytes = 0_u64;
    for index in 0..file_count {
        let file = archive.by_index_raw(index)?;
        let name = file.name().to_owned();
        if !seen.insert(name.clone()) {
            issues.push("duplicate archive member".to_owned());
        }
        if !safe_name(&name) {
            issues.push(format!("unsafe package path: {name}"));
        }
        if file.is_dir() || unsafe_mode(file.unix_mode()) {
            issues.push(format!("unsafe archive member type: {name}"));
        }
        if file.compression() != CompressionMethod::Stored {
            issues.push(format!("non-deterministic compression: {name}"));
        }
        if file.size() > MAX_MEMBER {
            issues.push(format!("member size limit exceeded: {name}"));
        }
        total_bytes = total_bytes.saturating_add(file.size());
        if total_bytes > MAX_TOTAL {
            issues.push("total uncompressed size limit exceeded".to_owned());
        }
        names.push(name);
    }
    let mut sorted_names = names.clone();
    sorted_names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if names != sorted_names {
        issues.push("members are not bytewise path sorted".to_owned());
    }
    drop(archive);
    let mut parsed_index = None;
    let mut evidence_index_sha256 = None;
    if names.iter().any(|name| name == INDEX_PATH) {
        match read_index(path).and_then(|content| {
            let value = json::parse_slice(&content)?;
            if canonical::canonicalize(&value)? != content {
                anyhow::bail!("package index is not canonical");
            }
            Ok(value)
        }) {
            Ok(value) => {
                evidence_index_sha256 = value
                    .get("evidence_index_sha256")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                parsed_index = Some(value);
            }
            Err(error) => issues.push(error.to_string()),
        }
    } else {
        issues.push("package index is missing".to_owned());
    }
    if verify_content && let Some(index) = &parsed_index {
        let mut archive = ZipArchive::new(File::open(path)?)?;
        let records = index
            .get("files")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut expected_names = Vec::new();
        for record in records {
            let Some(record) = record.as_object() else {
                issues.push("malformed package index record".to_owned());
                continue;
            };
            let name = record
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or_default();
            expected_names.push(name.to_owned());
            let Ok(mut file) = archive.by_name(name) else {
                issues.push(format!("indexed member is missing: {name}"));
                continue;
            };
            if file.size() > MAX_MEMBER {
                issues.push(format!("member size limit exceeded: {name}"));
                continue;
            }
            let mut content = Vec::with_capacity(usize::try_from(file.size())?);
            file.read_to_end(&mut content)?;
            if record.get("size").and_then(Value::as_u64) != Some(file.size()) {
                issues.push(format!("size mismatch: {name}"));
            }
            if record.get("sha256").and_then(Value::as_str)
                != Some(canonical::mncs_sha256(&content).as_str())
            {
                issues.push(format!("hash mismatch: {name}"));
            }
        }
        let actual_names = names
            .iter()
            .filter(|name| name.as_str() != INDEX_PATH)
            .cloned()
            .collect::<Vec<_>>();
        if expected_names != actual_names {
            issues.push("package index/member ordering mismatch".to_owned());
        }
        if let Ok(mut file) = archive.by_name("evidence/index.json") {
            let mut content = Vec::with_capacity(usize::try_from(file.size())?);
            file.read_to_end(&mut content)?;
            if evidence_index_sha256.as_deref() != Some(canonical::mncs_sha256(&content).as_str()) {
                issues.push("embedded evidence-index identity mismatch".to_owned());
            }
        }
    }
    issues.sort();
    issues.dedup();
    Ok(PackageReport {
        valid: issues.is_empty(),
        package_sha256,
        file_count,
        total_bytes,
        evidence_index_sha256,
        issues,
        index: parsed_index,
    })
}
