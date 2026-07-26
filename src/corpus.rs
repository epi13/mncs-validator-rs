//! Versioned cross-implementation corpus runner.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{attestation, canonical, json as strict_json, package, trust, validation};

#[derive(Debug, Serialize)]
pub struct VectorResult {
    pub id: String,
    pub actual: Value,
    pub expected: Value,
    pub matches: bool,
}

#[derive(Debug, Serialize)]
pub struct CorpusReport {
    pub corpus_version: String,
    pub implementation: &'static str,
    pub implementation_version: &'static str,
    pub vector_count: usize,
    pub mismatch_count: usize,
    pub unsupported_count: usize,
    pub results: Vec<VectorResult>,
}

fn paths(base: &Path, vector: &Value) -> Vec<PathBuf> {
    vector
        .get("input_paths")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|value| base.join(value))
        .collect()
}

fn parse_time(value: Option<&Value>) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(
        value
            .and_then(Value::as_str)
            .unwrap_or("2026-01-01T00:00:00Z"),
    )?
    .with_timezone(&Utc))
}

fn run_vector(base: &Path, vector: &Value) -> Result<Value> {
    let inputs = paths(base, vector);
    let kind = vector
        .get("kind")
        .and_then(Value::as_str)
        .context("vector has no kind")?;
    match kind {
        "canonical" => match canonical::canonicalize_file(&inputs[0]) {
            Ok(content) => {
                let digest = canonical::sha256(&content);
                let expected = vector
                    .get("expected_canonical_hash")
                    .and_then(Value::as_str);
                Ok(
                    json!({"category": if Some(digest.as_str()) == expected {"PASS"} else {"INVALID"}}),
                )
            }
            Err(_) => Ok(json!({"category": "INVALID"})),
        },
        "signature" => {
            let envelope = attestation::load(&inputs[0])?;
            let keys = inputs[1..]
                .iter()
                .map(|path| attestation::load(path))
                .collect::<Result<Vec<_>>>()?;
            let bindings = vector.get("bindings").and_then(Value::as_object);
            let result = attestation::verify(
                &envelope,
                &keys,
                bindings
                    .and_then(|value| value.get("subject"))
                    .and_then(Value::as_str),
                bindings
                    .and_then(|value| value.get("contract"))
                    .and_then(Value::as_str),
                bindings
                    .and_then(|value| value.get("environment"))
                    .and_then(Value::as_str),
                parse_time(bindings.and_then(|value| value.get("now")))?,
            )?;
            let category = if result.expired
                && result
                    .signatures
                    .iter()
                    .any(|item| item.cryptographically_valid)
            {
                "EXPIRED"
            } else if result.cryptographically_valid {
                "PASS"
            } else {
                "INVALID"
            };
            Ok(json!({"category": category}))
        }
        "trust" => {
            let envelope = attestation::load(&inputs[0])?;
            let policy = attestation::load(&inputs[1])?;
            let bindings = vector.get("bindings").and_then(Value::as_object);
            let result = trust::evaluate(
                &envelope,
                &policy,
                None,
                None,
                None,
                parse_time(bindings.and_then(|value| value.get("now")))?,
            )?;
            Ok(json!({"category": if result.trusted {"PASS"} else {"UNTRUSTED"}}))
        }
        "package" => Ok(json!({
            "category": if package::verify(&inputs[0], true)?.valid {"PASS"} else {"INVALID"}
        })),
        "package-reproducible" => {
            let first = canonical::read_regular(&inputs[0], 600 * 1024 * 1024)?;
            let second = canonical::read_regular(&inputs[1], 600 * 1024 * 1024)?;
            let expected = vector
                .get("expected_canonical_hash")
                .and_then(Value::as_str);
            Ok(json!({
                "category": if first == second && Some(canonical::sha256(&first).as_str()) == expected {
                    "PASS"
                } else {
                    "INVALID"
                }
            }))
        }
        "manifest" => {
            let report = validation::validate_manifest(&inputs[0])?;
            Ok(json!({
                "category": if report.valid {
                    report.computed_status.as_deref().unwrap_or("INVALID")
                } else {
                    "INVALID"
                }
            }))
        }
        "schema" => {
            let value = strict_json::parse_slice(&canonical::read_regular(
                &inputs[0],
                canonical::MAX_JSON_BYTES,
            )?)?;
            let valid = value
                .get("$id")
                .and_then(Value::as_str)
                .is_some_and(|identifier| identifier.contains("/0.2/"));
            Ok(json!({"category": if valid {"PASS"} else {"INVALID"}}))
        }
        "provider" => {
            let value = attestation::load(&inputs[0])?;
            let protocol = value.get("protocol_version").and_then(Value::as_str) == Some("0.1");
            let message_type = value.get("type").and_then(Value::as_str);
            let category = if !protocol
                || !matches!(
                    message_type,
                    Some(
                        "capabilities"
                            | "analysis_response"
                            | "health_response"
                            | "error"
                            | "cancelled"
                    )
                ) {
                "INVALID"
            } else {
                value
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("PASS")
            };
            Ok(json!({"category": category}))
        }
        _ => Ok(json!({"category": "UNSUPPORTED"})),
    }
}

pub fn run(path: &Path) -> Result<CorpusReport> {
    let corpus = attestation::load(path)?;
    let base = path.parent().context("corpus has no parent")?;
    let vectors = corpus
        .get("vectors")
        .and_then(Value::as_array)
        .context("corpus vectors must be an array")?;
    let mut results = Vec::new();
    for vector in vectors {
        let actual = run_vector(base, vector)?;
        let expected = vector
            .get("expected_rust")
            .cloned()
            .context("vector has no Rust expectation")?;
        results.push(VectorResult {
            id: vector
                .get("id")
                .and_then(Value::as_str)
                .context("vector has no ID")?
                .to_owned(),
            matches: actual == expected,
            actual,
            expected,
        });
    }
    Ok(CorpusReport {
        corpus_version: corpus
            .get("corpus_version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        implementation: "rust",
        implementation_version: env!("CARGO_PKG_VERSION"),
        vector_count: results.len(),
        mismatch_count: results.iter().filter(|item| !item.matches).count(),
        unsupported_count: results
            .iter()
            .filter(|item| {
                item.actual.get("category").and_then(Value::as_str) == Some("UNSUPPORTED")
            })
            .count(),
        results,
    })
}
