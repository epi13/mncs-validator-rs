//! Independent Ed25519 DSSE-compatible attestation verification.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{canonical, json};

pub const PAYLOAD_TYPE: &str = "application/vnd.mncs.attestation-statement.v0.2+json";

#[derive(Debug, Clone, Serialize)]
pub struct SignatureResult {
    pub keyid: String,
    pub cryptographically_valid: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Verification {
    pub payload_valid: bool,
    pub expired: bool,
    pub cryptographically_valid: bool,
    pub signatures: Vec<SignatureResult>,
    pub statement: Option<Value>,
}

fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes()
    .into_iter()
    .chain(payload.iter().copied())
    .collect()
}

fn key_id(raw: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(raw)))
}

fn parse_time(value: Option<&Value>) -> Option<DateTime<Utc>> {
    value
        .and_then(Value::as_str)
        .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
        .map(|value| value.with_timezone(&Utc))
}

fn public_keys(records: &[Value]) -> Result<BTreeMap<String, VerifyingKey>> {
    let mut keys = BTreeMap::new();
    for record in records {
        let object = record.as_object().context("key record must be an object")?;
        if object.get("algorithm").and_then(Value::as_str) != Some("ed25519") {
            bail!("unsupported public-key algorithm");
        }
        let keyid = object
            .get("keyid")
            .and_then(Value::as_str)
            .context("key record has no keyid")?;
        let raw = STANDARD.decode(
            object
                .get("public_key")
                .and_then(Value::as_str)
                .context("key record has no public_key")?,
        )?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid key length"))?;
        if key_id(&bytes) != keyid {
            bail!("key ID does not match public-key bytes");
        }
        if keys
            .insert(keyid.to_owned(), VerifyingKey::from_bytes(&bytes)?)
            .is_some()
        {
            bail!("duplicate public key ID");
        }
    }
    Ok(keys)
}

fn subject_hashes(statement: &Map<String, Value>) -> BTreeSet<&str> {
    statement
        .get("subject")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter_map(|item| item.get("digest"))
        .filter_map(Value::as_object)
        .filter_map(|digest| digest.get("sha256"))
        .filter_map(Value::as_str)
        .collect()
}

pub fn verify(
    envelope: &Value,
    key_records: &[Value],
    expected_subject: Option<&str>,
    expected_contract: Option<&str>,
    expected_environment: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Verification> {
    let object = envelope.as_object().context("envelope must be an object")?;
    let payload_type = object
        .get("payloadType")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut payload_valid = payload_type == PAYLOAD_TYPE;
    let payload = object
        .get("payload")
        .and_then(Value::as_str)
        .and_then(|value| STANDARD.decode(value).ok())
        .unwrap_or_default();
    let statement = json::parse_slice(&payload).ok();
    if statement
        .as_ref()
        .and_then(Value::as_object)
        .is_none_or(|_| {
            canonical::canonicalize(statement.as_ref().unwrap_or(&Value::Null))
                .ok()
                .as_deref()
                != Some(payload.as_slice())
        })
    {
        payload_valid = false;
    }
    let statement_object = statement.as_ref().and_then(Value::as_object);
    if let (Some(expected), Some(actual)) = (
        expected_subject.map(|value| value.strip_prefix("sha256:").unwrap_or(value)),
        statement_object,
    ) {
        if !subject_hashes(actual).contains(expected) {
            payload_valid = false;
        }
    }
    if let Some(expected) = expected_contract
        && statement_object
            .and_then(|value| value.get("contract_id"))
            .and_then(Value::as_str)
            != Some(expected)
    {
        payload_valid = false;
    }
    if let Some(expected) = expected_environment
        && statement_object
            .and_then(|value| value.get("environment"))
            .and_then(Value::as_str)
            != Some(expected)
    {
        payload_valid = false;
    }
    let expired = statement_object
        .and_then(|value| parse_time(value.get("expires_at")))
        .is_some_and(|expiration| now >= expiration);
    let keys = public_keys(key_records)?;
    let mut seen = BTreeSet::new();
    let mut results = Vec::new();
    let signatures = object
        .get("signatures")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !object.get("signatures").is_some_and(Value::is_array) {
        payload_valid = false;
    }
    for item in signatures {
        let Some(signature_object) = item.as_object() else {
            results.push(SignatureResult {
                keyid: String::new(),
                cryptographically_valid: false,
                reason: "malformed signature".to_owned(),
            });
            continue;
        };
        let keyid = signature_object
            .get("keyid")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if !seen.insert(keyid.clone()) {
            payload_valid = false;
            results.push(SignatureResult {
                keyid,
                cryptographically_valid: false,
                reason: "duplicate signature".to_owned(),
            });
            continue;
        }
        let valid = (|| -> Result<()> {
            if signature_object.get("algorithm").and_then(Value::as_str) != Some("ed25519") {
                bail!("algorithm confusion");
            }
            let key = keys.get(&keyid).context("public key unavailable")?;
            let raw = STANDARD.decode(
                signature_object
                    .get("sig")
                    .and_then(Value::as_str)
                    .context("signature missing")?,
            )?;
            let signature = Signature::from_slice(&raw)?;
            key.verify_strict(&pae(payload_type, &payload), &signature)?;
            Ok(())
        })()
        .is_ok();
        results.push(SignatureResult {
            keyid,
            cryptographically_valid: valid,
            reason: if valid {
                "valid signature".to_owned()
            } else {
                "invalid signature".to_owned()
            },
        });
    }
    let cryptographically_valid =
        payload_valid && results.iter().any(|item| item.cryptographically_valid);
    Ok(Verification {
        payload_valid,
        expired,
        cryptographically_valid,
        signatures: results,
        statement,
    })
}

pub fn load(path: &std::path::Path) -> Result<Value> {
    json::parse_slice(&canonical::read_regular(path, canonical::MAX_JSON_BYTES)?)
}
