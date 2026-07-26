//! Deterministic offline trust-policy evaluation.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::attestation::{self, Verification};

#[derive(Debug, Clone, Serialize)]
pub struct Evaluation {
    pub cryptographically_valid: bool,
    pub trusted: bool,
    pub certified: bool,
    pub trusted_signers: Vec<String>,
    pub satisfied_roles: Vec<String>,
    pub reasons: Vec<String>,
    pub verification: Verification,
}

fn parse_time(value: Option<&Value>) -> Option<DateTime<Utc>> {
    value
        .and_then(Value::as_str)
        .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
        .map(|value| value.with_timezone(&Utc))
}

fn scope_matches(value: &str, scopes: Option<&Value>) -> bool {
    scopes.and_then(Value::as_array).is_none_or(|values| {
        values
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item == "*" || item == value)
    })
}

fn positive_integer(policy: &serde_json::Map<String, Value>, name: &str) -> Result<usize> {
    let value = policy
        .get(name)
        .and_then(Value::as_u64)
        .with_context(|| format!("{name} must be an integer"))?;
    if value == 0 {
        bail!("{name} must be positive");
    }
    Ok(usize::try_from(value)?)
}

pub fn evaluate(
    envelope: &Value,
    policy: &Value,
    expected_subject: Option<&str>,
    expected_contract: Option<&str>,
    expected_environment: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Evaluation> {
    let object = policy.as_object().context("policy must be an object")?;
    if object.get("schema_version").and_then(Value::as_str) != Some("0.2")
        || object.get("trust_domain").and_then(Value::as_str).is_none()
        || object
            .get("unknown_handling")
            .and_then(Value::as_str)
            .is_none()
    {
        bail!("invalid trust-policy header");
    }
    let keys = object
        .get("keys")
        .and_then(Value::as_array)
        .context("policy keys must be an array")?;
    let verification = attestation::verify(
        envelope,
        keys,
        expected_subject,
        expected_contract,
        expected_environment,
        now,
    )?;
    let statement = verification
        .statement
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let predicate_type = statement
        .get("predicate_type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let contract = statement
        .get("contract_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let environment = statement
        .get("environment")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let component = statement
        .get("component")
        .and_then(Value::as_object)
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let valid_keyids = verification
        .signatures
        .iter()
        .filter(|item| item.cryptographically_valid)
        .map(|item| item.keyid.as_str())
        .collect::<BTreeSet<_>>();
    let revoked = object
        .get("revocations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter(|record| parse_time(record.get("revoked_at")).is_none_or(|time| time <= now))
        .filter_map(|record| record.get("keyid"))
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let mut reasons = Vec::new();
    let mut trusted_signers = BTreeSet::new();
    let mut roles = BTreeSet::new();
    let mut evaluators = BTreeSet::new();
    let mut generators = BTreeSet::new();
    for record in keys.iter().filter_map(Value::as_object) {
        let Some(keyid) = record.get("keyid").and_then(Value::as_str) else {
            continue;
        };
        if !valid_keyids.contains(keyid) {
            continue;
        }
        if record
            .get("trusted")
            .and_then(Value::as_bool)
            .is_some_and(|trusted| !trusted)
        {
            reasons.push(format!(
                "cryptographically valid but untrusted key: {keyid}"
            ));
            continue;
        }
        if revoked.contains(keyid) {
            reasons.push(format!("revoked key: {keyid}"));
            continue;
        }
        if parse_time(record.get("valid_from")).is_some_and(|time| now < time)
            || parse_time(record.get("valid_until")).is_some_and(|time| now >= time)
        {
            reasons.push(format!("key outside validity window: {keyid}"));
            continue;
        }
        if !scope_matches(predicate_type, record.get("predicate_types"))
            || !scope_matches(contract, record.get("contracts"))
            || !scope_matches(component, record.get("components"))
            || !scope_matches(environment, record.get("environments"))
        {
            reasons.push(format!("key outside statement scope: {keyid}"));
            continue;
        }
        trusted_signers.insert(keyid.to_owned());
        for role in record
            .get("roles")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            roles.insert(role.to_owned());
            if role == "evaluator" {
                evaluators.insert(keyid.to_owned());
            } else if role == "generator" {
                generators.insert(keyid.to_owned());
            }
        }
    }
    let allowed = object
        .get("allowed_predicate_types")
        .and_then(Value::as_array)
        .context("allowed_predicate_types must be an array")?
        .iter()
        .filter_map(Value::as_str)
        .any(|value| value == predicate_type);
    if !allowed {
        reasons.push("predicate type is not allowed".to_owned());
    }
    if verification.expired {
        reasons.push("attestation expired".to_owned());
    }
    if trusted_signers.len() < positive_integer(object, "minimum_signatures")? {
        reasons.push("insufficient trusted signatures".to_owned());
    }
    if trusted_signers.len() < positive_integer(object, "distinct_signers")? {
        reasons.push("insufficient distinct trusted signers".to_owned());
    }
    for role in object
        .get("required_roles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !roles.contains(role) {
            reasons.push(format!("missing required role: {role}"));
        }
    }
    let independent = object
        .get("minimum_independent_evaluators")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if u64::try_from(evaluators.len())? < independent {
        reasons.push("insufficient independent evaluators".to_owned());
    }
    if object
        .get("require_generator_evaluator_separation")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && (generators.is_empty() || evaluators.is_empty() || !generators.is_disjoint(&evaluators))
    {
        reasons.push("generator/evaluator separation failed".to_owned());
    }
    let status = statement
        .get("predicate")
        .and_then(Value::as_object)
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str);
    if status == Some("UNKNOWN") {
        reasons.push(format!(
            "UNKNOWN handled as {}",
            object
                .get("unknown_handling")
                .and_then(Value::as_str)
                .unwrap_or("reject")
        ));
    }
    reasons.sort();
    reasons.dedup();
    let cryptographically_valid = verification.cryptographically_valid && !verification.expired;
    let trusted = cryptographically_valid && reasons.is_empty();
    let certified = trusted && status == Some("PASS");
    Ok(Evaluation {
        cryptographically_valid,
        trusted,
        certified,
        trusted_signers: trusted_signers.into_iter().collect(),
        satisfied_roles: roles.into_iter().collect(),
        reasons,
        verification,
    })
}
