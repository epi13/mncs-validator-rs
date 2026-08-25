//! Rights & Provenance v0.2 conformance.
//!
//! Golden vectors are generated from the normative MNCS-language policy core
//! (`mncs.rights.policy.v01`) by `language/tools/gen_corpus.py` in the
//! mncs-rights-provenance repository and shared verbatim. The Rust gate
//! engine must reproduce them exactly.

use mncs_validator_rs::rights::{GateInput, effective_severities, outcome_from_effective};
use serde::Deserialize;

#[derive(Deserialize)]
struct GoldenCase {
    input: GoldenInput,
    #[allow(dead_code)]
    severities: serde_json::Value,
    outcome: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct GoldenInput {
    origin_code: i32,
    copyright_code: i32,
    rights_basis_code: i32,
    third_party_code: i32,
    prov_valid_code: i32,
    human_accept_code: i32,
    incompatible_source_count: i32,
    unknown_source_count: i32,
    contradiction_count: i32,
    hash_mismatch: bool,
    broken_evidence_refs: i32,
    graph_invalid: bool,
    attestation_conflicts: i32,
    impossible_evidence: bool,
    canonical_release_profile: bool,
}

impl From<&GoldenInput> for GateInput {
    fn from(value: &GoldenInput) -> Self {
        Self {
            origin_code: value.origin_code,
            copyright_code: value.copyright_code,
            rights_basis_code: value.rights_basis_code,
            third_party_code: value.third_party_code,
            prov_valid_code: value.prov_valid_code,
            human_accept_code: value.human_accept_code,
            incompatible_source_count: value.incompatible_source_count,
            unknown_source_count: value.unknown_source_count,
            contradiction_count: value.contradiction_count,
            hash_mismatch: value.hash_mismatch,
            broken_evidence_refs: value.broken_evidence_refs,
            graph_invalid: value.graph_invalid,
            attestation_conflicts: value.attestation_conflicts,
            impossible_evidence: value.impossible_evidence,
            canonical_release_profile: value.canonical_release_profile,
        }
    }
}

fn kebab(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (index, ch) in name.chars().enumerate() {
        if ch.is_uppercase() {
            if index > 0 {
                out.push('-');
            }
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn load_goldens() -> std::io::Result<Vec<GoldenCase>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/rights-conformance/golden-vectors.json"
    );
    let text = std::fs::read_to_string(path)?;
    let document: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    serde_json::from_value(document["cases"].clone())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

macro_rules! ok {
    ($expr:expr) => {
        match $expr {
            Ok(value) => value,
            Err(error) => panic!("test setup failed: {error}"),
        }
    };
}

macro_rules! report {
    ($manifest:expr) => {
        match mncs_validator_rs::rights::validate_manifest($manifest) {
            Ok(report) => report,
            Err(error) => panic!("validation failed: {error}"),
        }
    };
}

#[test]
fn rust_gate_engine_matches_language_core_golden_vectors() {
    let cases = ok!(load_goldens());
    assert!(!cases.is_empty(), "golden vectors must not be empty");
    for (index, case) in cases.iter().enumerate() {
        let input = GateInput::from(&case.input);
        let (_raw, effective) = effective_severities(&input);
        let outcome = outcome_from_effective(&effective);
        // Golden outcomes use MNCS enum variant names (PascalCase).
        assert_eq!(
            outcome,
            kebab(&case.outcome),
            "case {index} diverged from MNCS-language core"
        );
    }
}

const CLEAN_MANIFEST: &str = r#"{
  "schema_version": "0.2.0",
  "artifact": {"id": "example/clean", "class": "source-code"},
  "provenance": {
    "origin_classification": "human-authored",
    "participants": [{"type": "human", "role": "author", "name": "A"}],
    "process_evidence": []
  },
  "rights": {
    "distribution_license": "Apache-2.0",
    "copyright_status": "human-authorship-confirmed",
    "rights_basis": "contributor-attested",
    "third_party_material": "none-known",
    "sources": []
  },
  "review": {"technical_validation": "passed", "provenance_validation": "passed", "human_acceptance": "accepted"}
}"#;

#[test]
fn clean_human_authored_manifest_passes() {
    let report = report!(CLEAN_MANIFEST.as_bytes());
    assert_eq!(report.outcome, "pass", "issues: {:?}", report.issues);
    assert!(report.valid);
    assert_eq!(report.legal_conclusion, "NOT_MADE");
}

#[test]
fn scaffold_default_manifest_requires_review() {
    // Uncertain-by-default manifest: everything unresolved routes to review.
    let manifest = r#"{
      "schema_version": "0.2.0",
      "spec_profile": "development",
      "artifact": {"id": "example/dev", "class": "experiment-output"},
      "provenance": {"origin_classification": "origin-uncertain", "participants": [], "process_evidence": []},
      "rights": {
        "distribution_license": "Apache-2.0",
        "copyright_status": "unresolved",
        "rights_basis": "unknown-needs-review",
        "third_party_material": "unknown",
        "sources": []
      },
      "review": {"technical_validation": "not-run", "provenance_validation": "not-run", "human_acceptance": "not-reviewed"}
    }"#;
    let report = report!(manifest.as_bytes());
    // Unknown rights basis routes to review even under the development
    // profile; other uncertain states downgrade to findings only.
    assert_eq!(report.outcome, "review-required");
    assert!(
        report
            .findings
            .contains(&"third-party material state is unresolved".to_string())
    );
    assert!(
        report
            .findings
            .contains(&"copyright status remains unresolved".to_string())
    );
}

#[test]
fn incompatible_third_party_license_blocks() {
    let mut manifest = ok!(serde_json::to_value(ok!(serde_json::from_str::<
        serde_json::Value,
    >(CLEAN_MANIFEST))));
    manifest["rights"]["sources"] = serde_json::json!([
        {"kind": "repository", "reference": "https://upstream.invalid/x", "license_status": "incompatible"}
    ]);
    let content = ok!(serde_json::to_vec(&manifest));
    let report = report!(&content);
    assert_eq!(report.outcome, "blocked");
}

#[test]
fn cyclic_graph_is_invalid() {
    let mut manifest = ok!(serde_json::to_value(ok!(serde_json::from_str::<
        serde_json::Value,
    >(CLEAN_MANIFEST))));
    manifest["provenance"]["graph"] = serde_json::json!({
        "nodes": [
            {"id": "a", "kind": "artifact"},
            {"id": "b", "kind": "transformation"},
            {"id": "c", "kind": "artifact"}
        ],
        "edges": [
            {"from": "a", "to": "b", "relation": "transformed-by"},
            {"from": "b", "to": "c", "relation": "derived-from"},
            {"from": "c", "to": "a", "relation": "referenced"}
        ]
    });
    let content = ok!(serde_json::to_vec(&manifest));
    let report = report!(&content);
    // Graph integrity is a policy-fatal gate over an otherwise well-formed
    // document, so the outcome is "blocked", not "invalid".
    assert_eq!(report.outcome, "blocked");
    assert!(report.issues.iter().any(|issue| issue.contains("cycle")));
}

#[test]
fn unsupported_schema_version_is_invalid_not_guessed() {
    let mut manifest = ok!(serde_json::to_value(ok!(serde_json::from_str::<
        serde_json::Value,
    >(CLEAN_MANIFEST))));
    manifest["schema_version"] = serde_json::json!("9.9.9");
    let content = ok!(serde_json::to_vec(&manifest));
    let report = report!(&content);
    assert_eq!(report.outcome, "invalid");
}

#[test]
fn duplicate_keys_rejected_by_strict_parser() {
    let tampered = format!(
        "{{\"schema_version\": \"0.2.0\", \"schema_version\": \"0.1.0\", {}}}",
        &CLEAN_MANIFEST[1..]
    );
    let result = mncs_validator_rs::rights::validate_manifest(tampered.as_bytes());
    assert!(result.is_err(), "duplicate keys must fail closed");
}
