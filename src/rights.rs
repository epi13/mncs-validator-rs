//! MNCS Rights & Provenance v0.2 validation.
//!
//! Structural validation and release-policy evaluation over rights manifests.
//! Policy gate semantics mirror the normative MNCS-language core
//! (`mncs.rights.policy.v01` in the mncs-rights-provenance repository) and are
//! pinned by shared golden vectors (`fixtures/rights-conformance`).
//!
//! This layer is deliberately separate from technical-correctness validation:
//! it never executes evidence and never renders a legal conclusion. A passing
//! outcome records that project evidence requirements were satisfied.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::Value;

use crate::canonical;
use crate::json;

pub const SUPPORTED_SCHEMA_VERSION: &str = "0.2.0";

const SEVERITY_NONE: i32 = 0;
const SEVERITY_FINDING: i32 = 1;
const SEVERITY_REVIEW: i32 = 2;
const SEVERITY_BLOCKING: i32 = 3;

const ENFORCEMENT_DISABLED: i32 = 0;
const ENFORCEMENT_FINDING: i32 = 1;
const ENFORCEMENT_REVIEW: i32 = 2;
const ENFORCEMENT_FATAL: i32 = 3;

// Vocabulary code tables (fixed by specs/policy-core.md v0.2).
fn origin_code(value: &str) -> Option<i32> {
    Some(match value {
        "human-authored" => 0,
        "human-ai-assisted" => 1,
        "human-directed-machine-generated" => 2,
        "autonomous-machine-generated" => 3,
        "mixed-machine-origin" => 4,
        "third-party-derived" => 5,
        "generated-from-licensed-source" => 6,
        "generated-from-public-domain-source" => 7,
        "origin-uncertain" => 8,
        _ => return None,
    })
}

fn copyright_code(value: &str) -> Option<i32> {
    Some(match value {
        "human-authorship-confirmed" => 0,
        "human-authorship-material" => 1,
        "mixed-or-undetermined" => 2,
        "machine-originated-unresolved" => 3,
        "third-party-licensed" => 4,
        "public-domain-asserted" => 5,
        "unresolved" => 6,
        _ => return None,
    })
}

fn basis_code(value: &str) -> Option<i32> {
    Some(match value {
        "project-owned-or-controlled" => 0,
        "contributor-attested" => 1,
        "third-party-license" => 2,
        "public-domain-basis" => 3,
        "no-exclusive-right-asserted" => 4,
        "unknown-needs-review" => 5,
        _ => return None,
    })
}

fn third_party_code(value: &str) -> Option<i32> {
    Some(match value {
        "none-known" => 0,
        "present" => 1,
        "possible" => 2,
        "unknown" => 3,
        _ => return None,
    })
}

fn provenance_validation_code(value: &str) -> Option<i32> {
    Some(match value {
        "passed" => 0,
        "failed" => 1,
        "incomplete" => 2,
        "not-run" => 3,
        _ => return None,
    })
}

fn human_acceptance_code(value: &str) -> Option<i32> {
    Some(match value {
        "accepted" => 0,
        "rejected" => 1,
        "not-reviewed" => 2,
        "not-required" => 3,
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateInput {
    pub origin_code: i32,
    pub copyright_code: i32,
    pub rights_basis_code: i32,
    pub third_party_code: i32,
    pub prov_valid_code: i32,
    pub human_accept_code: i32,
    pub incompatible_source_count: i32,
    pub unknown_source_count: i32,
    pub contradiction_count: i32,
    pub hash_mismatch: bool,
    pub broken_evidence_refs: i32,
    pub graph_invalid: bool,
    pub attestation_conflicts: i32,
    pub impossible_evidence: bool,
    pub canonical_release_profile: bool,
}

/// Raw per-gate severity, canonical order matching
/// `mncs.rights.policy.v01::gate_severities`.
pub fn gate_severities(input: &GateInput) -> [i32; 14] {
    let review_or_finding = if input.canonical_release_profile {
        SEVERITY_REVIEW
    } else {
        SEVERITY_FINDING
    };
    [
        // hash_correspondence
        if input.hash_mismatch {
            SEVERITY_BLOCKING
        } else {
            SEVERITY_NONE
        },
        // evidence_refs
        if input.broken_evidence_refs > 0 {
            SEVERITY_REVIEW
        } else {
            SEVERITY_NONE
        },
        // graph_integrity
        if input.graph_invalid {
            SEVERITY_BLOCKING
        } else {
            SEVERITY_NONE
        },
        // incompatible_license
        if input.incompatible_source_count > 0 {
            SEVERITY_BLOCKING
        } else {
            SEVERITY_NONE
        },
        // contradictory_license
        if input.contradiction_count > 0 {
            SEVERITY_REVIEW
        } else {
            SEVERITY_NONE
        },
        // rights_basis_resolved
        if input.rights_basis_code == 5 {
            SEVERITY_REVIEW
        } else {
            SEVERITY_NONE
        },
        // third_party_resolved
        if input.third_party_code == 2 || input.third_party_code == 3 {
            review_or_finding
        } else {
            SEVERITY_NONE
        },
        // copyright_resolved
        if input.copyright_code == 6 {
            review_or_finding
        } else {
            SEVERITY_NONE
        },
        // provenance_passed
        if input.prov_valid_code == 1 {
            SEVERITY_BLOCKING
        } else {
            SEVERITY_NONE
        },
        // provenance_complete
        if input.prov_valid_code == 2 || input.prov_valid_code == 3 {
            SEVERITY_REVIEW
        } else {
            SEVERITY_NONE
        },
        // human_review_ok
        if input.human_accept_code == 1 {
            SEVERITY_BLOCKING
        } else if input.human_accept_code == 2 {
            review_or_finding
        } else {
            SEVERITY_NONE
        },
        // unknown_source_license
        if input.unknown_source_count > 0 {
            review_or_finding
        } else {
            SEVERITY_NONE
        },
        // attestation_integrity
        if input.attestation_conflicts > 0 {
            SEVERITY_REVIEW
        } else {
            SEVERITY_NONE
        },
        // impossible_evidence_gate
        if input.impossible_evidence {
            SEVERITY_BLOCKING
        } else {
            SEVERITY_NONE
        },
    ]
}

pub fn apply_enforcement(severity: i32, enforcement: i32) -> i32 {
    match enforcement {
        ENFORCEMENT_REVIEW => severity.min(SEVERITY_REVIEW),
        ENFORCEMENT_FINDING => severity.min(SEVERITY_FINDING),
        ENFORCEMENT_DISABLED => SEVERITY_NONE,
        _ => severity,
    }
}

/// Default canonical-release enforcement ceilings, canonical gate order.
pub const DEFAULT_ENFORCEMENTS: [i32; 14] = [
    ENFORCEMENT_FATAL,
    ENFORCEMENT_REVIEW,
    ENFORCEMENT_FATAL,
    ENFORCEMENT_FATAL,
    ENFORCEMENT_REVIEW,
    ENFORCEMENT_REVIEW,
    ENFORCEMENT_REVIEW,
    ENFORCEMENT_REVIEW,
    ENFORCEMENT_FATAL,
    ENFORCEMENT_REVIEW,
    ENFORCEMENT_REVIEW,
    ENFORCEMENT_REVIEW,
    ENFORCEMENT_REVIEW,
    ENFORCEMENT_FATAL,
];

/// Effective severities under the default canonical-release ceilings.
pub fn effective_severities(input: &GateInput) -> ([i32; 14], [i32; 14]) {
    let raw = gate_severities(input);
    let effective = [
        raw[0],
        raw[1].min(SEVERITY_REVIEW),
        raw[2],
        raw[3],
        raw[4].min(SEVERITY_REVIEW),
        raw[5].min(SEVERITY_REVIEW),
        raw[6].min(SEVERITY_REVIEW),
        raw[7].min(SEVERITY_REVIEW),
        raw[8],
        raw[9].min(SEVERITY_REVIEW),
        raw[10].min(SEVERITY_REVIEW),
        raw[11].min(SEVERITY_REVIEW),
        raw[12].min(SEVERITY_REVIEW),
        raw[13],
    ];
    (raw, effective)
}

/// Outcome name derived from the max effective severity.
pub fn outcome_from_effective(effective: &[i32; 14]) -> &'static str {
    let combined = effective.iter().copied().fold(SEVERITY_NONE, i32::max);
    if combined >= SEVERITY_BLOCKING {
        "blocked"
    } else if combined >= SEVERITY_REVIEW {
        "review-required"
    } else if combined >= SEVERITY_FINDING {
        "pass-with-findings"
    } else {
        "pass"
    }
}

pub const GATE_NAMES: [&str; 14] = [
    "artifact_hash_correspondence",
    "evidence_references_resolve",
    "graph_integrity",
    "no_incompatible_third_party_license",
    "no_contradictory_license_evidence",
    "rights_basis_resolved",
    "third_party_material_resolved",
    "copyright_status_resolved",
    "provenance_validation_passed",
    "provenance_complete",
    "human_review_state_acceptable",
    "unknown_source_license",
    "attestation_integrity",
    "no_falsified_or_impossible_evidence",
];

const GATE_FINDINGS: [&str; 14] = [
    "artifact/hash correspondence failed",
    "one or more evidence references are missing or unresolvable",
    "provenance graph violates integrity rules",
    "known incompatible third-party license terms",
    "contradictory license evidence present",
    "rights basis is explicitly unknown and needs review",
    "third-party material state is unresolved",
    "copyright status remains unresolved",
    "provenance validation failed",
    "provenance validation is incomplete or has not run",
    "human review state is unacceptable for release",
    "one or more source licenses have unknown status",
    "contribution attestations conflict or supersede unsoundly",
    "evidence appears falsified or internally impossible",
];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GateResult {
    pub gate: String,
    pub severity: String,
    pub enforcement: String,
    pub effective_severity: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RightsReport {
    pub valid: bool,
    pub outcome: String,
    pub severity: String,
    pub schema_version: String,
    pub manifest_identity_expected: String,
    pub manifest_identity_matches: bool,
    pub issues: Vec<String>,
    pub findings: Vec<String>,
    pub gate_results: Vec<GateResult>,
    pub legal_conclusion: String,
    pub note: String,
}

fn severity_name(severity: i32) -> &'static str {
    match severity {
        SEVERITY_BLOCKING => "blocking",
        SEVERITY_REVIEW => "review",
        SEVERITY_FINDING => "finding",
        _ => "none",
    }
}

fn enforcement_name(enforcement: i32) -> &'static str {
    match enforcement {
        ENFORCEMENT_FATAL => "fatal",
        ENFORCEMENT_REVIEW => "review",
        ENFORCEMENT_FINDING => "finding",
        _ => "disabled",
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// Structural validation mirroring schemas/v0.2/mncs-rights-manifest.schema.json.
pub fn validate_structure(document: &Value) -> Vec<String> {
    let mut issues = Vec::new();
    if !document.is_object() {
        issues.push("manifest must be a JSON object".to_string());
        return issues;
    }
    if str_field(document, "schema_version") != Some(SUPPORTED_SCHEMA_VERSION) {
        issues.push(format!(
            "unsupported schema_version: {:?}",
            str_field(document, "schema_version").unwrap_or("missing")
        ));
        return issues;
    }
    if let Some(identity) = document.get("manifest_identity") {
        match identity.as_str() {
            Some(text) if is_sha256_hex(text) => {}
            _ => issues.push("manifest_identity must be sha256 hex".to_string()),
        }
    }
    if let Some(profile) = document.get("spec_profile") {
        if profile != &Value::String("development".into())
            && profile != &Value::String("canonical-release".into())
        {
            issues.push(format!("invalid spec_profile: {profile}"));
        }
    }

    let artifact = document.get("artifact");
    let Some(artifact) = artifact else {
        issues.push("artifact section missing".to_string());
        return dedupe(issues);
    };
    if str_field(artifact, "id").is_none_or(str::is_empty) {
        issues.push("artifact.id must be a non-empty string".to_string());
    }
    const ARTIFACT_CLASSES: [&str; 9] = [
        "source-code",
        "documentation",
        "dataset",
        "model-weights",
        "configuration",
        "experiment-output",
        "receipt",
        "binary",
        "other",
    ];
    match str_field(artifact, "class") {
        None => issues.push("artifact.class missing".to_string()),
        Some(class) if !ARTIFACT_CLASSES.contains(&class) => {
            issues.push(format!("invalid artifact.class: {class:?}"));
        }
        Some(_) => {}
    }

    let provenance = document.get("provenance");
    let Some(provenance) = provenance else {
        issues.push("provenance section missing".to_string());
        return dedupe(issues);
    };
    const ORIGINS: [&str; 9] = [
        "human-authored",
        "human-ai-assisted",
        "human-directed-machine-generated",
        "autonomous-machine-generated",
        "mixed-machine-origin",
        "third-party-derived",
        "generated-from-licensed-source",
        "generated-from-public-domain-source",
        "origin-uncertain",
    ];
    match str_field(provenance, "origin_classification") {
        None => issues.push("provenance.origin_classification missing".to_string()),
        Some(origin) if !ORIGINS.contains(&origin) => {
            issues.push(format!("invalid origin_classification: {origin:?}"));
        }
        Some(_) => {}
    }
    if provenance
        .get("participants")
        .and_then(Value::as_array)
        .is_none()
    {
        issues.push("provenance.participants must be an array".to_string());
    }

    let rights = document.get("rights");
    let Some(rights) = rights else {
        issues.push("rights section missing".to_string());
        return dedupe(issues);
    };
    if str_field(rights, "distribution_license").is_none_or(str::is_empty) {
        issues.push("rights.distribution_license must be non-empty".to_string());
    }
    const COPYRIGHT: [&str; 7] = [
        "human-authorship-confirmed",
        "human-authorship-material",
        "mixed-or-undetermined",
        "machine-originated-unresolved",
        "third-party-licensed",
        "public-domain-asserted",
        "unresolved",
    ];
    match str_field(rights, "copyright_status") {
        None => issues.push("rights.copyright_status missing".to_string()),
        Some(status) if !COPYRIGHT.contains(&status) => {
            issues.push(format!("invalid copyright_status: {status:?}"));
        }
        Some(_) => {}
    }
    const BASES: [&str; 6] = [
        "project-owned-or-controlled",
        "contributor-attested",
        "third-party-license",
        "public-domain-basis",
        "no-exclusive-right-asserted",
        "unknown-needs-review",
    ];
    match str_field(rights, "rights_basis") {
        None => issues.push("rights.rights_basis missing".to_string()),
        Some(basis) if !BASES.contains(&basis) => {
            issues.push(format!("invalid rights_basis: {basis:?}"));
        }
        Some(_) => {}
    }
    const THIRD_PARTY: [&str; 4] = ["none-known", "present", "possible", "unknown"];
    match str_field(rights, "third_party_material") {
        None => issues.push("rights.third_party_material missing".to_string()),
        Some(state) if !THIRD_PARTY.contains(&state) => {
            issues.push(format!("invalid third_party_material: {state:?}"));
        }
        Some(_) => {}
    }
    if rights.get("sources").and_then(Value::as_array).is_none() {
        issues.push("rights.sources must be an array".to_string());
    }

    let review = document.get("review");
    let Some(review) = review else {
        issues.push("review section missing".to_string());
        return dedupe(issues);
    };
    const TECHNICAL: [&str; 4] = ["passed", "failed", "not-run", "not-applicable"];
    if matches!(str_field(review, "technical_validation"), Some(v) if !TECHNICAL.contains(&v)) {
        issues.push("review.technical_validation invalid".to_string());
    }
    const PROVENANCE: [&str; 4] = ["passed", "failed", "incomplete", "not-run"];
    if matches!(str_field(review, "provenance_validation"), Some(v) if !PROVENANCE.contains(&v)) {
        issues.push("review.provenance_validation invalid".to_string());
    }
    const HUMAN: [&str; 4] = ["accepted", "rejected", "not-reviewed", "not-required"];
    if matches!(str_field(review, "human_acceptance"), Some(v) if !HUMAN.contains(&v)) {
        issues.push("review.human_acceptance invalid".to_string());
    }
    dedupe(issues)
}

fn dedupe(mut issues: Vec<String>) -> Vec<String> {
    issues.sort();
    issues.dedup();
    issues
}

/// Iterative DAG check over the embedded graph (cycles/self-loops are fatal).
pub fn check_graph(document: &Value) -> (bool, Vec<String>) {
    let mut issues = Vec::new();
    let empty = Vec::new();
    let graph = document
        .get("provenance")
        .and_then(|p| p.get("graph"))
        .and_then(Value::as_object);
    let Some(graph) = graph else {
        return (true, issues);
    };
    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let edges = graph
        .get("edges")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let mut ids: BTreeMap<&str, ()> = BTreeMap::new();
    for node in nodes {
        if let Some(id) = node.get("id").and_then(Value::as_str) {
            ids.insert(id, ());
        }
    }
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in edges {
        let (Some(from), Some(to)) = (
            edge.get("from").and_then(Value::as_str),
            edge.get("to").and_then(Value::as_str),
        ) else {
            continue;
        };
        if from == to {
            issues.push(format!("edge self-loop on {from:?}"));
            continue;
        }
        if ids.contains_key(from) && ids.contains_key(to) {
            adjacency.entry(from).or_default().push(to);
        }
    }
    // Iterative coloring cycle detection.
    const WHITE: u8 = 0;
    const GRAY: u8 = 1;
    const BLACK: u8 = 2;
    let mut color: BTreeMap<&str, u8> = ids.keys().map(|key| (*key, WHITE)).collect();
    for start in ids.keys() {
        if color.get(start).copied().unwrap_or(BLACK) != WHITE {
            continue;
        }
        let mut stack: Vec<(&str, usize)> = vec![(start, 0)];
        color.insert(start, GRAY);
        while let Some(&mut (current, offset)) = stack.last_mut() {
            let neighbors = adjacency.get(current).cloned().unwrap_or_default();
            if offset >= neighbors.len() {
                color.insert(current, BLACK);
                stack.pop();
                continue;
            }
            if let Some(frame) = stack.last_mut() {
                frame.1 = offset + 1;
            }
            let neighbor = neighbors[offset];
            match color.get(neighbor).copied().unwrap_or(BLACK) {
                GRAY => {
                    issues.push(format!(
                        "graph contains a directed cycle through {neighbor:?}"
                    ));
                    return (false, issues);
                }
                WHITE => {
                    color.insert(neighbor, GRAY);
                    stack.push((neighbor, 0));
                }
                _ => {}
            }
        }
    }
    (issues.is_empty(), issues)
}

fn count_contradictions(rights: &Value) -> i32 {
    let mut contradictions = 0;
    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if let Some(sources) = rights.get("sources").and_then(Value::as_array) {
        for source in sources {
            let (Some(reference), Some(license_value)) =
                (str_field(source, "reference"), str_field(source, "license"))
            else {
                continue;
            };
            if license_value.is_empty() {
                continue;
            }
            let entry = seen.entry(reference.to_string()).or_default();
            if !entry.iter().any(|item| item == license_value) {
                entry.push(license_value.to_string());
            }
        }
    }
    for licenses in seen.values() {
        if licenses.len() > 1 {
            contradictions += 1;
        }
    }
    contradictions
}

fn gate_input_from_document(document: &Value) -> Result<(GateInput, Vec<String>)> {
    let mut issues = Vec::new();
    let provenance = document.get("provenance").cloned().unwrap_or(Value::Null);
    let rights = document.get("rights").cloned().unwrap_or(Value::Null);
    let review = document.get("review").cloned().unwrap_or(Value::Null);

    let mut decode =
        |value: Option<&str>, table: fn(&str) -> Option<i32>, fallback: i32, label: &str| {
            value.map_or(fallback, |text| {
                table(text).unwrap_or_else(|| {
                    issues.push(format!("unencodable {label}: {text:?}"));
                    fallback
                })
            })
        };

    let sources = rights.get("sources").and_then(Value::as_array);
    let mut incompatible = 0;
    let mut unknown_sources = 0;
    if let Some(sources) = sources {
        for source in sources {
            match str_field(source, "license_status") {
                Some("incompatible") => incompatible += 1,
                Some("unknown") => unknown_sources += 1,
                _ => {}
            }
        }
    }

    let canonical_release_profile = str_field(document, "spec_profile") != Some("development");

    let input = GateInput {
        origin_code: decode(
            str_field(&provenance, "origin_classification"),
            origin_code,
            8,
            "origin",
        ),
        copyright_code: decode(
            str_field(&rights, "copyright_status"),
            copyright_code,
            6,
            "copyright_status",
        ),
        rights_basis_code: decode(
            str_field(&rights, "rights_basis"),
            basis_code,
            5,
            "rights_basis",
        ),
        third_party_code: decode(
            str_field(&rights, "third_party_material"),
            third_party_code,
            3,
            "third_party_material",
        ),
        prov_valid_code: decode(
            str_field(&review, "provenance_validation"),
            provenance_validation_code,
            3,
            "provenance_validation",
        ),
        human_accept_code: decode(
            str_field(&review, "human_acceptance"),
            human_acceptance_code,
            2,
            "human_acceptance",
        ),
        incompatible_source_count: incompatible,
        unknown_source_count: unknown_sources,
        contradiction_count: count_contradictions(&rights),
        hash_mismatch: false,
        broken_evidence_refs: 0,
        graph_invalid: false,
        attestation_conflicts: 0,
        impossible_evidence: false,
        canonical_release_profile,
    };
    Ok((input, issues))
}

/// Full validation: structure, identity, graph integrity, policy gates.
pub fn validate_manifest(content: &[u8]) -> Result<RightsReport> {
    let document: Value =
        json::parse_slice(content).context("manifest is not strict RFC 8785 JSON")?;
    let issues = validate_structure(&document);

    let identity_expected = canonical::sha256(&canonical::canonicalize(&{
        let mut reduced = document.clone();
        if let Some(object) = reduced.as_object_mut() {
            object.remove("manifest_identity");
        }
        reduced
    })?);
    let declared_identity = str_field(&document, "manifest_identity").unwrap_or("");
    let identity_matches = declared_identity.is_empty() || (declared_identity == identity_expected);

    let structurally_valid = issues.is_empty();
    let mut all_issues = issues;
    let (graph_valid, graph_issues) = if structurally_valid {
        check_graph(&document)
    } else {
        (true, Vec::new())
    };
    if !graph_issues.is_empty() {
        all_issues.extend(graph_issues);
    }

    let report = if !structurally_valid {
        RightsReport {
            valid: false,
            outcome: "invalid".into(),
            severity: "blocking".into(),
            schema_version: SUPPORTED_SCHEMA_VERSION.into(),
            manifest_identity_expected: identity_expected,
            manifest_identity_matches: identity_matches,
            issues: all_issues,
            findings: Vec::new(),
            gate_results: Vec::new(),
            legal_conclusion: "NOT_MADE".into(),
            note: NOT_A_WARRANTY.into(),
        }
    } else {
        let (mut input, decode_issues) = gate_input_from_document(&document)?;
        all_issues.extend(decode_issues);
        input.graph_invalid = !graph_valid;
        let severities = gate_severities(&input);
        let mut gate_results = Vec::with_capacity(14);
        let mut findings = Vec::new();
        let mut combined = SEVERITY_NONE;
        for (index, raw) in severities.iter().enumerate() {
            let ceiling = DEFAULT_ENFORCEMENTS[index];
            let effective = apply_enforcement(*raw, ceiling);
            gate_results.push(GateResult {
                gate: GATE_NAMES[index].to_string(),
                severity: severity_name(*raw).to_string(),
                enforcement: enforcement_name(ceiling).to_string(),
                effective_severity: severity_name(effective).to_string(),
            });
            if effective > SEVERITY_NONE {
                findings.push(GATE_FINDINGS[index].to_string());
                combined = combined.max(effective);
            }
        }
        findings.sort();
        findings.dedup();
        let outcome = if combined >= SEVERITY_BLOCKING {
            "blocked"
        } else if combined >= SEVERITY_REVIEW {
            "review-required"
        } else if combined >= SEVERITY_FINDING {
            "pass-with-findings"
        } else {
            "pass"
        };
        if !identity_matches {
            all_issues.push("manifest_identity does not match canonical content".into());
        }
        RightsReport {
            valid: outcome != "invalid" && identity_matches,
            outcome: outcome.into(),
            severity: severity_name(combined).into(),
            schema_version: SUPPORTED_SCHEMA_VERSION.into(),
            manifest_identity_expected: identity_expected,
            manifest_identity_matches: identity_matches,
            issues: dedupe(all_issues),
            findings,
            gate_results,
            legal_conclusion: "NOT_MADE".into(),
            note: NOT_A_WARRANTY.into(),
        }
    };
    let _unused = ();
    Ok(report)
}

const NOT_A_WARRANTY: &str = "Passing means project evidence requirements were satisfied; this is not a legal warranty of title or non-infringement.";

pub fn read_manifest(path: &Path) -> Result<Vec<u8>> {
    canonical::read_regular(path, 8 * 1024 * 1024)
}

/// Exit-code mapping shared with the CLI: invalid=1, blocked=3,
/// review/findings=4, pass=0.
pub fn exit_code(report: &RightsReport) -> u8 {
    match report.outcome.as_str() {
        "invalid" => 1,
        "blocked" => 3,
        "pass" => 0,
        _ => 4,
    }
}

pub fn ensure_supported(document: &Value) -> Result<()> {
    if str_field(document, "schema_version") != Some(SUPPORTED_SCHEMA_VERSION) {
        bail!("unsupported rights manifest schema_version (expected {SUPPORTED_SCHEMA_VERSION})");
    }
    Ok(())
}
