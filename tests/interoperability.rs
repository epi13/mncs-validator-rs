// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use mncs_validator_rs::{attestation, canonical, corpus, package, trust};

#[test]
fn shared_corpus_has_complete_agreement() -> anyhow::Result<()> {
    let report = corpus::run(Path::new("fixtures/interoperability/corpus.json"))?;
    assert_eq!(report.vector_count, 32);
    assert_eq!(
        report.mismatch_count,
        0,
        "corpus mismatches: {:#?}",
        report
            .results
            .iter()
            .filter(|result| !result.matches)
            .collect::<Vec<_>>()
    );
    assert_eq!(report.unsupported_count, 0);
    Ok(())
}

#[test]
fn canonical_hash_matches_python_vector() -> anyhow::Result<()> {
    let content = canonical::canonicalize_file(Path::new(
        "fixtures/interoperability/vectors/canonical-json/numbers/original.json",
    ))?;
    assert_eq!(
        canonical::sha256(&content),
        "f891d34a27ac35713e66dbd418c87d8e9f4f9d406fd0cd7a4b5b8f97b9e52b1f"
    );
    Ok(())
}

#[test]
fn signature_and_trust_are_independent() -> anyhow::Result<()> {
    let envelope = attestation::load(Path::new(
        "fixtures/interoperability/fixtures/attestations/valid.envelope.json",
    ))?;
    let key = attestation::load(Path::new(
        "fixtures/interoperability/fixtures/attestations/public-key.json",
    ))?;
    let now =
        chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")?.with_timezone(&chrono::Utc);
    let verification = attestation::verify(&envelope, &[key], None, None, None, now)?;
    assert!(verification.cryptographically_valid);
    let policy = attestation::load(Path::new(
        "fixtures/interoperability/fixtures/attestations/revoked-policy.json",
    ))?;
    let evaluation = trust::evaluate(&envelope, &policy, None, None, None, now)?;
    assert!(evaluation.cryptographically_valid);
    assert!(!evaluation.trusted);
    Ok(())
}

#[test]
fn malicious_packages_are_rejected() -> anyhow::Result<()> {
    for name in ["traversal.mncs", "symlink.mncs", "oversized.mncs"] {
        let path = Path::new("fixtures/interoperability/fixtures/packages").join(name);
        assert!(!package::verify(&path, true)?.valid, "{name}");
    }
    Ok(())
}
