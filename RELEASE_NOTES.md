# mncs-validator-rs 0.2.0 — Independent MNCS Validator

This first release independently validates the MNCS 0.2 interoperability subset:
RFC 8785 canonical JSON, SHA-256 identities, schemas 0.1/0.1.1/0.2,
PASS/FAIL/UNKNOWN, Ed25519 DSSE attestations, deterministic trust thresholds and
revocation, safe `.mncs` packages, and the shared 0.2.0 golden corpus.

The validator is offline, never executes evidence, and does not call the Python
implementation. A valid signature authenticates bytes; it is not a correctness or
safety proof. See README and SECURITY for limits.
