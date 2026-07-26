# mncs-validator-rs

Independent, offline Rust validator for
[MNCS 0.2](https://github.com/epi13/machine-native-complexity-standard).
It does not invoke, embed, or wrap the Python validator and never executes evidence
binaries.

## Coverage

- strict UTF-8 JSON with duplicate-key, nonfinite, and unsafe-integer rejection;
- RFC 8785 JCS bytes and SHA-256 identities;
- schemas 0.1, 0.1.1, and 0.2 with PASS/FAIL/UNKNOWN preservation;
- stable file hashes and safe relative evidence paths;
- Ed25519 DSSE-compatible signature verification;
- deterministic trust thresholds, roles, scopes, validity, and revocation;
- bounded deterministic `.mncs` package inspection and verification;
- versioned cross-implementation corpus with explicit unsupported reporting.

`validate` checks the normative interoperable subset and content bindings. It does not
implement every Python reporting/comparison convenience command; unsupported
functionality is documented and is never reported as PASS.

## Build and use

```bash
cargo build --release
./target/release/mncs-rs version
./target/release/mncs-rs canonicalize FILE
./target/release/mncs-rs hash FILE
./target/release/mncs-rs validate MANIFEST
./target/release/mncs-rs validate-bundle DIRECTORY
./target/release/mncs-rs verify-attestation ENVELOPE --key PUBLIC_KEY
./target/release/mncs-rs trust-evaluate ENVELOPE POLICY
./target/release/mncs-rs inspect-package FILE.mncs
./target/release/mncs-rs verify-package FILE.mncs
./target/release/mncs-rs corpus fixtures/interoperability/corpus.json
```

Use `--json` globally where applicable.

## Stable exits

- 0: requested validation/verification succeeded;
- 1: invalid input, failed integrity, or corpus disagreement;
- 2: operational error such as missing files or unreadable input;
- 3: cryptographically valid but untrusted under the supplied policy.

## Assurance boundary

A valid signature proves that a key signed bytes. It does not prove correctness,
safety, performance, or honesty. Verification is offline. The binary opens no network
connection, performs no provider launch, and never imports or executes evidence.

MNCS is open, experimental, community-developed, tool-neutral, non-accredited, and
licensed under Apache-2.0.
