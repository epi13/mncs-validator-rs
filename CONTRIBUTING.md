# Contributing

Open an issue before broad semantic changes. Pull requests must keep the public exits
stable, add focused tests, update corpus expectations only with evidence, and pass:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
./scripts/run-corpus
```

Do not add network access, evidence execution, hidden trust roots, private keys, or
claims that unsupported behavior passed.
