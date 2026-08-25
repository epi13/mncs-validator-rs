//! `mncs-rs` independent offline validator CLI.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use mncs_validator_rs::{attestation, canonical, corpus, package, trust, validation};
use serde::Serialize;
use serde_json::{Value, json};

const EXIT_INVALID: u8 = 1;
const EXIT_OPERATIONAL: u8 = 2;
const EXIT_UNTRUSTED: u8 = 3;

#[derive(Debug, Parser)]
#[command(
    name = "mncs-rs",
    version,
    about = "Independent offline MNCS validator"
)]
struct Cli {
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Version,
    Canonicalize {
        file: PathBuf,
    },
    Hash {
        file: PathBuf,
    },
    Validate {
        manifest: PathBuf,
    },
    ValidateBundle {
        directory: PathBuf,
    },
    VerifyAttestation {
        envelope: PathBuf,
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        contract: Option<String>,
        #[arg(long)]
        environment: Option<String>,
        #[arg(long = "at")]
        evaluation_time: Option<String>,
    },
    TrustEvaluate {
        envelope: PathBuf,
        policy: PathBuf,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        contract: Option<String>,
        #[arg(long)]
        environment: Option<String>,
        #[arg(long = "at")]
        evaluation_time: Option<String>,
    },
    InspectPackage {
        file: PathBuf,
    },
    VerifyPackage {
        file: PathBuf,
    },
    Corpus {
        path: PathBuf,
    },
    /// Validate an MNCS Rights & Provenance v0.2 manifest and evaluate
    /// canonical release policy (distinct from technical-correctness checks).
    RightsValidate {
        manifest: PathBuf,
    },
}

fn emit<T: Serialize>(value: &T, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        println!("{}", serde_json::to_string(value)?);
    }
    Ok(())
}

fn evaluation_time(value: Option<&str>) -> Result<DateTime<Utc>> {
    value.map_or_else(
        || Ok(Utc::now()),
        |text| {
            Ok(DateTime::parse_from_rfc3339(text)
                .with_context(|| format!("invalid evaluation time: {text}"))?
                .with_timezone(&Utc))
        },
    )
}

fn run(cli: Cli) -> Result<u8> {
    match cli.command {
        Command::Version => {
            let result = json!({
                "package": "mncs-validator-rs",
                "package_version": env!("CARGO_PKG_VERSION"),
                "binary": "mncs-rs",
                "mncs_version": "0.2",
                "current_schema_version": "0.2",
                "supported_schema_versions": ["0.1", "0.1.1", "0.2"],
                "corpus_version": "0.2.0",
                "offline": true,
                "executes_evidence": false
            });
            emit(&result, cli.json)?;
            Ok(0)
        }
        Command::Canonicalize { file } => {
            let content = canonical::canonicalize_file(&file)?;
            if cli.json {
                emit(
                    &json!({
                        "canonical_utf8": String::from_utf8(content.clone())?,
                        "canonical_hex": hex::encode(&content),
                        "sha256": canonical::sha256(&content)
                    }),
                    true,
                )?;
            } else {
                println!("{}", String::from_utf8(content)?);
            }
            Ok(0)
        }
        Command::Hash { file } => {
            let hash = canonical::hash_file(&file)?;
            if cli.json {
                emit(&json!({"path": file, "sha256": hash}), true)?;
            } else {
                println!("{hash}");
            }
            Ok(0)
        }
        Command::Validate { manifest } => {
            let report = validation::validate_manifest(&manifest)?;
            emit(&report, cli.json)?;
            Ok(if report.valid { 0 } else { EXIT_INVALID })
        }
        Command::ValidateBundle { directory } => {
            let report = validation::validate_bundle(&directory)?;
            emit(&report, cli.json)?;
            Ok(if report.valid { 0 } else { EXIT_INVALID })
        }
        Command::VerifyAttestation {
            envelope,
            keys,
            subject,
            contract,
            environment,
            evaluation_time: at,
        } => {
            let envelope = attestation::load(&envelope)?;
            let keys = keys
                .iter()
                .map(|path| attestation::load(path))
                .collect::<Result<Vec<Value>>>()?;
            let result = attestation::verify(
                &envelope,
                &keys,
                subject.as_deref(),
                contract.as_deref(),
                environment.as_deref(),
                evaluation_time(at.as_deref())?,
            )?;
            let valid = result.cryptographically_valid && !result.expired;
            emit(&result, cli.json)?;
            Ok(if valid { 0 } else { EXIT_INVALID })
        }
        Command::TrustEvaluate {
            envelope,
            policy,
            subject,
            contract,
            environment,
            evaluation_time: at,
        } => {
            let result = trust::evaluate(
                &attestation::load(&envelope)?,
                &attestation::load(&policy)?,
                subject.as_deref(),
                contract.as_deref(),
                environment.as_deref(),
                evaluation_time(at.as_deref())?,
            )?;
            let trusted = result.trusted;
            emit(&result, cli.json)?;
            Ok(if trusted { 0 } else { EXIT_UNTRUSTED })
        }
        Command::InspectPackage { file } => {
            let report = package::verify(&file, false)?;
            emit(&report, cli.json)?;
            Ok(if report.valid { 0 } else { EXIT_INVALID })
        }
        Command::VerifyPackage { file } => {
            let report = package::verify(&file, true)?;
            emit(&report, cli.json)?;
            Ok(if report.valid { 0 } else { EXIT_INVALID })
        }
        Command::Corpus { path } => {
            let report = corpus::run(&path)?;
            let valid = report.mismatch_count == 0 && report.unsupported_count == 0;
            emit(&report, true)?;
            Ok(if valid { 0 } else { EXIT_INVALID })
        }
        Command::RightsValidate { manifest } => {
            use mncs_validator_rs::rights;
            let content = rights::read_manifest(&manifest)?;
            let report = rights::validate_manifest(&content)?;
            emit(&report, cli.json)?;
            Ok(rights::exit_code(&report))
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("mncs-rs: error: {error:#}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}
