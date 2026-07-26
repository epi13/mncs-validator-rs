//! RFC 8785 canonical JSON and SHA-256 identities.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::json;

pub const MAX_JSON_BYTES: u64 = 10 * 1024 * 1024;

pub fn read_regular(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let link_metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {}", path.display()))?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        bail!("not a regular non-symlink file: {}", path.display());
    }
    if link_metadata.len() > maximum {
        bail!("file exceeds {maximum} bytes: {}", path.display());
    }
    let mut file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > maximum {
        bail!("unsafe file type or size: {}", path.display());
    }
    let mut content = Vec::with_capacity(usize::try_from(before.len())?);
    (&mut file).take(maximum + 1).read_to_end(&mut content)?;
    if u64::try_from(content.len())? > maximum {
        bail!("file grew beyond {maximum} bytes: {}", path.display());
    }
    let after = file.metadata()?;
    if before.len() != after.len() || before.modified()? != after.modified()? {
        bail!("file changed while reading: {}", path.display());
    }
    Ok(content)
}

pub fn canonicalize_slice(content: &[u8]) -> Result<Vec<u8>> {
    canonicalize(&json::parse_slice(content)?)
}

pub fn canonicalize(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_jcs::to_vec(value)?)
}

pub fn canonicalize_file(path: &Path) -> Result<Vec<u8>> {
    canonicalize_slice(&read_regular(path, MAX_JSON_BYTES)?)
}

pub fn sha256(content: &[u8]) -> String {
    hex::encode(Sha256::digest(content))
}

pub fn mncs_sha256(content: &[u8]) -> String {
    format!("sha256:{}", sha256(content))
}

pub fn hash_file(path: &Path) -> Result<String> {
    Ok(mncs_sha256(&read_regular(path, 64 * 1024 * 1024)?))
}

#[cfg(test)]
mod tests {
    use super::canonicalize_slice;

    #[test]
    fn canonicalizes_numbers_and_order() -> anyhow::Result<()> {
        let actual = canonicalize_slice(r#"{"z":-0.0,"a":"€","n":1e+30}"#.as_bytes())?;
        assert_eq!(actual, r#"{"a":"€","n":1e+30,"z":0}"#.as_bytes());
        Ok(())
    }
}
