//! Strict JSON parsing with duplicate-key and numeric-domain rejection.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug)]
enum StrictValue {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("strict RFC 8785 JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if value.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(E::custom(
                "integer exceeds the interoperable JCS safe domain",
            ));
        }
        Ok(StrictValue::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if value > MAX_SAFE_INTEGER {
            return Err(E::custom(
                "integer exceeds the interoperable JCS safe domain",
            ));
        }
        Ok(StrictValue::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if !value.is_finite() {
            return Err(E::custom("nonfinite JSON number"));
        }
        Number::from_f64(value)
            .map(StrictValue::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(StrictValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value);
        }
        Ok(StrictValue::Array(values))
    }

    fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some((key, value)) = entries.next_entry::<String, StrictValue>()? {
            if values.insert(key.clone(), value).is_some() {
                return Err(A::Error::custom(format!(
                    "duplicate JSON object key: {key}"
                )));
            }
        }
        Ok(StrictValue::Object(values))
    }
}

impl From<StrictValue> for Value {
    fn from(value: StrictValue) -> Self {
        match value {
            StrictValue::Null => Self::Null,
            StrictValue::Bool(value) => Self::Bool(value),
            StrictValue::Number(value) => Self::Number(value),
            StrictValue::String(value) => Self::String(value),
            StrictValue::Array(values) => Self::Array(values.into_iter().map(Self::from).collect()),
            StrictValue::Object(values) => {
                let mapped = values
                    .into_iter()
                    .map(|(key, value)| (key, Self::from(value)))
                    .collect::<Map<String, Value>>();
                Self::Object(mapped)
            }
        }
    }
}

pub fn parse_slice(content: &[u8]) -> Result<Value> {
    std::str::from_utf8(content)?;
    let mut deserializer = serde_json::Deserializer::from_slice(content);
    let value = StrictValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value.into())
}

pub fn object(content: &[u8]) -> Result<Map<String, Value>> {
    match parse_slice(content)? {
        Value::Object(value) => Ok(value),
        _ => bail!("expected a JSON object"),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_slice;

    #[test]
    fn rejects_duplicate_keys_and_unsafe_integers() {
        assert!(parse_slice(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse_slice(b"9007199254740992").is_err());
        assert!(parse_slice(b"9007199254740991").is_ok());
    }
}
