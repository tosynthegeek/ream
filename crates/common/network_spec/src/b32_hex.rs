use alloy_primitives::aliases::B32;
use serde::{Deserializer, Serializer};
use serde_utils::hex::{self, PrefixedHexVisitor};

pub fn serialize<S>(hash: &B32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // `hex::encode` already prefixes with `0x`; adding another produces `0x0x…`, which every
    // consumer rejects as a malformed fork version.
    serializer.serialize_str(&hex::encode(hash))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<B32, D::Error>
where
    D: Deserializer<'de>,
{
    let decoded = deserializer.deserialize_str(PrefixedHexVisitor)?;
    B32::try_from(decoded.as_slice()).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::fixed_bytes;

    use super::*;

    /// Fork versions travel as `0x`-prefixed hex exactly once. A doubled prefix still looks
    /// like a hex string at a glance, so it survives eyeballing and only shows up as peers
    /// and tooling rejecting our whole config as malformed.
    #[test]
    fn test_serialize_prefixes_once() {
        let mut buffer = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut buffer);
        serialize(&fixed_bytes!("0x10000038"), &mut serializer).expect("serializes");

        assert_eq!(String::from_utf8(buffer).expect("utf8"), "\"0x10000038\"");
    }
}
