use actix_web::{HttpResponse, Responder, get};
use alloy_primitives::Address;
use ream_api_types_beacon::responses::DataResponse;
use ream_api_types_common::error::ApiError;
use ream_consensus_misc::constants::beacon::{
    DOMAIN_AGGREGATE_AND_PROOF, FAR_FUTURE_EPOCH, INACTIVITY_PENALTY_QUOTIENT_BELLATRIX,
    MAX_COMMITTEES_PER_SLOT, SLOTS_PER_EPOCH,
};
use ream_network_spec::networks::{BeaconNetworkSpec, beacon_network_spec};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Serialize, Deserialize, Default)]
pub struct DepositContract {
    #[serde(with = "serde_utils::quoted_u64")]
    chain_id: u64,
    address: Address,
}

impl DepositContract {
    pub fn new(chain_id: u64, address: Address) -> Self {
        Self { chain_id, address }
    }
}

/// Build the `config/spec` body: every value the node was configured with, plus the preset
/// and domain constants it was compiled against.
///
/// Peers and tooling diff this against the other clients on the network to decide whether we
/// are even talking about the same chain, so omitting entries is not a harmless shortcut —
/// assertoor reports "invalid node specs: spec mismatch" and marks the node offline while it
/// is happily following the chain.
fn build_spec(network_spec: &BeaconNetworkSpec) -> Result<Value, ApiError> {
    let mut spec = serde_json::to_value(network_spec)
        .map_err(|err| ApiError::InternalError(format!("Failed to encode network spec: {err}")))?;

    let Value::Object(entries) = &mut spec else {
        return Err(ApiError::InternalError(
            "Network spec did not encode as an object".into(),
        ));
    };

    // Expose the standard Beacon API name and unit.
    entries.remove("SLOT_DURATION_MS");
    entries.insert(
        "TERMINAL_TOTAL_DIFFICULTY".into(),
        Value::String(network_spec.terminal_total_difficulty.to_string()),
    );
    entries.insert(
        "DEPOSIT_NETWORK_ID".into(),
        json!(network_spec.deposit_network_id),
    );

    for (key, value) in [
        ("SECONDS_PER_SLOT", json!(network_spec.seconds_per_slot())),
        ("SLOTS_PER_EPOCH", json!(SLOTS_PER_EPOCH)),
        ("MAX_COMMITTEES_PER_SLOT", json!(MAX_COMMITTEES_PER_SLOT)),
        (
            "INACTIVITY_PENALTY_QUOTIENT",
            json!(INACTIVITY_PENALTY_QUOTIENT_BELLATRIX),
        ),
        (
            "DOMAIN_AGGREGATE_AND_PROOF",
            json!(DOMAIN_AGGREGATE_AND_PROOF),
        ),
        // Not a fork we implement. Reporting it as far future is how a client says
        // "not scheduled", and leaving it out instead reads as a disagreement.
        ("GLOAS_FORK_EPOCH", json!(FAR_FUTURE_EPOCH)),
    ] {
        entries.entry(key).or_insert(value);
    }

    // Match the quoted integers returned by other clients, including nested values.
    quote_integers(&mut spec);

    Ok(spec)
}

fn quote_integers(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(quote_integers),
        Value::Object(entries) => entries.values_mut().for_each(quote_integers),
        Value::Number(number) if number.is_i64() || number.is_u64() => {
            *value = Value::String(number.to_string());
        }
        _ => {}
    }
}

/// Called by `config/spec` to get specification configuration.
#[get("config/spec")]
pub async fn get_config_spec() -> Result<impl Responder, ApiError> {
    Ok(HttpResponse::Ok().json(DataResponse::new(build_spec(&beacon_network_spec())?)))
}

/// Called by `/deposit_contract` to get the Genesis Config of Beacon Chain.
#[get("config/deposit_contract")]
pub async fn get_config_deposit_contract() -> Result<impl Responder, ApiError> {
    let network_spec = beacon_network_spec();
    Ok(
        HttpResponse::Ok().json(DataResponse::new(DepositContract::new(
            network_spec.deposit_chain_id,
            network_spec.deposit_contract_address,
        ))),
    )
}

/// Called by `config/fork_schedule` to get fork schedule
#[get("config/fork_schedule")]
pub async fn get_fork_schedule() -> Result<impl Responder, ApiError> {
    Ok(HttpResponse::Ok().json(DataResponse::new(beacon_network_spec().fork_schedule())))
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;
    use ream_consensus_misc::blob_parameters::BlobParameters;
    use ream_network_spec::networks::DEV;

    use super::*;

    #[test]
    fn build_spec_uses_beacon_api_names_and_quotes_nested_integers() {
        let mut network_spec = DEV.as_ref().clone();
        network_spec.terminal_total_difficulty =
            U256::from_str_radix("58750000000000000000000", 10).expect("valid TTD");
        network_spec.deposit_chain_id = 1;
        network_spec.deposit_network_id = 2;
        network_spec.blob_schedule = vec![BlobParameters {
            epoch: 9,
            max_blobs_per_block: 12,
        }];

        let spec = build_spec(&network_spec).expect("builds spec");

        assert!(spec.get("SLOT_DURATION_MS").is_none());
        assert_eq!(spec["SECONDS_PER_SLOT"], "12");
        assert_eq!(spec["TERMINAL_TOTAL_DIFFICULTY"], "58750000000000000000000");
        assert_eq!(spec["DEPOSIT_CHAIN_ID"], "1");
        assert_eq!(spec["DEPOSIT_NETWORK_ID"], "2");
        assert_eq!(spec["BLOB_SCHEDULE"][0]["EPOCH"], "9");
        assert_eq!(spec["BLOB_SCHEDULE"][0]["MAX_BLOBS_PER_BLOCK"], "12");
    }
}
