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

    for (key, value) in [
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
        ("DEPOSIT_NETWORK_ID", json!(network_spec.deposit_chain_id)),
        // Not a fork we implement. Reporting it as far future is how a client says
        // "not scheduled", and leaving it out instead reads as a disagreement.
        ("GLOAS_FORK_EPOCH", json!(FAR_FUTURE_EPOCH)),
    ] {
        entries.entry(key).or_insert(value);
    }

    // The Beacon API quotes every integer, so that a JSON parser without 64-bit integers
    // cannot silently round one.
    for value in entries.values_mut() {
        if let Some(number) = value.as_u64() {
            *value = Value::String(number.to_string());
        }
    }

    Ok(spec)
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
