use std::{collections::HashSet, sync::Arc};

use actix_web::{
    HttpResponse, Responder, get, post,
    web::{Data, Json, Path, Query},
};
use alloy_primitives::{Address, B256, aliases::B32};
use ream_api_types_beacon::{
    block::{FullBlockData, ProduceBlockData, ProduceBlockResponse},
    committee::{BeaconCommitteeSubscription, SyncCommitteeSubscription},
    id::ValidatorID,
    query::{AttestationQuery, IdQuery, StatusQuery, SyncCommitteeContributionQuery},
    request::ValidatorsPostRequest,
    responses::{BeaconResponse, DataResponse, DataVersionedResponse},
    validator::{ValidatorBalance, ValidatorData, ValidatorStatus},
};
use ream_api_types_common::{error::ApiError, id::ID};
use ream_bls::{BLSSignature, PublicKey, traits::Verifiable};
use ream_consensus_beacon::{
    attestation::Attestation,
    attester_slashing::AttesterSlashing,
    beacon_committee_selection::BeaconCommitteeSelection,
    blob_sidecar::BlobIdentifier,
    bls_to_execution_change::SignedBLSToExecutionChange,
    electra::{
        beacon_block::BeaconBlock,
        beacon_block_body::BeaconBlockBody,
        beacon_state::{BeaconState, fork_name_at_epoch},
        blinded_beacon_block::BlindedBeaconBlock,
        blinded_beacon_block_body::BlindedBeaconBlockBody,
    },
    proposer_slashing::ProposerSlashing,
    sync_aggregate::SyncAggregate,
    sync_committe_selection::SyncCommitteeSelection,
    voluntary_exit::SignedVoluntaryExit,
};
use ream_consensus_misc::{
    attestation_data::AttestationData,
    checkpoint::Checkpoint,
    constants::beacon::{
        DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_BEACON_ATTESTER, DOMAIN_RANDAO, DOMAIN_SYNC_COMMITTEE,
        FULU_FORK_EPOCH, MAX_COMMITTEES_PER_SLOT, PROPOSER_REWARD_QUOTIENT, SLOTS_PER_EPOCH,
        SYNC_COMMITTEE_PROPOSER_REWARD_QUOTIENT, WHISTLEBLOWER_REWARD_QUOTIENT,
    },
    deposit::Deposit,
    fork_name::ForkName,
    misc::{
        compute_domain, compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch,
    },
    polynomial_commitments::{kzg_commitment::KZGCommitment, kzg_proof::KZGProof},
    validator::Validator,
};
use ream_events_beacon::{
    BeaconEvent, contribution_and_proof::SignedContributionAndProof,
    event::sync_committee::ContributionAndProofEvent,
};
use ream_execution_engine::ExecutionEngine;
use ream_execution_rpc_types::{
    forkchoice_update::{ForkchoiceStateV1, PayloadAttributesV3},
    get_payload::Payload,
};
use ream_fork_choice_beacon::store::Store;
use ream_network_manager::gossipsub::validate::sync_committee_contribution_and_proof::get_sync_subcommittee_pubkeys;
use ream_network_manager::p2p_sender::P2PSender;
use ream_network_spec::networks::beacon_network_spec;
use ream_operation_pool::OperationPool;
use ream_p2p::gossipsub::beacon::topics::{GossipTopic, GossipTopicKind};
use ream_storage::{
    db::beacon::BeaconDB,
    tables::table::{CustomTable, REDBTable},
};
use ream_sync_committee_pool::SyncCommitteePool;
use ream_validator_beacon::{
    aggregate_and_proof::SignedAggregateAndProof,
    attestation::{compute_on_chain_aggregate, compute_subnet_for_attestation},
    builder::{
        builder_bid::SignedBuilderBid, builder_client::BuilderClient,
        validator_registration::SignedValidatorRegistrationV1,
    },
    constants::{
        DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_SELECTION_PROOF,
        DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, SYNC_COMMITTEE_SUBNET_COUNT,
    },
    execution_requests::get_execution_requests,
    sync_committee::{SyncAggregatorSelectionData, is_sync_committee_aggregator},
};
use serde::Serialize;
use ssz_types::{
    VariableList,
    typenum::{U1, U8, U16},
};
use tokio::sync::broadcast;
use tree_hash::TreeHash;

use super::state::get_state_from_id;

///  For slots in Electra and later, this AttestationData must have a committee_index of 0.
const ELECTRA_COMMITTEE_INDEX: u64 = 0;
const MAX_VALIDATOR_COUNT: usize = 100;

fn gossip_fork_digest(state: &BeaconState) -> B32 {
    beacon_network_spec().fork_digest(FULU_FORK_EPOCH, state.genesis_validators_root)
}

fn build_validator_balances(
    validators: &[(Validator, u64)],
    filter_ids: Option<&Vec<ValidatorID>>,
) -> Vec<ValidatorBalance> {
    // Turn the optional Vec<ValidatorID> into an optional HashSet for O(1) lookups
    let filtered_ids = filter_ids.map(|ids| ids.iter().collect::<HashSet<_>>());

    validators
        .iter()
        .enumerate()
        .filter(|(idx, (validator, _))| match &filtered_ids {
            Some(ids) => {
                ids.contains(&ValidatorID::Index(*idx as u64))
                    || ids.contains(&ValidatorID::Address(validator.public_key.clone()))
            }
            None => true,
        })
        .map(|(idx, (_, balance))| ValidatorBalance {
            index: idx as u64,
            balance: *balance,
        })
        .collect()
}

#[get("/beacon/states/{state_id}/validators/{validator_id}")]
pub async fn get_validator_from_state(
    db: Data<BeaconDB>,
    param: Path<(ID, ValidatorID)>,
) -> Result<impl Responder, ApiError> {
    let (state_id, validator_id) = param.into_inner();
    let state = get_state_from_id(state_id, &db).await?;

    let (index, validator) = {
        match &validator_id {
            ValidatorID::Index(i) => match state.validators.get(*i as usize) {
                Some(validator) => (*i as usize, validator.to_owned()),
                None => {
                    return Err(ApiError::NotFound(format!(
                        "Validator not found for index: {i}"
                    )));
                }
            },
            ValidatorID::Address(public_key) => {
                match find_validator_by_public_key(&state, public_key) {
                    Some((i, validator)) => (i, validator.to_owned()),
                    None => {
                        return Err(ApiError::NotFound(format!(
                            "Validator not found for public_key: {public_key:?}"
                        )))?;
                    }
                }
            }
        }
    };

    let balance = state.balances.get(index).ok_or(ApiError::NotFound(format!(
        "Validator not found for index: {index}"
    )))?;

    let status = validator_status(&validator, &db).await?;

    Ok(
        HttpResponse::Ok().json(BeaconResponse::new(ValidatorData::new(
            index as u64,
            *balance,
            status,
            validator,
        ))),
    )
}

pub async fn validator_status(
    validator: &Validator,
    db: &BeaconDB,
) -> Result<ValidatorStatus, ApiError> {
    let highest_slot = db
        .slot_index_provider()
        .get_highest_slot()
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to get_highest_slot, error: {err:?}"))
        })?
        .ok_or(ApiError::NotFound(
            "Failed to find highest slot".to_string(),
        ))?;
    let state = get_state_from_id(ID::Slot(highest_slot), db).await?;
    let current_epoch = state.get_current_epoch();

    // Check if validator is pending (not yet activated)
    if validator.activation_epoch > current_epoch {
        Ok(ValidatorStatus::Pending)
    }
    // Check if validator has exited
    else if validator.exit_epoch <= current_epoch {
        Ok(ValidatorStatus::Offline)
    }
    // Validator is active
    else {
        Ok(ValidatorStatus::ActiveOngoing)
    }
}

/// Helper function to find validator by public key in state
fn find_validator_by_public_key<'a>(
    state: &'a BeaconState,
    public_key: &PublicKey,
) -> Option<(usize, &'a Validator)> {
    state
        .validators
        .iter()
        .enumerate()
        .find(|(_, v)| v.public_key == *public_key)
}

#[get("/beacon/states/{state_id}/validators")]
pub async fn get_validators_from_state(
    db: Data<BeaconDB>,
    state_id: Path<ID>,
    id_query: Query<IdQuery>,
    status_query: Query<StatusQuery>,
) -> Result<impl Responder, ApiError> {
    if let Some(validator_ids) = &id_query.id
        && validator_ids.len() >= MAX_VALIDATOR_COUNT
    {
        return Err(ApiError::TooManyValidatorsIds);
    }

    let state = get_state_from_id(state_id.into_inner(), &db).await?;
    let mut validators_data = Vec::new();
    let mut validator_indices_to_process = Vec::new();

    // First, collect all the validator indices we need to process
    if let Some(validator_ids) = &id_query.id {
        for validator_id in validator_ids {
            let (index, _) = {
                match validator_id {
                    ValidatorID::Index(i) => match state.validators.get(*i as usize) {
                        Some(validator) => (*i as usize, validator.to_owned()),
                        None => {
                            return Err(ApiError::NotFound(format!(
                                "Validator not found for index: {i}"
                            )))?;
                        }
                    },
                    ValidatorID::Address(public_key) => {
                        match find_validator_by_public_key(&state, public_key) {
                            Some((i, validator)) => (i, validator.to_owned()),
                            None => {
                                return Err(ApiError::NotFound(format!(
                                    "Validator not found for public_key: {public_key:?}"
                                )))?;
                            }
                        }
                    }
                }
            };
            validator_indices_to_process.push(index);
        }
    } else {
        validator_indices_to_process = (0..state.validators.len()).collect();
    }

    for index in validator_indices_to_process {
        let validator = &state.validators[index];

        let status = validator_status(validator, &db).await?;

        if status_query.has_status() && !status_query.contains_status(&status) {
            continue;
        }

        let balance = state.balances.get(index).ok_or(ApiError::NotFound(format!(
            "Validator not found for index: {index}"
        )))?;

        validators_data.push(ValidatorData::new(
            index as u64,
            *balance,
            status,
            validator.clone(),
        ));
    }

    Ok(HttpResponse::Ok().json(BeaconResponse::new(validators_data)))
}

#[post("/beacon/states/{state_id}/validators")]
pub async fn post_validators_from_state(
    db: Data<BeaconDB>,
    state_id: Path<ID>,
    request: Json<ValidatorsPostRequest>,
) -> Result<impl Responder, ApiError> {
    let ValidatorsPostRequest { ids, statuses, .. } = request.into_inner();
    let status_query = StatusQuery { status: statuses };

    let state = get_state_from_id(state_id.into_inner(), &db).await?;
    let mut validators_data = Vec::new();
    let mut validator_indices_to_process = Vec::new();

    // First, collect all the validator indices we need to process
    if let Some(validator_ids) = &ids {
        for validator_id in validator_ids {
            let (index, _) = {
                match validator_id {
                    ValidatorID::Index(i) => match state.validators.get(*i as usize) {
                        Some(validator) => (*i as usize, validator.to_owned()),
                        None => {
                            return Err(ApiError::NotFound(format!(
                                "Validator not found for index: {i}"
                            )))?;
                        }
                    },
                    ValidatorID::Address(public_key) => {
                        match find_validator_by_public_key(&state, public_key) {
                            Some((i, validator)) => (i, validator.to_owned()),
                            None => {
                                return Err(ApiError::NotFound(format!(
                                    "Validator not found for public_key: {public_key:?}"
                                )))?;
                            }
                        }
                    }
                }
            };
            validator_indices_to_process.push(index);
        }
    } else {
        validator_indices_to_process = (0..state.validators.len()).collect();
    }

    for index in validator_indices_to_process {
        let validator = &state.validators[index];

        let status = validator_status(validator, &db).await?;

        if status_query.has_status() && !status_query.contains_status(&status) {
            continue;
        }

        let balance = state.balances.get(index).ok_or(ApiError::NotFound(format!(
            "Validator not found for index: {index}"
        )))?;

        validators_data.push(ValidatorData::new(
            index as u64,
            *balance,
            status,
            validator.clone(),
        ));
    }

    Ok(HttpResponse::Ok().json(BeaconResponse::new(validators_data)))
}

#[derive(Debug, Serialize)]
struct ValidatorIdentity {
    #[serde(with = "serde_utils::quoted_u64")]
    index: u64,
    public_key: PublicKey,
    #[serde(with = "serde_utils::quoted_u64")]
    activation_epoch: u64,
}

#[post("/beacon/states/{state_id}/validator_identities")]
pub async fn post_validator_identities_from_state(
    db: Data<BeaconDB>,
    state_id: Path<ID>,
    validator_ids: Json<Vec<ValidatorID>>,
) -> Result<impl Responder, ApiError> {
    let state = get_state_from_id(state_id.into_inner(), &db).await?;

    let validator_ids_set: HashSet<ValidatorID> = validator_ids.into_inner().into_iter().collect();

    let validator_identities: Vec<ValidatorIdentity> = state
        .validators
        .iter()
        .enumerate()
        .filter_map(|(index, validator)| {
            if validator_ids_set.contains(&ValidatorID::Index(index as u64))
                || validator_ids_set.contains(&ValidatorID::Address(validator.public_key.clone()))
            {
                Some(ValidatorIdentity {
                    index: index as u64,
                    public_key: validator.public_key.clone(),
                    activation_epoch: validator.activation_epoch,
                })
            } else {
                None
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(BeaconResponse::new(validator_identities)))
}

#[get("/beacon/states/{state_id}/validator_balances")]
pub async fn get_validator_balances_from_state(
    state_id: Path<ID>,
    query: Query<IdQuery>,
    db: Data<BeaconDB>,
) -> Result<impl Responder, ApiError> {
    let state = get_state_from_id(state_id.into_inner(), &db).await?;
    Ok(
        HttpResponse::Ok().json(BeaconResponse::new(build_validator_balances(
            &state
                .validators
                .into_iter()
                .zip(state.balances.into_iter())
                .collect::<Vec<_>>(),
            query.id.as_ref(),
        ))),
    )
}

#[post("/beacon/states/{state_id}/validator_balances")]
pub async fn post_validator_balances_from_state(
    state_id: Path<ID>,
    body: Json<IdQuery>,
    db: Data<BeaconDB>,
) -> Result<impl Responder, ApiError> {
    let state = get_state_from_id(state_id.into_inner(), &db).await?;
    Ok(
        HttpResponse::Ok().json(BeaconResponse::new(build_validator_balances(
            &state
                .validators
                .into_iter()
                .zip(state.balances.into_iter())
                .collect::<Vec<_>>(),
            body.id.as_ref(),
        ))),
    )
}

#[derive(Debug, Serialize)]
pub struct ValidatorLivenessData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    pub is_live: bool,
}

impl ValidatorLivenessData {
    pub fn new(index: u64, is_live: bool) -> Self {
        Self { index, is_live }
    }
}

#[post("/validator/liveness/{epoch}")]
pub async fn post_validator_liveness(
    db: Data<BeaconDB>,
    epoch: Path<u64>,
    validator_indices: Json<Vec<String>>,
) -> Result<impl Responder, ApiError> {
    let epoch = epoch.into_inner();
    let validator_indices = validator_indices.into_inner();

    let slot = epoch * SLOTS_PER_EPOCH;
    let state = get_state_from_id(ID::Slot(slot), &db).await?;

    let mut liveness_data = Vec::new();

    for validator_index_str in validator_indices {
        let validator_index: u64 = validator_index_str
            .parse()
            .map_err(|err| ApiError::BadRequest(format!("Invalid validator index: {err:?}")))?;
        let index = validator_index as usize;

        match state.validators.get(index) {
            Some(_validator) => {
                let is_live = check_validator_participation(&state, index, epoch)?;
                liveness_data.push(ValidatorLivenessData::new(validator_index, is_live));
            }
            None => continue,
        }
    }

    Ok(HttpResponse::Ok().json(BeaconResponse::new(liveness_data)))
}

fn check_validator_participation(
    state: &BeaconState,
    validator_index: usize,
    epoch: u64,
) -> Result<bool, ApiError> {
    let validator = &state.validators[validator_index];
    if !validator.is_active_validator(epoch) {
        return Ok(false);
    }

    let current_epoch = state.get_current_epoch();

    if epoch == current_epoch {
        if let Some(participation) = state.current_epoch_participation.get(validator_index) {
            Ok(*participation > 0)
        } else {
            Ok(false)
        }
    } else if epoch == current_epoch - 1 {
        if let Some(participation) = state.previous_epoch_participation.get(validator_index) {
            Ok(*participation > 0)
        } else {
            Ok(false)
        }
    } else {
        Ok(validator.is_active_validator(epoch))
    }
}

#[get("/validator/attestation_data")]
pub async fn get_attestation_data(
    db: Data<BeaconDB>,
    opertation_pool: Data<Arc<OperationPool>>,
    query: Query<AttestationQuery>,
) -> Result<impl Responder, ApiError> {
    let store = Store::new(
        db.get_ref().clone(),
        opertation_pool.get_ref().clone(),
        None,
    );

    if store.is_syncing_for_validator_api().map_err(|err| {
        ApiError::InternalError(format!("Failed to check syncing status, err: {err:?}"))
    })? {
        return Err(ApiError::UnderSyncing);
    }

    let slot = query.slot;

    let current_slot = store.get_current_slot().map_err(|err| {
        ApiError::InternalError(format!("Failed to get current slot, err: {err:?}"))
    })?;

    if slot > current_slot + 1 {
        return Err(ApiError::InvalidParameter(format!(
            "Slot {slot:?} is too far ahead of the current slot {current_slot:?}"
        )));
    }

    let head_root = store
        .get_head()
        .map_err(|err| ApiError::InternalError(format!("Failed to get head root: {err:?}")))?;

    let state = db
        .state_provider()
        .get(head_root)
        .map_err(|err| ApiError::InternalError(format!("Failed to get state, error: {err:?}")))?
        .ok_or_else(|| ApiError::NotFound(format!("Failed to find state for root {head_root}")))?;

    let beacon_block_root = if slot >= state.slot {
        head_root
    } else {
        state
            .get_block_root_at_slot(slot)
            .or_else(|_| store.get_ancestor(head_root, slot))
            .map_err(|err| {
                ApiError::InternalError(format!(
                    "Failed to get attestation beacon block root, error: {err:?}"
                ))
            })?
    };

    let target_epoch = compute_epoch_at_slot(slot);
    let source_checkpoint = if target_epoch == state.get_previous_epoch() {
        state.previous_justified_checkpoint
    } else {
        state.current_justified_checkpoint
    };
    let target_slot = compute_start_slot_at_epoch(target_epoch);
    let target_root = if state.slot <= target_slot {
        beacon_block_root
    } else {
        state
            .get_block_root(target_epoch)
            .or_else(|_| store.get_checkpoint_block(beacon_block_root, target_epoch))
            .map_err(|err| {
                ApiError::InternalError(format!(
                    "Failed to get target checkpoint block, error: {err:?}"
                ))
            })?
    };
    let target_checkpoint = Checkpoint {
        epoch: target_epoch,
        root: target_root,
    };

    Ok(HttpResponse::Ok().json(DataResponse::new(AttestationData {
        slot,
        index: ELECTRA_COMMITTEE_INDEX,
        beacon_block_root,
        source: source_checkpoint,
        target: target_checkpoint,
    })))
}

/// For the initial stage, this endpoint returns a 501 as DVT support is not planned.
#[post("/validator/sync_committee_selections")]
pub async fn post_sync_committee_selections(
    _selections: Json<SyncCommitteeSelection>,
) -> Result<impl Responder, ApiError> {
    Ok(HttpResponse::NotImplemented())
}

/// For the initial stage, this endpoint returns a 501 as DVT support is not planned.
#[post("/validator/beacon_committee_selections")]
pub async fn post_beacon_committee_selections(
    _selections: Json<Vec<BeaconCommitteeSelection>>,
) -> Result<impl Responder, ApiError> {
    Ok(HttpResponse::NotImplemented())
}

#[get("/validator/sync_committee_contribution")]
pub async fn get_sync_committee_contribution(
    db: Data<BeaconDB>,
    operation_pool: Data<Arc<OperationPool>>,
    sync_committee_pool: Data<Arc<SyncCommitteePool>>,
    query: Query<SyncCommitteeContributionQuery>,
) -> Result<impl Responder, ApiError> {
    let store = Store::new(db.get_ref().clone(), operation_pool.get_ref().clone(), None);

    if store.is_syncing_for_validator_api().map_err(|err| {
        ApiError::InternalError(format!("Failed to check syncing status, err: {err:?}"))
    })? {
        return Err(ApiError::UnderSyncing);
    }

    let slot = query.slot;
    let subcommittee_index = query.subcommittee_index;
    let beacon_block_root = query.beacon_block_root;

    // Validate subcommittee index
    if subcommittee_index >= SYNC_COMMITTEE_SUBNET_COUNT {
        return Err(ApiError::InvalidParameter(format!(
            "Invalid subcommittee_index: {subcommittee_index}, must be less than {SYNC_COMMITTEE_SUBNET_COUNT}"
        )));
    }

    let current_slot = store.get_current_slot().map_err(|err| {
        ApiError::InternalError(format!("Failed to get current slot, err: {err:?}"))
    })?;

    // Validate slot is not too far in the future
    if slot > current_slot + 1 {
        return Err(ApiError::InvalidParameter(format!(
            "Slot {slot:?} is too far ahead of the current slot {current_slot:?}"
        )));
    }

    // Validate beacon block exists
    db.block_provider()
        .get(beacon_block_root)
        .map_err(|err| ApiError::InternalError(format!("Failed to get beacon block: {err:?}")))?
        .ok_or_else(|| {
            ApiError::NotFound(format!("Beacon block root {beacon_block_root:?} not found"))
        })?;

    // Check if block is fully verified (not optimistic)
    // TODO: Add optimistic sync check when execution layer integration is complete
    // For now, we assume all blocks in fork choice are fully verified

    // Try to get the best (highest-participation) sync committee contribution from the pool
    // Per spec: return 404 if no contribution is available
    let sync_committee_contribution = sync_committee_pool
        .get_best_sync_committee_contribution(slot, beacon_block_root, subcommittee_index)
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "No sync committee contribution available for beacon block root {beacon_block_root:?}"
            ))
        })?;

    Ok(HttpResponse::Ok().json(DataResponse::new(sync_committee_contribution)))
}

#[post("/validator/aggregate_and_proofs")]
pub async fn post_aggregate_and_proofs_v2(
    db: Data<BeaconDB>,
    aggregates: Json<Vec<SignedAggregateAndProof>>,
) -> Result<impl Responder, ApiError> {
    for signed_aggregate in aggregates.into_inner() {
        let aggregate_and_proof = signed_aggregate.message;
        let attestation = aggregate_and_proof.aggregate.clone();
        let slot = attestation.data.slot;
        let state = get_state_from_id(ID::Slot(slot), &db).await?;

        let aggregator_index = aggregate_and_proof.aggregator_index as usize;

        let aggregator = state
            .validators
            .get(aggregator_index)
            .ok_or_else(|| ApiError::NotFound("Aggregator not found".to_string()))?;

        let committee = state
            .get_beacon_committee(attestation.data.slot, attestation.data.index)
            .map_err(|err| {
                ApiError::InternalError(format!("Failed due to internal error: {err}"))
            })?;

        if !committee.contains(&(aggregator_index as u64)) {
            return Err(ApiError::BadRequest(
                "Aggregator not part of the committee".to_string(),
            ));
        }

        let aggregator_selection_domain =
            state.get_domain(DOMAIN_SELECTION_PROOF, Some(compute_epoch_at_slot(slot)));
        let aggregator_selection_signing_root =
            compute_signing_root(attestation.data.slot, aggregator_selection_domain);

        if !aggregate_and_proof
            .selection_proof
            .verify(
                &aggregator.public_key,
                aggregator_selection_signing_root.as_ref(),
            )
            .map_err(|err| {
                ApiError::InternalError(format!("Failed due to internal error: {err}"))
            })?
        {
            return Err(ApiError::BadRequest(
                "Aggregator selection proof is not valid".to_string(),
            ));
        }

        let committee_pub_keys: Vec<&PublicKey> = committee
            .iter()
            .enumerate()
            .filter(|(i, _)| attestation.aggregation_bits.get(*i).unwrap_or(false))
            .map(|(i, _)| &state.validators[committee[i] as usize].public_key)
            .collect();

        if committee_pub_keys.is_empty() {
            return Err(ApiError::BadRequest(
                "No aggregation bits set in the attestation".into(),
            ));
        }

        let aggregate_signature_domain =
            state.get_domain(DOMAIN_BEACON_ATTESTER, Some(attestation.data.target.epoch));
        let aggregate_signature_signing_root =
            compute_signing_root(&attestation.data, aggregate_signature_domain);

        if !attestation
            .signature
            .fast_aggregate_verify(
                committee_pub_keys,
                aggregate_signature_signing_root.as_ref(),
            )
            .map_err(|err| {
                ApiError::InternalError(format!("Failed due to internal error: {err}"))
            })?
        {
            return Err(ApiError::BadRequest(
                "Aggregated signature verification failed".to_string(),
            ));
        }

        let aggregate_proof_domain = state.get_domain(
            DOMAIN_AGGREGATE_AND_PROOF,
            Some(compute_epoch_at_slot(attestation.data.slot)),
        );
        let aggregate_proof_signing_root =
            compute_signing_root(aggregate_and_proof, aggregate_proof_domain);

        if !signed_aggregate
            .signature
            .verify(
                &aggregator.public_key,
                aggregate_proof_signing_root.as_ref(),
            )
            .map_err(|err| {
                ApiError::InternalError(format!("Failed due to internal error: {err}"))
            })?
        {
            return Err(ApiError::BadRequest(
                "Aggregate proof verification failed".to_string(),
            ));
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "data": "success"
    })))
}

#[derive(Debug, Clone)]
pub enum SubscriptionAction {
    Subscribe { subnet_id: u64, fork: B32 },
}

impl SubscriptionAction {
    fn subnet_id(&self) -> u64 {
        match self {
            SubscriptionAction::Subscribe { subnet_id, .. } => *subnet_id,
        }
    }

    fn fork(&self) -> B32 {
        match self {
            SubscriptionAction::Subscribe { fork, .. } => *fork,
        }
    }
}

#[post("/validator/beacon_committee_subscriptions")]
pub async fn post_beacon_committee_subscriptions(
    db: Data<BeaconDB>,
    subscriptions: Json<Vec<BeaconCommitteeSubscription>>,
    network: Data<Arc<P2PSender>>,
) -> Result<impl Responder, ApiError> {
    let mut subnets: HashSet<(u64, B32)> = HashSet::new();

    for sub in subscriptions.into_inner() {
        let state = get_state_from_id(ID::Slot(sub.slot), &db).await?;

        if sub.committees_at_slot > MAX_COMMITTEES_PER_SLOT {
            return Err(ApiError::BadRequest(
                "Committees at a slot should be less than the maximum committees per slot".into(),
            ));
        }

        if sub.committee_index >= sub.committees_at_slot {
            return Err(ApiError::BadRequest(
                "Committee index cannot be more than the committees in a slot".into(),
            ));
        }

        let committee_members = state
            .get_beacon_committee(sub.slot, sub.committee_index)
            .map_err(|err| ApiError::InternalError(format!("Failed to get committee: {err}")))?;

        if !committee_members.contains(&sub.validator_index) {
            return Err(ApiError::BadRequest(
                "Validator not part of the committee".into(),
            ));
        }

        let subnet_id =
            compute_subnet_for_attestation(sub.committees_at_slot, sub.slot, sub.committee_index);

        let fork = gossip_fork_digest(&state);

        subnets.insert((subnet_id, fork));
    }

    let actions: Vec<SubscriptionAction> = subnets
        .into_iter()
        .map(|(subnet_id, fork)| SubscriptionAction::Subscribe { subnet_id, fork })
        .collect();

    for action in actions {
        let topic = GossipTopic {
            fork: action.fork(),
            kind: GossipTopicKind::BeaconAttestation(action.subnet_id()),
        };

        network
            .subscribe(topic)
            .await
            .map_err(|err| ApiError::InternalError(err.to_string()))?;
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "data": "success"
    })))
}

fn sync_subscription_subnets(
    current_committee: &ream_consensus_beacon::sync_committee::SyncCommittee,
    next_committee: &ream_consensus_beacon::sync_committee::SyncCommittee,
    public_key: &PublicKey,
    indices: &[u64],
) -> Result<HashSet<u64>, ApiError> {
    let mut subnets = HashSet::new();
    for &index in indices {
        let current = current_committee.public_keys.get(index as usize);
        let next = next_committee.public_keys.get(index as usize);
        if current != Some(public_key) && next != Some(public_key) {
            return Err(ApiError::BadRequest(format!(
                "Invalid sync committee position {index}"
            )));
        }
        subnets.insert(
            index / (current_committee.public_keys.len() as u64 / SYNC_COMMITTEE_SUBNET_COUNT),
        );
    }
    Ok(subnets)
}

#[post("/validator/sync_committee_subscriptions")]
pub async fn post_sync_committee_subscriptions(
    db: Data<BeaconDB>,
    subscriptions: Json<Vec<SyncCommitteeSubscription>>,
    network: Data<Arc<P2PSender>>,
) -> Result<impl Responder, ApiError> {
    let subscriptions = subscriptions.into_inner();

    if subscriptions.is_empty() {
        return Err(ApiError::BadRequest("Empty request body".to_string()));
    }

    let highest_slot = db
        .slot_index_provider()
        .get_highest_slot()
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to get_highest_slot, error: {err:?}"))
        })?
        .ok_or(ApiError::NotFound(
            "Failed to find highest slot".to_string(),
        ))?;
    let state = get_state_from_id(ID::Slot(highest_slot), &db).await?;
    let current_epoch = state.get_current_epoch();

    let mut subnets_to_subscribe: HashSet<(u64, B32)> = HashSet::new();

    for subscription in subscriptions {
        let validator = state
            .validators
            .get(subscription.validator_index as usize)
            .ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "Validator index {} not found",
                    subscription.validator_index
                ))
            })?;

        if !validator.is_active_validator(current_epoch) {
            return Err(ApiError::BadRequest(format!(
                "Validator {} is not active",
                subscription.validator_index
            )));
        }

        // Validate until_epoch is in the future
        if subscription.until_epoch <= current_epoch {
            return Err(ApiError::BadRequest(format!(
                "until_epoch {} must be greater than current epoch {current_epoch}",
                subscription.until_epoch
            )));
        }

        let validator_subnets = sync_subscription_subnets(
            &state.current_sync_committee,
            &state.next_sync_committee,
            &validator.public_key,
            &subscription.sync_committee_indices,
        )?;

        let fork = gossip_fork_digest(&state);
        for subnet_id in validator_subnets {
            subnets_to_subscribe.insert((subnet_id, fork));
        }
    }

    // Subscribe to all required subnets
    for (subnet_id, fork) in subnets_to_subscribe {
        let topic = GossipTopic {
            fork,
            kind: GossipTopicKind::SyncCommittee(subnet_id),
        };

        network
            .subscribe(topic)
            .await
            .map_err(|err| ApiError::InternalError(err.to_string()))?;
    }

    Ok(HttpResponse::Ok().body(""))
}

/// Verify validator registration signature
fn verify_validator_registration_signature(
    signed_registration: &SignedValidatorRegistrationV1,
) -> Result<bool, ApiError> {
    use ream_validator_beacon::builder::DOMAIN_APPLICATION_BUILDER;

    let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, None, None);
    let signing_root = compute_signing_root(signed_registration.message.clone(), domain);

    signed_registration
        .signature
        .verify(
            &signed_registration.message.public_key,
            signing_root.as_ref(),
        )
        .map_err(|err| ApiError::InternalError(format!("Signature verification failed: {err:?}")))
}

#[post("/validator/register_validator")]
pub async fn post_register_validator(
    db: Data<BeaconDB>,
    builder_client: Data<
        Option<Arc<ream_validator_beacon::builder::builder_client::BuilderClient>>,
    >,
    registrations: Json<Vec<SignedValidatorRegistrationV1>>,
) -> Result<impl Responder, ApiError> {
    let registrations = registrations.into_inner();

    if registrations.is_empty() {
        return Err(ApiError::BadRequest("Empty request body".to_string()));
    }

    // Get the current state once for all validator status checks
    let highest_slot = db
        .slot_index_provider()
        .get_highest_slot()
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to get_highest_slot, error: {err:?}"))
        })?
        .ok_or(ApiError::NotFound(
            "Failed to find highest slot".to_string(),
        ))?;
    let state = get_state_from_id(ID::Slot(highest_slot), &db).await?;
    let current_epoch = state.get_current_epoch();

    for registration in registrations {
        // Verify signature
        let signature_valid = verify_validator_registration_signature(&registration)?;
        if !signature_valid {
            continue;
        }

        // Check if validator is active or pending (not exited or unknown)
        let is_valid = if let Some((_index, validator)) =
            find_validator_by_public_key(&state, &registration.message.public_key)
        {
            let is_pending = validator.activation_epoch > current_epoch;
            let is_active =
                validator.activation_epoch <= current_epoch && current_epoch < validator.exit_epoch;
            is_pending || is_active
        } else {
            false
        };

        if !is_valid {
            continue;
        }

        // Forward immediately to builder if available
        if let Some(client) = builder_client.get_ref().as_ref() {
            client
                .register_validator(registration)
                .await
                .map_err(|err| {
                    ApiError::InternalError(format!("Failed to forward to builder: {err}"))
                })?;
        }
    }

    Ok(HttpResponse::Ok().body("Validator registrations have been received."))
}

#[derive(Clone, Debug, Serialize)]
struct ContributionAndProofFailure {
    index: usize,
    message: String,
}

fn validate_signed_contribution_and_proof(
    signed_contribution_and_proof: &SignedContributionAndProof,
    state: &BeaconState,
) -> Result<(), String> {
    let contribution_and_proof = &signed_contribution_and_proof.message;
    let contribution = &contribution_and_proof.contribution;
    let epoch = compute_epoch_at_slot(contribution.slot);

    if contribution.subcommittee_index >= SYNC_COMMITTEE_SUBNET_COUNT {
        return Err("The subcommittee index is out of range".to_string());
    }

    if contribution.aggregation_bits.num_set_bits() == 0 {
        return Err("The contribution has no participants".to_string());
    }

    if !is_sync_committee_aggregator(&contribution_and_proof.selection_proof) {
        return Err("The selection proof is not a valid aggregator".to_string());
    }

    let aggregator_index = usize::try_from(contribution_and_proof.aggregator_index)
        .map_err(|err| format!("Invalid aggregator index: {err:?}"))?;

    let validator = state
        .validators
        .get(aggregator_index)
        .ok_or_else(|| "Aggregator not found".to_string())?;

    let sync_committee_validators =
        get_sync_subcommittee_pubkeys(state, contribution.subcommittee_index);

    if !sync_committee_validators.contains(&validator.public_key) {
        return Err("The aggregator is not in the subcommittee".to_string());
    }

    let selection_data = SyncAggregatorSelectionData {
        slot: contribution.slot,
        subcommittee_index: contribution.subcommittee_index,
    };

    let selection_proof_valid = contribution_and_proof
        .selection_proof
        .verify(
            &validator.public_key,
            compute_signing_root(
                selection_data,
                state.get_domain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, Some(epoch)),
            )
            .as_slice(),
        )
        .map_err(|err| format!("Selection proof verification error: {err:?}"))?;

    if !selection_proof_valid {
        return Err("The selection proof is not a valid signature".to_string());
    }

    let sync_committee_valid = contribution
        .signature
        .fast_aggregate_verify(
            sync_committee_validators
                .iter()
                .collect::<Vec<&PublicKey>>(),
            compute_signing_root(
                contribution.beacon_block_root,
                state.get_domain(DOMAIN_SYNC_COMMITTEE, Some(epoch)),
            )
            .as_ref(),
        )
        .map_err(|err| format!("Sync committee signature verification error: {err:?}"))?;

    if !sync_committee_valid {
        return Err("The aggregate signature is not valid".to_string());
    }

    let contribution_and_proof_valid = signed_contribution_and_proof
        .signature
        .verify(
            &validator.public_key,
            compute_signing_root(
                contribution_and_proof,
                state.get_domain(DOMAIN_CONTRIBUTION_AND_PROOF, Some(epoch)),
            )
            .as_slice(),
        )
        .map_err(|err| format!("Contribution and proof signature verification error: {err:?}"))?;

    if !contribution_and_proof_valid {
        return Err("The aggregator signature is not valid".to_string());
    }

    Ok(())
}

#[post("/validator/contribution_and_proofs")]
pub async fn post_contribution_and_proofs(
    db: Data<BeaconDB>,
    operation_pool: Data<Arc<OperationPool>>,
    event_sender: Data<broadcast::Sender<BeaconEvent>>,
    contributions: Json<Vec<SignedContributionAndProof>>,
) -> Result<impl Responder, ApiError> {
    let store = Store::new(db.get_ref().clone(), operation_pool.get_ref().clone(), None);

    if store.is_syncing_for_validator_api().map_err(|err| {
        ApiError::InternalError(format!("Failed to check syncing status, err: {err:?}"))
    })? {
        return Err(ApiError::UnderSyncing);
    }

    let highest_slot = db
        .slot_index_provider()
        .get_highest_slot()
        .map_err(|err| ApiError::InternalError(format!("Failed to get highest slot: {err:?}")))?
        .ok_or_else(|| ApiError::NotFound("Failed to find highest slot".to_string()))?;

    let state = get_state_from_id(ID::Slot(highest_slot), &db).await?;
    let contributions = contributions.into_inner();
    let mut failures = Vec::new();

    for (index, signed_contribution_and_proof) in contributions.iter().enumerate() {
        match validate_signed_contribution_and_proof(signed_contribution_and_proof, &state) {
            Ok(()) => {
                let event = BeaconEvent::ContributionAndProof(ContributionAndProofEvent {
                    message: signed_contribution_and_proof.message.clone(),
                    signature: signed_contribution_and_proof.signature.clone(),
                });
                let _ = event_sender.send(event);
            }
            Err(err) => {
                failures.push(ContributionAndProofFailure {
                    index,
                    message: err,
                });
            }
        }
    }

    if !failures.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "code": 400,
            "message": "some failures",
            "failures": failures
        })));
    }

    Ok(HttpResponse::Ok().body("success"))
}

#[derive(serde::Deserialize)]
struct BlockQuery {
    randao_reveal: BLSSignature,
    graffiti: Option<B256>,
    skip_randao_verification: Option<bool>,
    builder_boost_factor: Option<u64>,
}

fn verify_randao_reveal(
    state: &BeaconState,
    epoch: u64,
    randao_reveal: &BLSSignature,
    skip_randao_verification: bool,
    proposer_public_key: &PublicKey,
) -> Result<(), ApiError> {
    if skip_randao_verification {
        if !randao_reveal.is_infinity() {
            return Err(ApiError::BadRequest(
                "If randao verification is skipped then the randao reveal must be equal to point at infinity".into(),
            ));
        }
    } else {
        let randao_proof_domain = state.get_domain(DOMAIN_RANDAO, Some(epoch));
        let randao_proof_signing_root = compute_signing_root(epoch, randao_proof_domain);
        if !randao_reveal
            .verify(proposer_public_key, randao_proof_signing_root.as_ref())
            .map_err(|err| {
                ApiError::InternalError(format!("Failed due to internal error: {err}"))
            })?
        {
            return Err(ApiError::BadRequest(
                "Randao reveal verification failed".to_string(),
            ));
        }
    }
    Ok(())
}

fn calculate_consensus_block_value(
    state: &BeaconState,
    attestations: &VariableList<Attestation, U8>,
    proposer_slashings: &VariableList<ProposerSlashing, U16>,
    attester_slashings: &VariableList<AttesterSlashing, U1>,
    sync_aggregate: &SyncAggregate,
) -> Result<u64, ApiError> {
    let mut total_reward = 0u64;

    // Calculate attestation rewards
    for attestation in attestations {
        if let Ok(attesting_indices) = state.get_attesting_indices(attestation) {
            let total_participating_balance: u64 = attesting_indices
                .iter()
                .filter_map(|&idx| {
                    state
                        .validators
                        .get(idx as usize)
                        .map(|v| v.effective_balance)
                })
                .sum();

            let proposer_reward = total_participating_balance
                .saturating_div(SLOTS_PER_EPOCH.saturating_mul(PROPOSER_REWARD_QUOTIENT));

            total_reward = total_reward.saturating_add(proposer_reward);
        }
    }

    // Calculate proposer slashing rewards
    for proposer_slashing in proposer_slashings {
        let index = proposer_slashing.signed_header_1.message.proposer_index;
        if let Some(validator) = state.validators.get(index as usize) {
            total_reward = total_reward.saturating_add(
                validator
                    .effective_balance
                    .saturating_div(WHISTLEBLOWER_REWARD_QUOTIENT),
            );
        }
    }

    // Calculate attester slashing rewards
    let current_epoch = state.get_current_epoch();
    for attester_slashing in attester_slashings {
        if let Ok((attestation_indices_1, attestation_indices_2)) =
            state.get_slashable_attester_indices(attester_slashing)
        {
            let slashed_indices: HashSet<_> = attestation_indices_1
                .intersection(&attestation_indices_2)
                .copied()
                .collect();

            for index in slashed_indices {
                if let Some(validator) = state.validators.get(index as usize)
                    && validator.is_slashable_validator(current_epoch)
                {
                    total_reward = total_reward.saturating_add(
                        validator
                            .effective_balance
                            .saturating_div(WHISTLEBLOWER_REWARD_QUOTIENT),
                    );
                }
            }
        }
    }

    // Calculate sync committee rewards
    if !sync_aggregate.sync_committee_bits.is_empty() {
        let (_, base_proposer_reward) = state.get_proposer_and_participant_rewards();
        let participating_count = sync_aggregate.sync_committee_bits.num_set_bits() as u64;
        let sync_reward = (participating_count.saturating_mul(base_proposer_reward))
            .saturating_div(SYNC_COMMITTEE_PROPOSER_REWARD_QUOTIENT);

        total_reward = total_reward.saturating_add(sync_reward);
    }

    Ok(total_reward)
}

async fn get_local_execution_payload(
    execution_engine: &ExecutionEngine,
    fork_name: ForkName,
    forkchoice_state: ForkchoiceStateV1,
    payload_attribute: PayloadAttributesV3,
) -> Result<(Payload, u64), ApiError> {
    let result = execution_engine
        .engine_forkchoice_updated_v3(
            ForkchoiceStateV1 {
                head_block_hash: forkchoice_state.head_block_hash,
                safe_block_hash: forkchoice_state.safe_block_hash,
                finalized_block_hash: forkchoice_state.finalized_block_hash,
            },
            Some(PayloadAttributesV3 {
                timestamp: payload_attribute.timestamp,
                prev_randao: payload_attribute.prev_randao,
                suggested_fee_recipient: payload_attribute.suggested_fee_recipient,
                withdrawals: payload_attribute.withdrawals.clone(),
                parent_beacon_block_root: payload_attribute.parent_beacon_block_root,
            }),
        )
        .await
        .map_err(|err| ApiError::InternalError(format!("Failed to update forkchoice: {err}")))?;

    let payload_id = result.payload_id.ok_or_else(|| {
        ApiError::InternalError("No payload id returned from forkchoice update".into())
    })?;

    let payload = execution_engine
        .engine_get_payload(&fork_name, payload_id)
        .await
        .map_err(|err| ApiError::InternalError(format!("Failed to get payload: {err}")))?;

    let execution_value: u64 = (*payload.block_value())
        .try_into()
        .map_err(|err| ApiError::InternalError(format!("Block value too large: {err}")))?;

    Ok((payload, execution_value))
}

async fn compare_builder_vs_local(
    builder_client: Option<&Arc<BuilderClient>>,
    parent_hash: B256,
    proposer_public_key: &PublicKey,
    slot: u64,
    local_execution_value: u64,
    builder_boost_factor: u64,
) -> Result<(bool, Option<SignedBuilderBid>, u64), ApiError> {
    if let Some(builder) = builder_client {
        match builder
            .get_builder_header(parent_hash, proposer_public_key, slot)
            .await
        {
            Ok(bid) => {
                let builder_value_u256 = bid.message.value;
                let builder_value_u64: u64 = match builder_value_u256.try_into() {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::warn!(
                            "Builder bid value too large to fit in u64: {err:?}, falling back to local execution"
                        );
                        return Ok((false, None, 0));
                    }
                };
                let boosted_builder_value = builder_value_u64
                    .saturating_mul(builder_boost_factor)
                    .saturating_div(100);

                let use_builder = boosted_builder_value > local_execution_value;
                Ok((use_builder, Some(bid), builder_value_u64))
            }
            Err(err) => {
                tracing::warn!(
                    "Failed to get builder header: {err:?}, falling back to local execution"
                );
                Ok((false, None, 0))
            }
        }
    } else {
        Ok((false, None, 0))
    }
}

fn validate_proposal_blob_bundle(
    bundle: &ream_execution_rpc_types::get_payload::BlobsBundle,
) -> Result<usize, ApiError> {
    use ream_execution_rpc_types::get_payload::BlobsBundle;
    let (blobs, commitments, proofs, proofs_per_blob) = match bundle {
        BlobsBundle::V1(bundle) => (
            bundle.blobs.len(),
            bundle.commitments.len(),
            bundle.proofs.len(),
            1,
        ),
        BlobsBundle::V2(bundle) => (
            bundle.blobs.len(),
            bundle.commitments.len(),
            bundle.proofs.len(),
            ream_consensus_misc::constants::beacon::CELLS_PER_EXT_BLOB as usize,
        ),
    };
    if blobs != commitments || proofs != commitments * proofs_per_blob {
        return Err(ApiError::InternalError(
            "Invalid execution payload blob bundle lengths".into(),
        ));
    }
    Ok(proofs_per_blob)
}

fn execution_checkpoint_hash(db: &BeaconDB, root: B256) -> Result<B256, ApiError> {
    if root == B256::ZERO {
        return Ok(B256::ZERO);
    }
    db.block_provider()
        .get(root)
        .map_err(|err| ApiError::InternalError(format!("Failed to read checkpoint block: {err}")))?
        .map(|block| block.message.body.execution_payload.block_hash)
        .ok_or_else(|| ApiError::InternalError(format!("Missing checkpoint block {root}")))
}

#[get("/validator/blocks/{slot}")]
pub async fn get_blocks_v3(
    path: Path<u64>,
    query: Query<BlockQuery>,
    db: Data<BeaconDB>,
    beacon_chain: Data<Arc<ream_chain_beacon::beacon_chain::BeaconChain>>,
    operation_pool: Data<Arc<OperationPool>>,
    execution_engine: Data<Option<ExecutionEngine>>,
    builder_client: Data<Option<Arc<BuilderClient>>>,
) -> Result<impl Responder, ApiError> {
    let slot = path.into_inner();
    let query_params = query.into_inner();
    let randao_reveal = query_params.randao_reveal;
    let graffiti = query_params.graffiti.unwrap_or_default();
    let skip_randao_verification = query_params.skip_randao_verification.unwrap_or(false);
    let builder_boost_factor = query_params.builder_boost_factor.unwrap_or(100);

    let head = beacon_chain
        .head()
        .map_err(|err| ApiError::InternalError(format!("Failed to read head: {err}")))?;
    let mut state = (*head.state).clone();

    let current_slot = state.slot;

    if slot < current_slot {
        return Err(ApiError::BadRequest(
            "Current slot is greater than requested slot".into(),
        ));
    }

    // Process slots to get state at the requested slot.
    if slot > current_slot {
        state
            .process_slots(slot)
            .map_err(|err| ApiError::InternalError(format!("Failed to process slots: {err}")))?;
    }

    let proposer_index = state.get_beacon_proposer_index(Some(slot)).map_err(|err| {
        ApiError::InternalError(format!(
            "Failed to get the proposer index for slot {slot}: {err}",
        ))
    })?;

    let Some(proposer) = state.validators.get(proposer_index as usize) else {
        return Err(ApiError::ValidatorNotFound(format!("{proposer_index}")));
    };

    let proposer_public_key = proposer.public_key.clone();
    let epoch = compute_epoch_at_slot(slot);
    let fork_name = fork_name_at_epoch(epoch);

    verify_randao_reveal(
        &state,
        epoch,
        &randao_reveal,
        skip_randao_verification,
        &proposer_public_key,
    )?;

    let fee_recipient = operation_pool
        .get_proposer_preparation(proposer_index)
        .unwrap_or(Address::ZERO);

    let (withdrawals, _) = state.get_expected_withdrawals().map_err(|err| {
        ApiError::InternalError(format!("Failed to get expected withdrawals: {err}"))
    })?;

    let forkchoice_state = ForkchoiceStateV1 {
        head_block_hash: state.latest_execution_payload_header.block_hash,
        safe_block_hash: execution_checkpoint_hash(&db, head.justified_checkpoint.root)?,
        finalized_block_hash: execution_checkpoint_hash(&db, head.finalized_checkpoint.root)?,
    };

    let payload_attribute = PayloadAttributesV3 {
        timestamp: state.compute_timestamp_at_slot(slot),
        prev_randao: state.get_randao_mix(epoch),
        suggested_fee_recipient: fee_recipient,
        withdrawals: withdrawals.try_into().map_err(|err| {
            ApiError::InternalError(format!(
                "Failed to convert withdrawals to VariableList: {err}"
            ))
        })?,
        parent_beacon_block_root: state.latest_block_header.tree_hash_root(),
    };

    let Some(execution_engine) = execution_engine.get_ref().as_ref() else {
        return Err(ApiError::InternalError(
            "Execution engine not available".into(),
        ));
    };

    let (local_payload, local_execution_value) = get_local_execution_payload(
        execution_engine,
        fork_name,
        forkchoice_state,
        payload_attribute,
    )
    .await?;

    let builder_client_ref = builder_client.get_ref().as_ref();
    let (use_builder, builder_bid, builder_value) = compare_builder_vs_local(
        builder_client_ref,
        state.latest_execution_payload_header.block_hash,
        &proposer_public_key,
        slot,
        local_execution_value,
        builder_boost_factor,
    )
    .await?;

    let proposer_slashings: VariableList<ProposerSlashing, U16> = operation_pool
        .get_all_proposer_slahsings()
        .try_into()
        .unwrap_or_default();
    let attester_slashings: VariableList<AttesterSlashing, U1> = operation_pool
        .get_all_attester_slashings()
        .try_into()
        .unwrap_or_default();
    let attestations: VariableList<Attestation, U8> = operation_pool
        .get_attestations_for_block(&state)
        .try_into()
        .unwrap_or_default();
    let deposits: VariableList<Deposit, U16> = operation_pool
        .get_all_deposits()
        .try_into()
        .unwrap_or_default();
    let voluntary_exits: VariableList<SignedVoluntaryExit, U16> = operation_pool
        .get_signed_voluntary_exits()
        .try_into()
        .unwrap_or_default();
    let mut sync_aggregate = operation_pool
        .get_sync_aggregate(
            slot.saturating_sub(1),
            state.latest_block_header.tree_hash_root(),
        )
        .unwrap_or_default();
    if sync_aggregate.sync_committee_bits.num_set_bits() == 0 {
        sync_aggregate.sync_committee_signature = BLSSignature::infinity();
    }
    let bls_to_execution_changes: VariableList<SignedBLSToExecutionChange, U16> = operation_pool
        .get_signed_bls_to_execution_changes()
        .try_into()
        .unwrap_or_default();

    let common_block_body_fields = (
        randao_reveal,
        state.eth1_data.clone(),
        graffiti,
        proposer_slashings.clone(),
        attester_slashings.clone(),
        attestations.clone(),
        deposits,
        voluntary_exits,
        sync_aggregate.clone(),
        bls_to_execution_changes,
    );

    let consensus_block_value = calculate_consensus_block_value(
        &state,
        &attestations,
        &proposer_slashings,
        &attester_slashings,
        &sync_aggregate,
    )?;

    if use_builder {
        let builder_bid = builder_bid.expect("Builder bid should exist when use_builder is true");

        let blinded_beacon_block_body = BlindedBeaconBlockBody {
            randao_reveal: common_block_body_fields.0,
            eth1_data: common_block_body_fields.1,
            graffiti: common_block_body_fields.2,
            proposer_slashings: common_block_body_fields.3,
            attester_slashings: common_block_body_fields.4,
            attestations: common_block_body_fields.5,
            deposits: common_block_body_fields.6,
            voluntary_exits: common_block_body_fields.7,
            sync_aggregate: common_block_body_fields.8,
            execution_payload_header: builder_bid.message.header,
            bls_to_execution_changes: common_block_body_fields.9,
            blob_kzg_commitments: builder_bid.message.blob_kzg_commitments,
            execution_requests: builder_bid.message.execution_requests,
        };

        let blinded_block = BlindedBeaconBlock {
            slot,
            proposer_index,
            parent_root: state.latest_block_header.tree_hash_root(),
            state_root: state.tree_hash_root(),
            body: blinded_beacon_block_body,
        };

        let response = ProduceBlockResponse {
            version: fork_name.to_string(),
            execution_payload_blinded: true,
            execution_payload_value: builder_value,
            consensus_block_value,
            data: ProduceBlockData::Blinded(blinded_block),
        };

        return Ok(HttpResponse::Ok()
            .insert_header(("Eth-Consensus-Version", fork_name.to_string()))
            .insert_header(("Eth-Execution-Payload-Blinded", "true"))
            .insert_header((
                "Eth-Execution-Payload-Value",
                response.execution_payload_value.to_string(),
            ))
            .insert_header((
                "Eth-Consensus-Block-Value",
                consensus_block_value.to_string(),
            ))
            .json(response));
    }

    let execution_payload = local_payload.to_execution_payload();

    let blob_kzg_commitments: Vec<KZGCommitment> = local_payload.blobs_bundle().get_commitments();

    let kzg_proofs: Vec<KZGProof> = local_payload.blobs_bundle().get_proofs();

    let proofs_per_blob = validate_proposal_blob_bundle(&local_payload.blobs_bundle())?;

    let execution_requests =
        get_execution_requests(local_payload.execution_requests().clone()).unwrap_or_default();

    let block_body = BeaconBlockBody {
        randao_reveal: common_block_body_fields.0,
        eth1_data: common_block_body_fields.1,
        graffiti: common_block_body_fields.2,
        proposer_slashings: common_block_body_fields.3,
        attester_slashings: common_block_body_fields.4,
        attestations: common_block_body_fields.5,
        deposits: common_block_body_fields.6,
        voluntary_exits: common_block_body_fields.7,
        sync_aggregate: common_block_body_fields.8,
        execution_payload,
        bls_to_execution_changes: common_block_body_fields.9,
        blob_kzg_commitments: blob_kzg_commitments.clone().try_into().unwrap_or_default(),
        execution_requests,
    };

    let mut block = BeaconBlock {
        slot,
        proposer_index,
        parent_root: state.latest_block_header.tree_hash_root(),
        state_root: B256::default(),
        body: block_body,
    };
    let mut post_state = state.clone();
    post_state
        .process_block(&block, &Option::<ExecutionEngine>::None)
        .await
        .map_err(|err| {
            ApiError::InternalError(format!("Failed to compute post-state root: {err}"))
        })?;
    block.state_root = post_state.tree_hash_root();

    let blobs = local_payload.blobs_bundle().get_blobs();
    if blobs.len() != blob_kzg_commitments.len() {
        return Err(ApiError::InternalError(
            "Blob count does not match commitments".into(),
        ));
    }
    let block_root = block.tree_hash_root();
    let blobs_and_proofs_provider = db.blobs_and_proofs_provider();
    for (index, (blob, commitment)) in blobs.iter().zip(&blob_kzg_commitments).enumerate() {
        let proof = if proofs_per_blob == 1 {
            kzg_proofs[index]
        } else {
            let blob = blob.clone();
            let commitment = commitment.clone();
            tokio::task::spawn_blocking(move || {
                ream_polynomial_commitments::handlers::compute_blob_kzg_proof(&blob, &commitment)
            })
            .await
            .map_err(|err| ApiError::InternalError(format!("Blob proof worker failed: {err}")))?
            .map_err(|err| {
                ApiError::InternalError(format!("Failed to compute cached blob proof: {err}"))
            })?
        };
        blobs_and_proofs_provider
            .insert(
                BlobIdentifier::new(block_root, index as u64),
                ream_execution_rpc_types::get_blobs::BlobAndProofV1 {
                    blob: blob.clone(),
                    proof,
                },
            )
            .map_err(|err| {
                ApiError::InternalError(format!("Failed to cache proposal blob: {err}"))
            })?;
    }

    let response = ProduceBlockResponse {
        version: fork_name.to_string(),
        execution_payload_blinded: false,
        execution_payload_value: local_execution_value,
        consensus_block_value,
        data: ProduceBlockData::Full(FullBlockData {
            block,
            kzg_proofs,
            blobs,
        }),
    };

    Ok(HttpResponse::Ok()
        .insert_header(("Eth-Consensus-Version", fork_name.to_string()))
        .insert_header(("Eth-Execution-Payload-Blinded", "false"))
        .insert_header((
            "Eth-Execution-Payload-Value",
            local_execution_value.to_string(),
        ))
        .insert_header((
            "Eth-Consensus-Block-Value",
            consensus_block_value.to_string(),
        ))
        .json(response))
}

#[get("/validator/aggregate_attestation")]
pub async fn get_aggregate_attestation(
    opertation_pool: Data<Arc<OperationPool>>,
    attestation_query: Query<AttestationQuery>,
) -> Result<impl Responder, ApiError> {
    let attestations = opertation_pool.get_attestations(
        attestation_query.slot,
        attestation_query.committee_index,
        attestation_query.attestation_data_root,
    );
    if attestations.is_empty() {
        return Err(ApiError::NotFound(String::from("No attestations found")));
    }

    let aggregated_attestation = compute_on_chain_aggregate(attestations).map_err(|err| {
        ApiError::InternalError(format!("Failed to compute attestation aggregate {err}"))
    })?;

    Ok(HttpResponse::Ok().json(DataVersionedResponse::new(aggregated_attestation)))
}

#[cfg(test)]
mod validator_api_tests {
    use super::*;
    use actix_web::{App, test};
    use ream_execution_rpc_types::{
        get_blobs::Blob,
        get_payload::{BlobsBundle, BlobsBundleV1, BlobsBundleV2},
    };
    use ream_storage::db::ReamDB;

    #[actix_web::test]
    async fn subscription_route_extracts_registered_p2p_sender() {
        let temp = tempdir::TempDir::new("subscription_rpc").unwrap();
        let db = ReamDB::new(temp.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let app = test::init_service(
            App::new()
                .app_data(Data::new(db))
                .app_data(Data::new(Arc::new(P2PSender(tx))))
                .service(post_sync_committee_subscriptions),
        )
        .await;
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/validator/sync_committee_subscriptions")
                .set_json(serde_json::json!([]))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
        let body = test::read_body(response).await;
        assert!(String::from_utf8_lossy(&body).contains("Empty request body"));
    }

    #[test]
    async fn checkpoint_uses_execution_hash_not_beacon_root() {
        let temp = tempdir::TempDir::new("checkpoint_rpc").unwrap();
        let db = ReamDB::new(temp.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let mut block = ream_consensus_beacon::electra::beacon_block::SignedBeaconBlock {
            message: Default::default(),
            signature: Default::default(),
        };
        let execution_hash = B256::repeat_byte(42);
        block.message.body.execution_payload.block_hash = execution_hash;
        let root = block.message.tree_hash_root();
        assert_ne!(root, execution_hash);
        db.block_provider().insert(root, block).unwrap();
        assert_eq!(
            execution_checkpoint_hash(&db, root).unwrap(),
            execution_hash
        );
        assert_eq!(
            execution_checkpoint_hash(&db, B256::ZERO).unwrap(),
            B256::ZERO
        );
        assert!(execution_checkpoint_hash(&db, B256::repeat_byte(9)).is_err());
    }

    #[test]
    async fn sync_positions_map_to_subnets_and_reject_out_of_range() {
        let committee = ream_consensus_beacon::sync_committee::SyncCommittee {
            public_keys: Default::default(),
            aggregate_public_key: Default::default(),
        };
        let key = committee.public_keys[0].clone();
        let subnets =
            sync_subscription_subnets(&committee, &committee, &key, &[0, 127, 128, 511]).unwrap();
        assert_eq!(subnets, HashSet::from([0, 1, 3]));
        assert!(sync_subscription_subnets(&committee, &committee, &key, &[512]).is_err());
        assert!(sync_subscription_subnets(&committee, &committee, &key, &[u64::MAX]).is_err());
    }

    #[test]
    async fn fulu_bundle_requires_cell_proofs_and_one_blob_per_commitment() {
        let mut bundle = BlobsBundleV2 {
            blobs: vec![Blob::default()].try_into().unwrap(),
            commitments: vec![KZGCommitment::empty_for_testing()].try_into().unwrap(),
            proofs: vec![KZGProof::default(); 128].try_into().unwrap(),
        };
        assert_eq!(
            validate_proposal_blob_bundle(&BlobsBundle::V2(bundle.clone())).unwrap(),
            128
        );
        bundle.proofs = vec![KZGProof::default()].try_into().unwrap();
        assert!(validate_proposal_blob_bundle(&BlobsBundle::V2(bundle)).is_err());
        let bundle = BlobsBundleV1 {
            blobs: vec![Blob::default()].try_into().unwrap(),
            commitments: vec![KZGCommitment::empty_for_testing()].try_into().unwrap(),
            proofs: vec![KZGProof::default()].try_into().unwrap(),
        };
        assert_eq!(
            validate_proposal_blob_bundle(&BlobsBundle::V1(bundle)).unwrap(),
            1
        );
    }
}
