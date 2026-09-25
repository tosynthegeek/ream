use std::sync::Arc;

use actix_web::{
    HttpResponse, Responder, get, post,
    web::{Data, Json, Path},
};
use alloy_primitives::B256;
use ream_api_types_beacon::{
    duties::{AttesterDuty, ProposerDuty, SyncCommitteeDuty},
    responses::DutiesResponse,
};
use ream_api_types_common::error::ApiError;
use ream_consensus_beacon::electra::beacon_state::BeaconState;
use ream_consensus_misc::{
    constants::beacon::{MIN_SEED_LOOKAHEAD, SLOTS_PER_EPOCH},
    misc::{compute_epoch_at_slot, compute_start_slot_at_epoch},
};
use ream_fork_choice_beacon::store::Store;
use ream_network_spec::networks::beacon_network_spec;
use ream_operation_pool::OperationPool;
use ream_storage::{db::beacon::BeaconDB, tables::table::REDBTable};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(untagged)]
enum ValidatorIndexRequest {
    Number(u64),
    String(String),
}

/// Returns the slot whose block root fixes the proposer shuffling for `epoch`.
/// Fulu moves it from the end of `N - 1` to `N - 2`; checking `epoch - 1` keeps the fork epoch on
/// the legacy boundary.
fn proposer_shuffling_decision_slot(epoch: u64, fulu_fork_epoch: u64) -> u64 {
    if epoch.saturating_sub(1) >= fulu_fork_epoch {
        compute_start_slot_at_epoch(epoch.saturating_sub(MIN_SEED_LOOKAHEAD)).saturating_sub(1)
    } else {
        compute_start_slot_at_epoch(epoch).saturating_sub(1)
    }
}

fn validate_proposer_duties_epoch(epoch: u64, current_epoch: u64) -> Result<(), ApiError> {
    if epoch > current_epoch.saturating_add(1) {
        return Err(ApiError::BadRequest(format!(
            "Request epoch {epoch} is more than one epoch past the current epoch {current_epoch}"
        )));
    }

    Ok(())
}

/// Reads the current epoch so future requests can be rejected before epoch-to-slot conversion.
fn current_epoch(store: &Store) -> Result<u64, ApiError> {
    let slot = store
        .get_current_slot()
        .map_err(|err| ApiError::InternalError(format!("Failed to get current slot: {err:?}")))?;

    Ok(compute_epoch_at_slot(slot))
}

/// Selects the dependent-root semantics returned by v1 and v2.
enum DependentRoot {
    Legacy,
    ForkAware,
}

async fn proposer_duties(
    db: &BeaconDB,
    epoch: u64,
    dependent_root_kind: DependentRoot,
) -> Result<HttpResponse, ApiError> {
    let store = Store::new(db.clone(), Arc::new(OperationPool::default()), None);
    let current_epoch = current_epoch(&store)?;
    validate_proposer_duties_epoch(epoch, current_epoch)?;

    // Convert only after the guard because epoch-to-slot multiplication is unchecked.
    let decision_slot = match dependent_root_kind {
        DependentRoot::Legacy => compute_start_slot_at_epoch(epoch).saturating_sub(1),
        DependentRoot::ForkAware => {
            proposer_shuffling_decision_slot(epoch, beacon_network_spec().fulu_fork_epoch)
        }
    };
    let start_slot = compute_start_slot_at_epoch(epoch);
    let (state, state_block_root) =
        get_canonical_state_and_block_root_at_or_before_slot(&store, start_slot).await?;
    let dependent_root = if state.slot <= decision_slot {
        state_block_root
    } else {
        state
            .get_block_root_at_slot(decision_slot)
            .map_err(|err| ApiError::NotFound(format!(
                "Failed to find the block root deciding the proposer shuffling for epoch {epoch}: {err}"
            )))?
    };
    let end_slot = start_slot + SLOTS_PER_EPOCH;
    let mut duties = vec![];
    for slot in start_slot..end_slot {
        let validator_index = state
            .get_beacon_proposer_index(Some(slot))
            .map_err(|err| ApiError::BadRequest(err.to_string()))?;
        let Some(validator) = state.validators.get(validator_index as usize) else {
            return Err(ApiError::ValidatorNotFound(format!("{validator_index}")));
        };
        duties.push(ProposerDuty {
            public_key: validator.public_key.clone(),
            validator_index,
            slot,
        });
    }
    Ok(HttpResponse::Ok().json(DutiesResponse::new(Some(dependent_root), duties)))
}

/// Serves v1 proposer duties with the legacy end-of-`N - 1` dependent root.
#[get("/validator/duties/proposer/{epoch}")]
pub async fn get_proposer_duties(
    db: Data<BeaconDB>,
    epoch: Path<u64>,
) -> Result<impl Responder, ApiError> {
    let epoch = epoch.into_inner();
    proposer_duties(&db, epoch, DependentRoot::Legacy).await
}

/// Serves v2 proposer duties with the fork-aware dependent root.
#[get("/validator/duties/proposer/{epoch}")]
pub async fn get_proposer_duties_v2(
    db: Data<BeaconDB>,
    epoch: Path<u64>,
) -> Result<impl Responder, ApiError> {
    let epoch = epoch.into_inner();
    proposer_duties(&db, epoch, DependentRoot::ForkAware).await
}

#[post("/validator/duties/attester/{epoch}")]
pub async fn get_attester_duties(
    db: Data<BeaconDB>,
    epoch: Path<u64>,
    validator_indices: Json<Vec<ValidatorIndexRequest>>,
) -> Result<impl Responder, ApiError> {
    let epoch = epoch.into_inner();
    let start_slot = compute_start_slot_at_epoch(epoch);
    let state = get_state_at_or_before_slot(&db, start_slot).await?;
    let dependent_root = if epoch == 0 {
        get_block_root_at_or_before_slot(&db, 0)?
    } else {
        get_block_root_at_or_before_slot(&db, start_slot - 1)?
    };
    let validator_indices = parse_validator_indices(validator_indices.into_inner())?;
    let committees_at_slot = state.get_committee_count_per_slot(epoch);
    let mut duties = vec![];

    for validator_index in validator_indices {
        let Some(validator) = state.validators.get(validator_index as usize) else {
            return Err(ApiError::ValidatorNotFound(format!(
                "Validator with index {validator_index} not found in state at epoch {epoch}"
            )));
        };

        if let Some((committee, committee_index, slot)) = state
            .get_committee_assignment(epoch, validator_index)
            .map_err(|err| {
                ApiError::BadRequest(format!(
                    "Failed to get committee assignment for validator {validator_index}: {err}"
                ))
            })?
        {
            let validator_committee_index = committee
                .iter()
                .position(|&index| index == validator_index)
                .ok_or_else(|| {
                    ApiError::BadRequest("Validator not found in assigned committee".to_string())
                })?;

            duties.push(AttesterDuty {
                public_key: validator.public_key.clone(),
                validator_index,
                committee_index,
                committee_length: committee.len() as u64,
                committees_at_slot,
                validator_committee_index: validator_committee_index as u64,
                slot,
            });
        }
    }
    Ok(HttpResponse::Ok().json(DutiesResponse::new(Some(dependent_root), duties)))
}

#[post("/validator/duties/sync/{epoch}")]
pub async fn get_sync_committee_duties(
    db: Data<BeaconDB>,
    epoch: Path<u64>,
    validator_indices: Json<Vec<ValidatorIndexRequest>>,
) -> Result<impl Responder, ApiError> {
    let epoch = epoch.into_inner();
    let state = get_state_at_or_before_slot(&db, compute_start_slot_at_epoch(epoch)).await?;
    let validator_indices = parse_validator_indices(validator_indices.into_inner())?;

    let mut duties = vec![];
    for validator_index in validator_indices {
        let Some(validator) = state.validators.get(validator_index as usize) else {
            return Err(ApiError::ValidatorNotFound(format!(
                "Validator with index {validator_index} not found in state at epoch {epoch}"
            )));
        };

        let sync_committee_indices = state
            .get_sync_committee_indices(&state.current_sync_committee)
            .map_err(|err| {
                ApiError::BadRequest(format!("Failed to get sync committee indices {err:?}"))
            })?;

        let validator_sync_committee_indices = sync_committee_indices
            .iter()
            .enumerate()
            .filter_map(|(index, &committee_index)| {
                if validator_index == committee_index as u64 {
                    Some(index as u64)
                } else {
                    None
                }
            })
            .collect();

        duties.push(SyncCommitteeDuty {
            public_key: validator.public_key.clone(),
            validator_index,
            validator_sync_committee_indices,
        });
    }
    Ok(HttpResponse::Ok().json(DutiesResponse::new(None, duties)))
}

fn parse_validator_indices(
    validator_indices: Vec<ValidatorIndexRequest>,
) -> Result<Vec<u64>, ApiError> {
    validator_indices
        .into_iter()
        .map(|index| match index {
            ValidatorIndexRequest::Number(index) => Ok(index),
            ValidatorIndexRequest::String(index) => index.parse::<u64>().map_err(|err| {
                ApiError::BadRequest(format!("Invalid validator index `{index}`: {err}"))
            }),
        })
        .collect()
}

/// Resolves from fork-choice head so an overwritten slot index cannot select a side fork.
async fn get_canonical_state_and_block_root_at_or_before_slot(
    store: &Store,
    slot: u64,
) -> Result<(BeaconState, B256), ApiError> {
    let head_root = store
        .get_head()
        .map_err(|err| ApiError::InternalError(format!("Failed to get head root: {err:?}")))?;
    let block_root = get_block_root_at_or_before_slot_from_head(store, head_root, slot)?;

    get_state_and_block_root(&store.db, block_root, slot).await
}

fn get_block_root_at_or_before_slot_from_head(
    store: &Store,
    head_root: B256,
    slot: u64,
) -> Result<B256, ApiError> {
    store.get_ancestor(head_root, slot).map_err(|err| {
        ApiError::InternalError(format!(
            "Failed to find canonical block root at or before slot {slot}: {err:?}"
        ))
    })
}

/// Loads the state at `slot` and the root of the block it was built on.
async fn get_state_and_block_root_at_or_before_slot(
    db: &BeaconDB,
    slot: u64,
) -> Result<(BeaconState, B256), ApiError> {
    let block_root = get_block_root_at_or_before_slot(db, slot)?;
    get_state_and_block_root(db, block_root, slot).await
}

async fn get_state_and_block_root(
    db: &BeaconDB,
    block_root: B256,
    slot: u64,
) -> Result<(BeaconState, B256), ApiError> {
    let mut state = db
        .state_provider()
        .get(block_root)
        .map_err(|err| {
            ApiError::InternalError(format!(
                "Failed to get beacon state by block root, error: {err:?}"
            ))
        })?
        .ok_or_else(|| {
            ApiError::NotFound(format!("Failed to find beacon state for slot {slot}"))
        })?;
    if state.slot < slot {
        state
            .process_slots(slot)
            .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    }
    Ok((state, block_root))
}

async fn get_state_at_or_before_slot(db: &BeaconDB, slot: u64) -> Result<BeaconState, ApiError> {
    Ok(get_state_and_block_root_at_or_before_slot(db, slot)
        .await?
        .0)
}

fn get_block_root_at_or_before_slot(db: &BeaconDB, slot: u64) -> Result<B256, ApiError> {
    for candidate_slot in (0..=slot).rev() {
        match db
            .slot_index_provider()
            .get(candidate_slot)
            .map_err(|err| {
                ApiError::InternalError(format!(
                    "Failed to get block root for slot {candidate_slot}, error: {err:?}"
                ))
            })? {
            Some(block_root) => return Ok(block_root),
            None => continue,
        }
    }

    Err(ApiError::NotFound(format!(
        "Failed to find block root at or before slot {slot}"
    )))
}

#[cfg(test)]
mod tests {
    use ream_bls::BLSSignature;
    use ream_consensus_beacon::electra::beacon_block::{BeaconBlock, SignedBeaconBlock};
    use ream_storage::db::ReamDB;
    use tempdir::TempDir;
    use tree_hash::TreeHash;

    use super::*;

    #[test]
    fn attester_duty_includes_quoted_committee_length() {
        let duty = AttesterDuty {
            public_key: Default::default(),
            validator_index: 7,
            committee_index: 0,
            committee_length: 3,
            committees_at_slot: 1,
            validator_committee_index: 2,
            slot: 5,
        };
        let json = serde_json::to_value(duty).unwrap();
        assert_eq!(json["committee_length"], "3");
    }

    fn test_db() -> (BeaconDB, TempDir) {
        let temp_dir = TempDir::new("ream_rpc_beacon_duties").expect("creates temp directory");
        let db = ReamDB::new(temp_dir.path().to_path_buf())
            .expect("creates database")
            .init_beacon_db()
            .expect("initializes beacon database");
        (db, temp_dir)
    }

    fn block(slot: u64, parent_root: B256, state_root: B256) -> SignedBeaconBlock {
        SignedBeaconBlock {
            message: BeaconBlock {
                slot,
                parent_root,
                state_root,
                ..Default::default()
            },
            signature: BLSSignature::default(),
        }
    }

    #[test]
    fn proposer_decision_slot_preserves_the_fulu_boundary() {
        let fulu_fork_epoch = 5;

        assert_eq!(
            proposer_shuffling_decision_slot(4, fulu_fork_epoch),
            4 * SLOTS_PER_EPOCH - 1
        );
        assert_eq!(
            proposer_shuffling_decision_slot(5, fulu_fork_epoch),
            5 * SLOTS_PER_EPOCH - 1
        );
        assert_eq!(
            proposer_shuffling_decision_slot(6, fulu_fork_epoch),
            5 * SLOTS_PER_EPOCH - 1
        );
    }

    #[test]
    fn proposer_decision_slot_saturates_at_genesis() {
        assert_eq!(proposer_shuffling_decision_slot(0, 0), 0);
        assert_eq!(proposer_shuffling_decision_slot(1, 0), 0);
        assert_eq!(proposer_shuffling_decision_slot(2, 0), SLOTS_PER_EPOCH - 1);
    }

    #[test]
    fn proposer_duties_reject_epochs_beyond_the_lookahead() {
        assert!(validate_proposer_duties_epoch(10, 10).is_ok());
        assert!(validate_proposer_duties_epoch(11, 10).is_ok());
        assert!(matches!(
            validate_proposer_duties_epoch(12, 10),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            validate_proposer_duties_epoch(u64::MAX, 10),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn canonical_lookup_ignores_a_later_side_fork_at_the_same_slot() {
        let (db, _temp_dir) = test_db();
        let anchor = block(0, B256::ZERO, B256::repeat_byte(1));
        let anchor_root = anchor.message.tree_hash_root();
        let canonical = block(100, anchor_root, B256::repeat_byte(2));
        let canonical_root = canonical.message.tree_hash_root();
        let side_fork = block(100, anchor_root, B256::repeat_byte(3));
        let side_fork_root = side_fork.message.tree_hash_root();

        db.block_provider()
            .insert(anchor_root, anchor)
            .expect("stores anchor block");
        db.block_provider()
            .insert(canonical_root, canonical)
            .expect("stores canonical block");
        db.block_provider()
            .insert(side_fork_root, side_fork)
            .expect("stores side-fork block");

        assert_eq!(
            db.slot_index_provider().get(100).expect("reads slot index"),
            Some(side_fork_root)
        );

        let store = Store::new(db, Arc::new(OperationPool::default()), None);
        assert_eq!(
            get_block_root_at_or_before_slot_from_head(&store, canonical_root, 100)
                .expect("resolves canonical ancestor"),
            canonical_root
        );
    }
}
