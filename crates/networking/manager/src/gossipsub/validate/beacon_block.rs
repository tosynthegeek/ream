use std::time::{Duration, Instant};

use anyhow::anyhow;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::electra::{beacon_block::SignedBeaconBlock, beacon_state::BeaconState};
use ream_consensus_misc::{
    constants::beacon::MAX_BLOBS_PER_BLOCK_ELECTRA, misc::compute_start_slot_at_epoch,
};
use ream_storage::{
    cache::{AddressSlotIdentifier, BeaconCacheDB},
    tables::{field::REDBField, table::REDBTable},
};
use tree_hash::TreeHash;

use super::result::DependencyValidationResult;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipValidatedBlock {
    block: Box<SignedBeaconBlock>,
}

enum BlockValidationOutcome {
    Accept,
    Ignore(String),
    Reject(String),
    DeferUnknownParent,
}

impl GossipValidatedBlock {
    fn new(block: SignedBeaconBlock) -> Self {
        Self {
            block: Box::new(block),
        }
    }

    pub(crate) fn block(&self) -> &SignedBeaconBlock {
        &self.block
    }

    pub(crate) fn into_inner(self) -> SignedBeaconBlock {
        *self.block
    }
}

struct ParentContext {
    block: SignedBeaconBlock,
    state: BeaconState,
    pending_availability: bool,
}

pub async fn validate_gossip_beacon_block(
    beacon_chain: &BeaconChain,
    cached_db: &BeaconCacheDB,
    block: &SignedBeaconBlock,
) -> anyhow::Result<DependencyValidationResult<GossipValidatedBlock>> {
    let (head_state, parent) = {
        let store = beacon_chain.store.lock().await;
        let head_root = store.get_head()?;
        let head_state = store
            .db
            .state_provider()
            .get(head_root)?
            .ok_or_else(|| anyhow!("No beacon state found for head root: {head_root}"))?;

        let parent = if let Some(parent_block) =
            store.db.block_provider().get(block.message.parent_root)?
        {
            let Some(parent_state) = store.db.state_provider().get(block.message.parent_root)?
            else {
                return Err(anyhow!(
                    "failed to get state for known parent block {}",
                    block.message.parent_root
                ));
            };
            Some(ParentContext {
                block: parent_block,
                state: parent_state,
                pending_availability: false,
            })
        } else if let Some(pending) = store
            .data_availability_checker
            .pending_block(&block.message.parent_root)
        {
            if pending.signed_block.message.tree_hash_root() != block.message.parent_root {
                return Err(anyhow!(
                    "pending availability block root does not match lookup key"
                ));
            }
            Some(ParentContext {
                block: pending.signed_block.clone(),
                state: pending.post_state.clone(),
                pending_availability: true,
            })
        } else {
            None
        };
        (head_state, parent)
    };

    // Looking up the parent above does not classify the message. Validation still checks the
    // signature before returning unknown-parent, as required by the gossip specification.
    let state = parent.as_ref().map_or(&head_state, |parent| &parent.state);
    match validate_beacon_block(beacon_chain, cached_db, block, state, parent.as_ref()).await? {
        BlockValidationOutcome::Accept => {}
        BlockValidationOutcome::DeferUnknownParent => {
            return Ok(DependencyValidationResult::ParentPendingAvailability {
                parent_root: block.message.parent_root,
                validated: GossipValidatedBlock::new(block.clone()),
            });
        }
        BlockValidationOutcome::Ignore(reason) => {
            return Ok(DependencyValidationResult::Ignore(reason));
        }
        BlockValidationOutcome::Reject(reason) => {
            return Ok(DependencyValidationResult::Reject(reason));
        }
    }

    if parent.is_some_and(|parent| parent.pending_availability) {
        Ok(DependencyValidationResult::ParentPendingAvailability {
            parent_root: block.message.parent_root,
            validated: GossipValidatedBlock::new(block.clone()),
        })
    } else {
        Ok(DependencyValidationResult::Accept)
    }
}

async fn validate_beacon_block(
    beacon_chain: &BeaconChain,
    cached_db: &BeaconCacheDB,
    block: &SignedBeaconBlock,
    state: &BeaconState,
    parent: Option<&ParentContext>,
) -> anyhow::Result<BlockValidationOutcome> {
    // DIAGNOSTIC: validate_gossip_beacon_block itself showed up taking as long as ~6.9s on a
    // single block. This function is where the actual per-block cost lives (signature
    // verification, state advancement, proposer index / shuffling computation, ancestry walk) —
    // timing each step separately here, alongside the already-instrumented `store.get_head()`
    // cache-miss logging, should show whether it's this function or the store lookups around it
    // that dominates, and if it's this function, which specific step.
    let overall_start = Instant::now();
    macro_rules! log_step {
        ($label:expr, $start:expr) => {{
            let elapsed = $start.elapsed();
            if elapsed > Duration::from_millis(200) {
                tracing::warn!(
                    step = $label,
                    ?elapsed,
                    slot = block.message.slot,
                    "validate_beacon_block step was slow"
                );
            } else {
                tracing::debug!(
                    step = $label,
                    ?elapsed,
                    slot = block.message.slot,
                    "validate_beacon_block step finished"
                );
            }
        }};
    }

    let store = beacon_chain.store.lock().await;

    // [IGNORE] The block is not from a future slot.
    if block.message.slot > store.get_current_slot()? {
        return Ok(BlockValidationOutcome::Ignore(
            "Block is from a future slot".to_string(),
        ));
    }

    // [IGNORE] The block is from a slot greater than the latest finalized slot.
    let finalized_checkpoint = store.db.finalized_checkpoint_provider().get()?;
    if block.message.slot <= compute_start_slot_at_epoch(finalized_checkpoint.epoch) {
        return Ok(BlockValidationOutcome::Ignore(
            "Block is not from a slot greater than the latest finalized slot".to_string(),
        ));
    }

    let Some(validator) = state.validators.get(block.message.proposer_index as usize) else {
        return Ok(BlockValidationOutcome::Reject(
            "Validator not found".to_string(),
        ));
    };

    // [IGNORE] The block is the first block with valid signature received for the proposer for the
    // slot.
    if cached_db
        .seen_proposer_signature
        .read()
        .await
        .contains(&AddressSlotIdentifier {
            address: validator.public_key.clone(),
            slot: block.message.slot,
        })
    {
        return Ok(BlockValidationOutcome::Ignore(
            "Signature already received".to_string(),
        ));
    }

    // [REJECT] The proposer signature is valid with respect to the proposer_index pubkey.
    let signature_start = Instant::now();
    let signature_result = state.verify_block_header_signature(&block.signed_header());
    log_step!("verify_block_header_signature", signature_start);
    match signature_result {
        Ok(true) => {}
        Ok(false) => {
            return Ok(BlockValidationOutcome::Reject(
                "Invalid signature".to_string(),
            ));
        }
        Err(err) => {
            return Ok(BlockValidationOutcome::Reject(format!(
                "Signature verification failed: {err}"
            )));
        }
    }

    let Some(parent) = parent else {
        return Ok(BlockValidationOutcome::DeferUnknownParent);
    };

    // [REJECT] The block is from a higher slot than its parent.
    if block.message.slot <= parent.block.message.slot {
        return Ok(BlockValidationOutcome::Reject(
            "Block is not from a higher slot".to_string(),
        ));
    }

    #[cfg(not(feature = "disable_ancestor_validation"))]
    if !parent.pending_availability {
        let ancestry_start = Instant::now();
        let ancestor_ok = store
            .get_checkpoint_block(block.message.parent_root, finalized_checkpoint.epoch)?
            == finalized_checkpoint.root;
        log_step!("get_checkpoint_block_ancestry_walk", ancestry_start);
        if !ancestor_ok {
            return Ok(BlockValidationOutcome::Reject(
                "Finalized checkpoint is not an ancestor".to_string(),
            ));
        }
    }

    // A pending parent is not in the block DB, so an ancestry walk cannot cross it. At arrival we
    // can only check that the child is newer than finality and points to that exact pending block.
    // Finality can advance while it waits; release repeats the normal walk after parent import.

    // State advancement and cache access do not require exclusive access to the store.
    drop(store);
    let mut state = state.clone();
    let process_slots_start = Instant::now();
    let process_slots_result = state.process_slots(block.message.slot);
    log_step!("process_slots", process_slots_start);
    if let Err(err) = process_slots_result {
        return Ok(BlockValidationOutcome::Ignore(format!(
            "Could not advance parent state to block slot: {err:?}"
        )));
    }

    // [REJECT] The block is proposed by the expected proposer_index for the block's slot.
    let proposer_index_start = Instant::now();
    let proposer_index_result = state.get_beacon_proposer_index(None);
    log_step!("get_beacon_proposer_index", proposer_index_start);
    if proposer_index_result? != block.message.proposer_index {
        return Ok(BlockValidationOutcome::Reject(
            "Proposer index is incorrect".to_string(),
        ));
    }

    // [REJECT] The block's execution payload timestamp is correct with respect to the slot.
    if block.message.body.execution_payload.timestamp
        != state.compute_timestamp_at_slot(block.message.slot)
    {
        return Ok(BlockValidationOutcome::Reject(
            "Execution payload timestamp is incorrect".to_string(),
        ));
    }

    // [IGNORE] Every BLS-to-execution change is the first seen for its validator and this slot.
    for signed_bls_execution_change in &block.message.body.bls_to_execution_changes {
        let Some(change_validator) = state
            .validators
            .get(signed_bls_execution_change.message.validator_index as usize)
        else {
            return Ok(BlockValidationOutcome::Reject(
                "BLS to execution change validator not found".to_string(),
            ));
        };
        if cached_db
            .seen_bls_to_execution_signature
            .read()
            .await
            .contains(&AddressSlotIdentifier {
                address: change_validator.public_key.clone(),
                slot: block.message.slot,
            })
        {
            return Ok(BlockValidationOutcome::Ignore(
                "BLS to execution change already received".to_string(),
            ));
        }
    }

    // [REJECT] All process_bls_to_execution_change conditions pass validation.
    for signed_bls_execution_change in &block.message.body.bls_to_execution_changes {
        if state
            .validate_bls_to_execution_change(signed_bls_execution_change)
            .is_err()
        {
            return Ok(BlockValidationOutcome::Reject(
                "BLS to execution change is invalid".to_string(),
            ));
        }
    }

    // [REJECT] The length of KZG commitments is less than or equal to the limitation.
    if block.message.body.blob_kzg_commitments.len() > MAX_BLOBS_PER_BLOCK_ELECTRA as usize {
        return Ok(BlockValidationOutcome::Reject(
            "Length of KZG commitments is greater than the limit".to_string(),
        ));
    }

    // Epoch processing can extend the validator registry, so cache against the block-slot state.
    let validator = &state.validators[block.message.proposer_index as usize];
    let proposer_slot = AddressSlotIdentifier {
        address: validator.public_key.clone(),
        slot: block.message.slot,
    };
    let mut seen_proposer_signatures = cached_db.seen_proposer_signature.write().await;
    if seen_proposer_signatures.contains(&proposer_slot) {
        return Ok(BlockValidationOutcome::Ignore(
            "Signature already received".to_string(),
        ));
    }
    seen_proposer_signatures.put(proposer_slot, block.signature.clone());
    drop(seen_proposer_signatures);

    for signed_bls_execution_change in &block.message.body.bls_to_execution_changes {
        let validator =
            &state.validators[signed_bls_execution_change.message.validator_index as usize];
        cached_db.seen_bls_to_execution_signature.write().await.put(
            AddressSlotIdentifier {
                address: validator.public_key.clone(),
                slot: block.message.slot,
            },
            signed_bls_execution_change.message.clone(),
        );
    }

    log_step!("validate_beacon_block_total", overall_start);
    Ok(BlockValidationOutcome::Accept)
}
