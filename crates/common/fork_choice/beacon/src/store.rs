use std::{cmp::Ordering, collections::VecDeque, sync::Arc};

use alloy_primitives::{B256, map::HashSet};
use anyhow::{anyhow, bail, ensure};
use hashbrown::HashMap;
use ream_bls::BLSSignature;
use ream_consensus_beacon::{
    attestation::Attestation,
    data_column_sidecar::ColumnIdentifier,
    electra::{
        beacon_block::{BeaconBlock, SignedBeaconBlock},
        beacon_state::BeaconState,
    },
    fork_choice::latest_message::LatestMessage,
    helpers::{calculate_committee_fraction, get_total_active_balance},
};
use ream_consensus_misc::{
    checkpoint::Checkpoint,
    constants::beacon::{GENESIS_EPOCH, GENESIS_SLOT, INTERVALS_PER_SLOT, SLOTS_PER_EPOCH},
    misc::{compute_epoch_at_slot, compute_start_slot_at_epoch, is_shuffling_stable},
};
use ream_data_availability::{DataAvailabilityChecker, PendingBlock};
use ream_metrics::{
    BEACON_CURRENT_ACTIVE_VALIDATORS, BEACON_CURRENT_JUSTIFIED_EPOCH, BEACON_FINALIZED_EPOCH,
    BEACON_PREVIOUS_JUSTIFIED_EPOCH,
};
use ream_network_spec::networks::beacon_network_spec;
use ream_operation_pool::OperationPool;
use ream_storage::{
    db::beacon::BeaconDB,
    errors::StoreError,
    tables::{
        field::{CustomField, REDBField},
        multimap_table::MultimapTable,
        table::{CustomTable, REDBTable},
    },
};
use ream_sync_committee_pool::SyncCommitteePool;
use tracing::{debug, warn};
use tree_hash::TreeHash;

use crate::{
    constants::{
        PROPOSER_SCORE_BOOST, REORG_HEAD_WEIGHT_THRESHOLD, REORG_MAX_EPOCHS_SINCE_FINALIZATION,
        REORG_PARENT_WEIGHT_THRESHOLD,
    },
    fork_choice_tree::{ForkChoiceBlock, ForkChoiceTree, ViabilityContext},
};

const VALIDATOR_API_SYNC_TOLERANCE_EPOCHS: u64 = 2;

#[derive(Debug)]
pub struct BlockWithEpochInfo {
    pub block: BeaconBlock,
    pub justified_epoch: u64,
    pub finalized_epoch: u64,
}

#[derive(Debug)]
pub struct Store {
    pub db: BeaconDB,
    pub data_availability_checker: DataAvailabilityChecker,
    pub operation_pool: Arc<OperationPool>,
    pub sync_committee_pool: Arc<SyncCommitteePool>,
    fork_choice: Option<ForkChoiceTree>,
}

impl Store {
    pub fn new(
        db: BeaconDB,
        operation_pool: Arc<OperationPool>,
        sync_committee_pool: Option<Arc<SyncCommitteePool>>,
    ) -> Self {
        let sync_committee_pool =
            sync_committee_pool.unwrap_or_else(|| Arc::new(SyncCommitteePool::default()));
        Self {
            db,
            data_availability_checker: DataAvailabilityChecker::supernode(),
            operation_pool,
            sync_committee_pool,
            fork_choice: None,
        }
    }

    pub fn backfill_data_availability_columns(
        &mut self,
        block_root: B256,
    ) -> anyhow::Result<Option<PendingBlock>> {
        backfill_data_availability_columns_from_db(
            &self.db,
            &mut self.data_availability_checker,
            block_root,
        )
    }

    pub fn is_previous_epoch_justified(&self) -> anyhow::Result<bool> {
        let current_epoch = self.get_current_store_epoch()?;
        Ok(self.db.justified_checkpoint_provider().get()?.epoch + 1 == current_epoch)
    }

    pub fn get_current_store_epoch(&self) -> anyhow::Result<u64> {
        Ok(compute_epoch_at_slot(self.get_current_slot()?))
    }

    pub fn get_current_slot(&self) -> anyhow::Result<u64> {
        Ok(GENESIS_SLOT + self.get_slots_since_genesis()?)
    }

    pub fn get_slots_since_genesis(&self) -> anyhow::Result<u64> {
        Ok(self
            .db
            .time_provider()
            .get()?
            .saturating_sub(self.db.genesis_time_provider().get()?)
            / beacon_network_spec().seconds_per_slot())
    }

    pub fn get_ancestor(&self, root: B256, slot: u64) -> anyhow::Result<B256> {
        let block = self
            .db
            .block_provider()
            .get(root)?
            .ok_or(anyhow!("Failed to find beacon_block_provider()"))?
            .message;
        if block.slot > slot {
            self.get_ancestor(block.parent_root, slot)
        } else {
            Ok(root)
        }
    }

    /// Compute the checkpoint block for epoch ``epoch`` in the chain of block ``root``
    pub fn get_checkpoint_block(&self, root: B256, epoch: u64) -> anyhow::Result<B256> {
        let epoch_first_slot = compute_start_slot_at_epoch(epoch);
        self.get_ancestor(root, epoch_first_slot)
    }

    pub fn filter_block_tree(
        &self,
        block_root: B256,
        blocks: &mut HashMap<B256, BlockWithEpochInfo>,
    ) -> anyhow::Result<bool> {
        let Some(block) = self.db.block_provider().get(block_root)? else {
            bail!("failed to get block");
        };

        // If any children branches contain expected finalized/justified checkpoints,
        // add to filtered block-tree and signal viability to parent.
        let children = self
            .db
            .parent_root_index_multimap_provider()
            .get(block_root)?
            .unwrap_or_default();

        if !children.is_empty() {
            let filter_results = children
                .iter()
                .map(|child| self.filter_block_tree(*child, blocks))
                .collect::<anyhow::Result<Vec<_>>>()?;

            if filter_results.iter().any(|&result| result) {
                let voting_source = self.get_voting_source(block_root)?;
                let finalized_epoch = self.db.finalized_checkpoint_provider().get()?.epoch;

                blocks.insert(
                    block_root,
                    BlockWithEpochInfo {
                        block: block.message.clone(),
                        // NOTE: Use the node's own `voting_source.epoch` as its `justified_epoch`,
                        // as it means this node justifies the source.
                        justified_epoch: voting_source.epoch,
                        finalized_epoch,
                    },
                );
                return Ok(true);
            }
            return Ok(false);
        }

        let current_epoch = self.get_current_store_epoch()?;
        let voting_source = self.get_voting_source(block_root)?;

        // The voting source should be either at the same height as the store's justified checkpoint
        // or not more than two epochs ago
        let justified_checkpoint_epoch = self.db.justified_checkpoint_provider().get()?.epoch;
        let correct_justified = justified_checkpoint_epoch == GENESIS_EPOCH || {
            voting_source.epoch == justified_checkpoint_epoch
                || voting_source.epoch + 2 >= current_epoch
        };

        let finalized_checkpoint = self.db.finalized_checkpoint_provider().get()?;
        let finalized_checkpoint_block =
            self.get_checkpoint_block(block_root, finalized_checkpoint.epoch)?;

        let correct_finalized = finalized_checkpoint.epoch == GENESIS_EPOCH
            || finalized_checkpoint.root == finalized_checkpoint_block;

        // If expected finalized/justified, add to viable block-tree and signal viability to parent.
        if correct_justified && correct_finalized {
            blocks.insert(
                block_root,
                BlockWithEpochInfo {
                    block: block.message.clone(),
                    // NOTE: Use the node's own `voting_source.epoch` as its `justified_epoch`,
                    // as it means this node justifies the source.
                    justified_epoch: voting_source.epoch,
                    finalized_epoch: finalized_checkpoint.epoch,
                },
            );
            return Ok(true);
        }

        // Otherwise, branch not viable
        Ok(false)
    }

    /// Retrieve a filtered block tree from ``store``, only returning branches
    /// whose leaf state's justified/finalized info agrees with that in ``store``.
    ///
    /// NOTE: ``blocks`` must contain justified/finalized epoch information of its node, so struct
    /// ``BlockWithEpochInfo`` which contains ``justified_epoch`` and ``finalized_epoch`` should
    /// be the value of the map.
    pub fn get_filtered_block_tree(&self) -> anyhow::Result<HashMap<B256, BlockWithEpochInfo>> {
        let base = self.db.justified_checkpoint_provider().get()?.root;
        let mut blocks = HashMap::default();
        self.filter_block_tree(base, &mut blocks)?;
        Ok(blocks)
    }

    pub fn get_head(&self) -> anyhow::Result<B256> {
        match &self.fork_choice {
            Some(tree) => Ok(tree.head()),
            None => self.get_head_from_db(),
        }
    }

    pub fn get_head_from_db(&self) -> anyhow::Result<B256> {
        // Get filtered block tree that only includes viable branches
        let blocks = self.get_filtered_block_tree()?;
        // Execute the LMD-GHOST fork choice
        let mut head = self.db.justified_checkpoint_provider().get()?.root;

        loop {
            let mut children = vec![];
            for root in blocks.keys() {
                if blocks[root].block.parent_root == head {
                    children.push(root);
                }
            }

            if children.is_empty() {
                return Ok(head);
            }

            if children.len() == 1 {
                head = *children[0];
                continue;
            }

            let mut weighted_children = children
                .into_iter()
                .map(|child| Ok((*child, self.get_weight(*child)?)))
                .collect::<anyhow::Result<Vec<_>>>()?;

            // Sort by latest attesting balance with ties broken lexicographically
            // Ties broken by favoring block with lexicographically higher root
            weighted_children.sort_by(|(a, weight_a), (b, weight_b)| {
                match weight_a.cmp(weight_b) {
                    Ordering::Equal => a.cmp(b),
                    other => other,
                }
            });

            let Some((best_child, _)) = weighted_children.last() else {
                bail!("Children should always be present");
            };

            head = *best_child;
        }
    }

    /// Builds the in-memory fork choice tree from the database and starts maintaining it.
    pub fn enable_fork_choice_tree(&mut self) -> anyhow::Result<()> {
        self.fork_choice = None;

        let finalized_checkpoint = self.db.finalized_checkpoint_provider().get()?;
        let justified_checkpoint = self.db.justified_checkpoint_provider().get()?;
        let current_epoch = self.get_current_store_epoch()?;

        let anchor = self.fork_choice_block_from_db(finalized_checkpoint.root, current_epoch)?;
        let mut tree = ForkChoiceTree::new(
            anchor,
            ViabilityContext {
                justified_checkpoint,
                finalized_checkpoint,
                current_epoch,
            },
        );

        // Breadth-first so every parent is inserted before its children.
        let mut queue = VecDeque::from([finalized_checkpoint.root]);
        while let Some(parent_root) = queue.pop_front() {
            let children = self
                .db
                .parent_root_index_multimap_provider()
                .get(parent_root)?
                .unwrap_or_default();
            for child_root in children {
                tree.insert(self.fork_choice_block_from_db(child_root, current_epoch)?)?;
                queue.push_back(child_root);
            }
        }

        // Balances must be loaded before votes so they are counted with the right weight.
        self.reconcile_fork_choice_tree(&mut tree)?;
        match self.db.equivocating_indices_provider().get() {
            Ok(indices) => tree.mark_equivocating(indices),
            Err(StoreError::FieldNotInitilized) => {}
            Err(err) => return Err(err.into()),
        }
        tree.process_votes(
            self.db
                .latest_messages_provider()
                .get_all()?
                .into_iter()
                .map(|(validator_index, message)| (validator_index, message.root)),
        );

        self.fork_choice = Some(tree);
        Ok(())
    }

    pub fn is_fork_choice_tree_enabled(&self) -> bool {
        self.fork_choice.is_some()
    }

    /// Brings the fork choice tree in line with the checkpoints, time and proposer boost stored in
    /// the database: prunes at a new finalized root, refreshes viability on justified/finalized/
    /// epoch changes, reloads balances when the justified checkpoint changed and applies the
    /// proposer boost.
    pub fn refresh_fork_choice(&mut self) {
        let Some(mut tree) = self.fork_choice.take() else {
            return;
        };
        match self.reconcile_fork_choice_tree(&mut tree) {
            Ok(()) => self.fork_choice = Some(tree),
            Err(err) => self.recover_fork_choice(err),
        }
    }

    /// Adds a freshly imported block to the fork choice tree. Must run after the block, its state
    /// and its unrealized justification are in the database.
    pub fn fork_choice_insert_block(
        &mut self,
        block_root: B256,
        parent_root: B256,
        slot: u64,
        justified_checkpoint: Checkpoint,
    ) {
        if self.fork_choice.is_none() {
            return;
        }
        let unrealized_justified_checkpoint = self
            .db
            .unrealized_justifications_provider()
            .get(block_root)
            .ok()
            .flatten()
            .unwrap_or(justified_checkpoint);
        let result = match self.fork_choice.as_mut() {
            Some(tree) => tree.insert(ForkChoiceBlock {
                root: block_root,
                parent_root,
                slot,
                justified_checkpoint,
                unrealized_justified_checkpoint,
            }),
            None => return,
        };
        if let Err(err) = result {
            self.recover_fork_choice(err);
        }
    }

    /// Removes the fork choice influence of validators found equivocating.
    pub fn fork_choice_mark_equivocating(&mut self, indices: impl IntoIterator<Item = u64>) {
        if let Some(tree) = self.fork_choice.as_mut() {
            tree.mark_equivocating(indices);
        }
    }

    fn recover_fork_choice(&mut self, err: anyhow::Error) {
        warn!("Fork choice tree is out of sync ({err:#}), rebuilding it from the database");
        if let Err(err) = self.enable_fork_choice_tree() {
            warn!(
                "Failed to rebuild the fork choice tree, computing the head from the database: {err:#}"
            );
            self.fork_choice = None;
        }
    }

    fn reconcile_fork_choice_tree(&mut self, tree: &mut ForkChoiceTree) -> anyhow::Result<()> {
        let finalized_checkpoint = self.db.finalized_checkpoint_provider().get()?;
        let justified_checkpoint = self.db.justified_checkpoint_provider().get()?;

        if tree.root() != finalized_checkpoint.root {
            tree.prune(finalized_checkpoint.root)?;
        }
        tree.update_context(ViabilityContext {
            justified_checkpoint,
            finalized_checkpoint,
            current_epoch: self.get_current_store_epoch()?,
        });

        if tree.balances_checkpoint() != Some(justified_checkpoint) {
            self.load_fork_choice_balances(tree, justified_checkpoint)?;
        }

        let proposer_boost_root = self.db.proposer_boost_root_provider().get()?;
        tree.set_proposer_boost_root(
            (proposer_boost_root != B256::ZERO).then_some(proposer_boost_root),
        );
        Ok(())
    }

    /// Loads validator balances from the justified checkpoint state, exactly as `get_weight`
    /// derives them: active, unslashed validators' effective balances.
    fn load_fork_choice_balances(
        &mut self,
        tree: &mut ForkChoiceTree,
        justified_checkpoint: Checkpoint,
    ) -> anyhow::Result<()> {
        let mut justified_state = self
            .db
            .checkpoint_states_provider()
            .get(justified_checkpoint)?;
        if justified_state.is_none() {
            // A newly justified checkpoint's state is normally stored when an attestation targeting
            // it is processed, which can come after the block that justified it.
            self.store_target_checkpoint_state(justified_checkpoint)?;
            justified_state = self
                .db
                .checkpoint_states_provider()
                .get(justified_checkpoint)?;
        }
        let Some(state) = justified_state else {
            // Keep the previous balances; `balances_checkpoint` stays behind so the next refresh
            // retries.
            debug!("Justified checkpoint state is not available yet, keeping previous balances");
            return Ok(());
        };

        let mut balances = vec![0; state.validators.len()];
        for index in state.get_active_validator_indices(state.get_current_epoch()) {
            let validator = &state.validators[index as usize];
            if !validator.slashed {
                balances[index as usize] = validator.effective_balance;
            }
        }
        // Same derivation as `get_proposer_score`.
        let proposer_score =
            (get_total_active_balance(&state) / SLOTS_PER_EPOCH * PROPOSER_SCORE_BOOST) / 100;

        tree.set_balances(justified_checkpoint, balances, proposer_score);
        Ok(())
    }

    fn fork_choice_block_from_db(
        &self,
        root: B256,
        current_epoch: u64,
    ) -> anyhow::Result<ForkChoiceBlock> {
        let block = self
            .db
            .block_provider()
            .get(root)?
            .ok_or_else(|| anyhow!("block {root} not found"))?
            .message;
        let unrealized = self.db.unrealized_justifications_provider().get(root)?;
        let realized = if compute_epoch_at_slot(block.slot) >= current_epoch {
            self.db
                .state_provider()
                .get(root)?
                .map(|state| state.current_justified_checkpoint)
        } else {
            None
        };
        let justified_checkpoint = realized
            .or(unrealized)
            .ok_or_else(|| anyhow!("no voting source available for block {root}"))?;
        Ok(ForkChoiceBlock {
            root,
            parent_root: block.parent_root,
            slot: block.slot,
            justified_checkpoint,
            unrealized_justified_checkpoint: unrealized.unwrap_or(justified_checkpoint),
        })
    }

    /// Update checkpoints in store if necessary
    pub fn update_checkpoints(
        &mut self,
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
        previous_justified_checkpoint: Checkpoint,
    ) -> anyhow::Result<()> {
        // Update justified checkpoint
        if justified_checkpoint.epoch > self.db.justified_checkpoint_provider().get()?.epoch {
            self.db
                .justified_checkpoint_provider()
                .insert(justified_checkpoint)?;
            BEACON_CURRENT_JUSTIFIED_EPOCH.set(justified_checkpoint.epoch as i64);
        }

        self.db
            .previous_justified_checkpoint_provider()
            .insert(previous_justified_checkpoint)?;
        BEACON_PREVIOUS_JUSTIFIED_EPOCH.set(previous_justified_checkpoint.epoch as i64);

        // Update finalized checkpoint
        if finalized_checkpoint.epoch > self.db.finalized_checkpoint_provider().get()?.epoch {
            self.db
                .finalized_checkpoint_provider()
                .insert(finalized_checkpoint)?;
            BEACON_FINALIZED_EPOCH.set(finalized_checkpoint.epoch as i64);
            // Clean operation pool
            if let Some(state) = self.db.state_provider().get(finalized_checkpoint.root)? {
                self.operation_pool.clean_signed_voluntary_exits(&state);

                // Clean expired proposer preparations
                let current_epoch = self.get_current_store_epoch()?;
                self.operation_pool
                    .clean_proposer_preparations(current_epoch);

                if let Some(block) = self.db.block_provider().get(finalized_checkpoint.root)? {
                    for signed_bls_to_execution_change in
                        block.message.body.bls_to_execution_changes
                    {
                        self.operation_pool.remove_signed_bls_to_execution_change(
                            signed_bls_to_execution_change.tree_hash_root(),
                        );
                    }
                }
            }

            // Prune old blobs based on the retention period
            let current_slot = self.get_current_slot()?;
            let min_retention_epochs = beacon_network_spec().min_epochs_for_blob_sidecars_requests;
            match self.db.prune_old_blobs(current_slot, min_retention_epochs) {
                Ok(pruned_count) => {
                    if pruned_count > 0 {
                        tracing::info!("Pruned {} old blobs", pruned_count);
                    }
                }
                Err(err) => {
                    tracing::error!("Failed to prune old blobs: {}", err);
                }
            }
        }

        Ok(())
    }

    /// Update unrealized checkpoints in store if necessary
    pub fn update_unrealized_checkpoints(
        &mut self,
        unrealized_justified_checkpoint: Checkpoint,
        unrealized_finalized_checkpoint: Checkpoint,
    ) -> anyhow::Result<()> {
        // Update unrealized justified checkpoint
        if unrealized_justified_checkpoint.epoch
            > self
                .db
                .unrealized_justified_checkpoint_provider()
                .get()?
                .epoch
        {
            self.db
                .unrealized_justified_checkpoint_provider()
                .insert(unrealized_justified_checkpoint)?;
        }

        // Update unrealized finalized checkpoint
        if unrealized_finalized_checkpoint.epoch
            > self
                .db
                .unrealized_finalized_checkpoint_provider()
                .get()?
                .epoch
        {
            self.db
                .unrealized_finalized_checkpoint_provider()
                .insert(unrealized_finalized_checkpoint)?;
        }

        Ok(())
    }

    // Helper functions
    pub fn is_head_late(&self, head_root: B256) -> anyhow::Result<bool> {
        Ok(!self
            .db
            .block_timeliness_provider()
            .get(head_root)?
            .unwrap_or(true))
    }

    pub fn is_ffg_competitive(&self, head_root: B256, parent_root: B256) -> anyhow::Result<bool> {
        Ok(self
            .db
            .unrealized_justifications_provider()
            .get(head_root)?
            == self
                .db
                .unrealized_justifications_provider()
                .get(parent_root)?)
    }

    pub fn is_proposing_on_time(&self) -> anyhow::Result<bool> {
        // Use half `SECONDS_PER_SLOT // INTERVALS_PER_SLOT` as the proposer reorg deadline
        let time_into_slot = (self.db.time_provider().get()?
            - self.db.genesis_time_provider().get()?)
            % beacon_network_spec().seconds_per_slot();
        let proposer_reorg_cutoff =
            beacon_network_spec().seconds_per_slot() / INTERVALS_PER_SLOT / 2;
        Ok(time_into_slot <= proposer_reorg_cutoff)
    }

    pub fn is_finalization_ok(&self, slot: u64) -> anyhow::Result<bool> {
        let epochs_since_finalization =
            compute_epoch_at_slot(slot) - self.db.finalized_checkpoint_provider().get()?.epoch;
        Ok(epochs_since_finalization <= REORG_MAX_EPOCHS_SINCE_FINALIZATION)
    }

    pub fn get_proposer_score(&self) -> anyhow::Result<u64> {
        let justified_checkpoint_state = self
            .db
            .checkpoint_states_provider()
            .get(self.db.justified_checkpoint_provider().get()?)?
            .ok_or(anyhow!("Failed to find checkpoint in checkpoint states"))?;
        let committee_weight =
            get_total_active_balance(&justified_checkpoint_state) / SLOTS_PER_EPOCH;

        Ok((committee_weight * PROPOSER_SCORE_BOOST) / 100)
    }

    pub fn get_weight(&self, root: B256) -> anyhow::Result<u64> {
        let state = &self
            .db
            .checkpoint_states_provider()
            .get(self.db.justified_checkpoint_provider().get()?)?
            .ok_or_else(|| anyhow!("checkpoint_states not found"))?;

        let unslashed_and_active_indices: Vec<u64> = state
            .get_active_validator_indices(state.get_current_epoch())
            .into_iter()
            .filter(|&i| !state.validators[i as usize].slashed)
            .collect();

        let mut attestation_score: u64 = 0;
        for index in unslashed_and_active_indices {
            if self.db.latest_messages_provider().get(index)?.is_some()
                && !self
                    .db
                    .equivocating_indices_provider()
                    .get()?
                    .contains(&index)
                && self.get_ancestor(
                    self.db
                        .latest_messages_provider()
                        .get(index)?
                        .ok_or_else(|| anyhow!("latest_messages not found"))?
                        .root,
                    self.db
                        .block_provider()
                        .get(root)?
                        .ok_or_else(|| anyhow!(" block not found"))?
                        .message
                        .slot,
                )? == root
            {
                attestation_score += state.validators[index as usize].effective_balance;
            }
        }

        if self.db.proposer_boost_root_provider().get()? == B256::ZERO {
            // Return only attestation score if ``proposer_boost_root`` is not set
            return Ok(attestation_score);
        }

        // Calculate proposer score if ``proposer_boost_root`` is set
        // Boost is applied if ``root`` is an ancestor of ``proposer_boost_root``
        let proposer_score = if self.get_ancestor(
            self.db.proposer_boost_root_provider().get()?,
            self.db
                .block_provider()
                .get(root)?
                .ok_or_else(|| anyhow!("block not found"))?
                .message
                .slot,
        )? == root
        {
            self.get_proposer_score()?
        } else {
            0
        };

        Ok(attestation_score + proposer_score)
    }

    // Compute the voting source checkpoint in event that block with root ``block_root`` is the head
    // block
    pub fn get_voting_source(&self, block_root: B256) -> anyhow::Result<Checkpoint> {
        let block = self
            .db
            .block_provider()
            .get(block_root)?
            .ok_or_else(|| anyhow!("block not found"))?;

        let current_epoch = self.get_current_store_epoch()?;
        let block_epoch = compute_epoch_at_slot(block.message.slot);

        if current_epoch > block_epoch {
            // The block is from a prior epoch, the voting source will be pulled-up
            Ok(self
                .db
                .unrealized_justifications_provider()
                .get(block_root)?
                .ok_or_else(|| anyhow!("unrealized_justifications not found"))?)
        } else {
            // The block is not from a prior epoch, therefore the voting source is not pulled up
            let head_state = self
                .db
                .state_provider()
                .get(block_root)?
                .ok_or_else(|| anyhow!("state not found"))?;
            Ok(head_state.current_justified_checkpoint)
        }
    }

    pub fn is_head_weak(&self, head_root: B256) -> anyhow::Result<bool> {
        let justified_state = self
            .db
            .checkpoint_states_provider()
            .get(self.db.justified_checkpoint_provider().get()?)?
            .ok_or(anyhow!("Justified checkpoint must exist in the store"))?;

        let reorg_threshold =
            calculate_committee_fraction(&justified_state, REORG_HEAD_WEIGHT_THRESHOLD);
        let head_weight = self.get_weight(head_root)?;

        Ok(head_weight < reorg_threshold)
    }

    pub fn is_parent_strong(&self, parent_root: B256) -> anyhow::Result<bool> {
        let justified_state = self
            .db
            .checkpoint_states_provider()
            .get(self.db.justified_checkpoint_provider().get()?)?
            .ok_or(anyhow!("Justified checkpoint must exist in the store"))?;

        let parent_threshold =
            calculate_committee_fraction(&justified_state, REORG_PARENT_WEIGHT_THRESHOLD);
        let parent_weight = self.get_weight(parent_root)?;

        Ok(parent_weight > parent_threshold)
    }

    pub fn get_proposer_head(&self, head_root: B256, slot: u64) -> anyhow::Result<B256> {
        let head_block = self
            .db
            .block_provider()
            .get(head_root)?
            .ok_or(anyhow!("Head block must exist"))?;
        let parent_root = head_block.message.parent_root;
        let parent_block = self
            .db
            .block_provider()
            .get(parent_root)?
            .ok_or(anyhow!("Parent block must exist"))?;

        // Only re-org the head block if it arrived later than the attestation deadline.
        let head_late = self.is_head_late(head_root)?;

        // Do not re-org on an epoch boundary where the proposer shuffling could change.
        let shuffling_stable = is_shuffling_stable(slot);

        // Ensure that the FFG information of the new head will be competitive with the current
        // head.
        let ffg_competitive = self.is_ffg_competitive(head_root, parent_root)?;

        // Do not re-org if the chain is not finalizing with acceptable frequency.
        let finalization_ok = self.is_finalization_ok(slot)?;

        // Only re-org if we are proposing on-time.
        let proposing_on_time = self.is_proposing_on_time()?;

        // Only re-org a single slot at most.
        let parent_slot_ok = parent_block.message.slot + 1 == head_block.message.slot;
        let current_time_ok = head_block.message.slot + 1 == slot;
        let single_slot_reorg = parent_slot_ok && current_time_ok;

        // Check that the head has few enough votes to be overpowered by our proposer boost.
        assert!(self.db.proposer_boost_root_provider().get()? != head_root); // Ensure boost has worn off
        let head_weak = self.is_head_weak(head_root)?;

        // Check that the missing votes are assigned to the parent and not being hoarded.
        let parent_strong = self.is_parent_strong(parent_root)?;

        if head_late
            && shuffling_stable
            && ffg_competitive
            && finalization_ok
            && proposing_on_time
            && single_slot_reorg
            && head_weak
            && parent_strong
        {
            // We can re-org the current head by building upon its parent block.
            Ok(parent_root)
        } else {
            Ok(head_root)
        }
    }

    pub fn update_latest_messages(
        &mut self,
        attesting_indices: Vec<u64>,
        attestation: Attestation,
    ) -> anyhow::Result<()> {
        let target = attestation.data.target;
        let beacon_block_root = attestation.data.beacon_block_root;
        let mut non_equivocating_attesting_indices = vec![];

        let equivocating = self
            .db
            .equivocating_indices_provider()
            .get()
            .unwrap_or_default();

        for &index in &attesting_indices {
            if !equivocating.contains(&index) {
                non_equivocating_attesting_indices.push(index);
            }
        }

        let latest_messages = self.db.latest_messages_provider();
        let mut updates = Vec::new();
        for index in non_equivocating_attesting_indices {
            if latest_messages
                .get(index)?
                .is_none_or(|message| target.epoch > message.epoch)
            {
                updates.push((
                    index,
                    LatestMessage {
                        epoch: target.epoch,
                        root: beacon_block_root,
                    },
                ));
            }
        }
        if !updates.is_empty() {
            let votes = updates
                .iter()
                .map(|(index, message)| (*index, message.root))
                .collect::<Vec<_>>();
            latest_messages.insert_batch(updates)?;
            if let Some(tree) = self.fork_choice.as_mut() {
                tree.process_votes(votes);
            }
        }

        Ok(())
    }

    pub fn on_tick_per_slot(&mut self, time: u64) -> anyhow::Result<()> {
        let previous_slot = self.get_current_slot()?;

        // Update store time
        self.db.time_provider().insert(time)?;

        let current_slot = self.get_current_slot()?;

        // If this is a new slot, reset store.proposer_boost_root
        if current_slot > previous_slot {
            self.db.proposer_boost_root_provider().insert(B256::ZERO)?;

            // Clean old sync committee messages and contributions per slot
            self.sync_committee_pool
                .clean_sync_committee_messages(current_slot);
            self.sync_committee_pool
                .clean_sync_committee_contributions(current_slot);

            // A finalized checkpoint only finalizes the checkpoint slot, not every block in its
            // epoch. Keep pending blocks from later slots in that epoch while pruning entries at
            // or before the finalized slot and entries outside the sidecar retention window.
            let cutoff_slot = pending_availability_cutoff_slot(
                self.db.finalized_checkpoint_provider().get()?.epoch,
                self.get_current_store_epoch()?,
                beacon_network_spec().min_epochs_for_data_column_sidecars_requests,
            );
            let pruned_availability = self.data_availability_checker.prune(cutoff_slot);
            if pruned_availability > 0 {
                debug!("Pruned {pruned_availability} stale pending availability entries");
            }

            // Drop attestations that have aged out of the inclusion window (nothing else prunes
            // them, and they can never be included again).
            self.operation_pool
                .clean_attestations(compute_epoch_at_slot(current_slot));
        }

        // If a new epoch, pull-up justification and finalization from previous epoch
        if current_slot > previous_slot && compute_slots_since_epoch_start(current_slot) == 0 {
            match self.get_head() {
                Ok(head) => {
                    if let Some(state) = self.db.state_provider().get(head)? {
                        let active_count = state
                            .get_active_validator_indices(state.get_current_epoch())
                            .len();
                        BEACON_CURRENT_ACTIVE_VALIDATORS.set(active_count as i64);
                    } else {
                        tracing::warn!("Could not find head state for active validators metric");
                    }
                }
                Err(err) => {
                    tracing::warn!("Failed to get head for active validators metric: {err:?}");
                }
            };

            let unrealized_justified = self.db.unrealized_justified_checkpoint_provider().get()?;
            let unrealized_finalized = self.db.unrealized_finalized_checkpoint_provider().get()?;

            // On epoch boundary, previous_justified becomes what was previously current justified
            let previous_justified = self.db.justified_checkpoint_provider().get()?;
            self.update_checkpoints(
                unrealized_justified,
                unrealized_finalized,
                previous_justified,
            )?;
        }

        self.refresh_fork_choice();

        Ok(())
    }

    pub fn validate_target_epoch_against_current_time(
        &mut self,
        attestation: &Attestation,
    ) -> anyhow::Result<()> {
        let target = attestation.data.target;

        // Attestations must be from the current or previous epoch
        let current_epoch = self.get_current_store_epoch()?;

        // Use GENESIS_EPOCH for previous when genesis to avoid underflow
        let previous_epoch = if current_epoch > GENESIS_EPOCH {
            current_epoch - 1
        } else {
            GENESIS_EPOCH
        };

        // If attestation target is from a future epoch, delay consideration until the epoch arrives
        ensure!([current_epoch, previous_epoch].contains(&target.epoch));

        Ok(())
    }

    pub fn validate_on_attestation(
        &mut self,
        attestation: &Attestation,
        is_from_block: bool,
    ) -> anyhow::Result<()> {
        let target = attestation.data.target;

        // If the given attestation is not from a beacon block message, we have to check the target
        // epoch scope.
        if !is_from_block {
            self.validate_target_epoch_against_current_time(attestation)?;
        }

        // Check that the epoch number and slot number are matching
        ensure!(target.epoch == compute_epoch_at_slot(attestation.data.slot));

        // Attestation target must be for a known block. If target block is unknown, delay
        // consideration until block is found
        ensure!(self.db.block_provider().get(target.root)?.is_some());

        // Attestations must be for a known block. If block is unknown, delay consideration until
        // the block is found
        ensure!(
            self.db
                .block_provider()
                .get(attestation.data.beacon_block_root)?
                .is_some()
        );
        // Attestations must not be for blocks in the future. If not, the attestation should not be
        // considered
        ensure!(
            self.db
                .block_provider()
                .get(attestation.data.beacon_block_root)?
                .ok_or_else(|| anyhow!("block not found"))?
                .message
                .slot
                <= attestation.data.slot
        );

        // LMD vote must be consistent with FFG vote target
        ensure!(
            target.root
                == self.get_checkpoint_block(attestation.data.beacon_block_root, target.epoch)?
        );

        // Attestations can only affect the fork choice of subsequent slots.
        // Delay consideration in the fork choice until their slot is in the past.
        ensure!(self.get_current_slot()? >= attestation.data.slot + 1);

        Ok(())
    }

    pub fn store_target_checkpoint_state(&mut self, target: Checkpoint) -> anyhow::Result<()> {
        if self.db.checkpoint_states_provider().get(target)?.is_some() {
            return Ok(());
        }

        let Some(mut base_state) = self.db.state_provider().get(target.root)? else {
            return Ok(());
        };

        let target_slot = compute_start_slot_at_epoch(target.epoch);
        if base_state.slot < target_slot {
            base_state.process_slots(target_slot)?;
        }
        self.db
            .checkpoint_states_provider()
            .insert(target, base_state)?;

        Ok(())
    }

    pub fn compute_pulled_up_tip(&mut self, block_root: B256) -> anyhow::Result<()> {
        let mut state = self
            .db
            .state_provider()
            .get(block_root)?
            .ok_or_else(|| anyhow!("beacon state not found"))?;
        // Pull up the post-state of the block to the next epoch boundary
        state.process_justification_and_finalization()?;

        BEACON_CURRENT_ACTIVE_VALIDATORS.set(
            state
                .get_active_validator_indices(state.get_current_epoch())
                .len() as i64,
        );

        self.db
            .unrealized_justifications_provider()
            .insert(block_root, state.current_justified_checkpoint)?;
        self.update_unrealized_checkpoints(
            state.current_justified_checkpoint,
            state.finalized_checkpoint,
        )?;

        // If the block is from a prior epoch, apply the realized values
        let block_epoch = compute_epoch_at_slot(
            self.db
                .block_provider()
                .get(block_root)?
                .ok_or_else(|| anyhow!("block not found"))?
                .message
                .slot,
        );
        let current_epoch = self.get_current_store_epoch()?;
        if block_epoch < current_epoch {
            self.update_checkpoints(
                state.current_justified_checkpoint,
                state.finalized_checkpoint,
                state.previous_justified_checkpoint,
            )?;
        }

        Ok(())
    }

    pub fn is_syncing_for_validator_api(&self) -> anyhow::Result<bool> {
        let head = self.get_head()?;

        let head_slot = match self.db.block_provider().get(head) {
            Ok(Some(block)) => block.message.slot,
            err => {
                return Err(anyhow!("Failed to get head slot, error: {err:?}"));
            }
        };

        let sync_distance = self.get_current_slot()?.saturating_sub(head_slot);
        let sync_tolerance = VALIDATOR_API_SYNC_TOLERANCE_EPOCHS * SLOTS_PER_EPOCH;

        Ok(sync_distance > sync_tolerance)
    }
}

pub fn get_forkchoice_store(
    anchor_state: BeaconState,
    anchor_block: BeaconBlock,
    db: BeaconDB,
) -> anyhow::Result<Store> {
    ensure!(anchor_block.state_root == anchor_state.tree_hash_root());
    let anchor_root = anchor_block.tree_hash_root();
    let anchor_epoch = anchor_state.get_current_epoch();
    let justified_checkpoint = Checkpoint {
        epoch: anchor_epoch,
        root: anchor_root,
    };
    let finalized_checkpoint = Checkpoint {
        epoch: anchor_epoch,
        root: anchor_root,
    };
    let proposer_boost_root = B256::ZERO;
    let signature = BLSSignature::default();

    let signed_anchor_block = SignedBeaconBlock {
        message: anchor_block,
        signature,
    };

    let previous_justified_checkpoint = Checkpoint {
        epoch: anchor_epoch,
        root: anchor_root,
    };

    db.time_provider().insert(
        anchor_state.genesis_time + beacon_network_spec().seconds_per_slot() * anchor_state.slot,
    )?;
    db.genesis_time_provider()
        .insert(anchor_state.genesis_time)?;
    db.justified_checkpoint_provider()
        .insert(justified_checkpoint)?;
    db.finalized_checkpoint_provider()
        .insert(finalized_checkpoint)?;
    db.unrealized_justified_checkpoint_provider()
        .insert(justified_checkpoint)?;
    db.unrealized_finalized_checkpoint_provider()
        .insert(finalized_checkpoint)?;
    db.proposer_boost_root_provider()
        .insert(proposer_boost_root)?;
    // Seed the equivocating-indices set. `get_weight` (LMD-GHOST) reads this via a strict
    // `.get()?`, so leaving it uninitialized makes every `get_head` throw "Field not initilized"
    // the moment any validator has a latest message (i.e. once attestations reach fork choice).
    db.equivocating_indices_provider()
        .insert(HashSet::default())?;
    db.block_provider()
        .insert(anchor_root, signed_anchor_block)?;
    db.state_provider()
        .insert(anchor_root, anchor_state.clone())?;
    db.state_root_index_provider()
        .insert(anchor_state.tree_hash_root(), anchor_root)?;
    db.slot_index_provider()
        .insert(anchor_state.slot, anchor_root)?;
    db.checkpoint_states_provider()
        .insert(justified_checkpoint, anchor_state)?;
    db.unrealized_justifications_provider()
        .insert(anchor_root, justified_checkpoint)?;
    db.previous_justified_checkpoint_provider()
        .insert(previous_justified_checkpoint)?;

    let operation_pool = Arc::new(OperationPool::default());

    let mut store = Store::new(db, operation_pool, None);
    store.enable_fork_choice_tree()?;

    Ok(store)
}

pub fn get_slots_since_genesis_from_db(db: &BeaconDB) -> anyhow::Result<u64> {
    Ok(db
        .time_provider()
        .get()?
        .saturating_sub(db.genesis_time_provider().get()?)
        / beacon_network_spec().seconds_per_slot())
}

pub fn get_current_slot_from_db(db: &BeaconDB) -> anyhow::Result<u64> {
    Ok(GENESIS_SLOT + get_slots_since_genesis_from_db(db)?)
}

/// Finds the ancestor of `root` at or before `slot` using only database reads, so callers that do
/// not hold the [`Store`] can walk ancestry.
pub fn get_ancestor_from_db(db: &BeaconDB, mut root: B256, slot: u64) -> anyhow::Result<B256> {
    loop {
        let block = db
            .block_provider()
            .get(root)?
            .ok_or(anyhow!("Failed to find beacon_block_provider()"))?
            .message;
        if block.slot > slot {
            root = block.parent_root;
        } else {
            return Ok(root);
        }
    }
}

pub fn get_checkpoint_block_from_db(db: &BeaconDB, root: B256, epoch: u64) -> anyhow::Result<B256> {
    get_ancestor_from_db(db, root, compute_start_slot_at_epoch(epoch))
}

pub fn compute_slots_since_epoch_start(slot: u64) -> u64 {
    slot - compute_start_slot_at_epoch(compute_epoch_at_slot(slot))
}

fn pending_availability_cutoff_slot(
    finalized_epoch: u64,
    current_epoch: u64,
    retention_epochs: u64,
) -> u64 {
    let finalized_slot = compute_start_slot_at_epoch(finalized_epoch);
    let retention_cutoff_slot =
        compute_start_slot_at_epoch(current_epoch.saturating_sub(retention_epochs));
    std::cmp::max(finalized_slot.saturating_add(1), retention_cutoff_slot)
}

fn backfill_data_availability_columns_from_db<State>(
    db: &BeaconDB,
    data_availability_checker: &mut DataAvailabilityChecker<State>,
    block_root: B256,
) -> anyhow::Result<Option<PendingBlock<State>>> {
    let required_columns = data_availability_checker
        .required_columns()
        .iter()
        .copied()
        .collect::<Vec<_>>();

    for column_index in required_columns {
        let column_identifier = ColumnIdentifier::new(block_root, column_index);
        if let Some(sidecar) = db.column_sidecars_provider().get(column_identifier)? {
            data_availability_checker.add_column(
                block_root,
                column_index,
                sidecar.signed_block_header.message.slot,
            );
            if let Some(available) = data_availability_checker.take_if_complete(block_root) {
                return Ok(Some(available));
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use ream_consensus_beacon::{
        data_column_sidecar::DataColumnSidecar,
        electra::{
            beacon_block::{BeaconBlock, SignedBeaconBlock},
            beacon_block_body::BeaconBlockBody,
        },
    };
    use ream_consensus_misc::{
        beacon_block_header::SignedBeaconBlockHeader, constants::beacon::BYTES_PER_COMMITMENT,
        polynomial_commitments::kzg_commitment::KZGCommitment,
    };
    use ream_data_availability::AvailabilityEntryStatus;
    use ream_storage::db::ReamDB;
    use ssz_types::{FixedVector, VariableList};
    use tempdir::TempDir;

    use super::*;

    fn test_db() -> (BeaconDB, TempDir) {
        let temp_dir = TempDir::new("ream_fork_choice_beacon_store").unwrap();
        let db = ReamDB::new(temp_dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        (db, temp_dir)
    }

    fn signed_block(slot: u64) -> SignedBeaconBlock {
        SignedBeaconBlock {
            message: BeaconBlock {
                slot,
                body: BeaconBlockBody {
                    blob_kzg_commitments: VariableList::new(vec![KZGCommitment(
                        [0; BYTES_PER_COMMITMENT],
                    )])
                    .unwrap(),
                    ..Default::default()
                },
                ..Default::default()
            },
            signature: Default::default(),
        }
    }

    fn data_column_sidecar(index: u64, block: &SignedBeaconBlock) -> DataColumnSidecar {
        let mut signed_block_header = SignedBeaconBlockHeader::default();
        signed_block_header.message.slot = block.message.slot;
        signed_block_header.message.proposer_index = block.message.proposer_index;
        signed_block_header.message.parent_root = block.message.parent_root;
        signed_block_header.message.state_root = block.message.state_root;
        signed_block_header.message.body_root = block.message.body.tree_hash_root();
        signed_block_header.signature = block.signature.clone();

        DataColumnSidecar {
            index,
            column: VariableList::empty(),
            kzg_commitments: VariableList::empty(),
            kzg_proofs: VariableList::empty(),
            signed_block_header,
            kzg_commitments_inclusion_proof: FixedVector::default(),
        }
    }

    #[test]
    fn backfill_data_availability_columns_completes_pending_block_from_db() {
        let (db, _temp_dir) = test_db();
        let block = signed_block(11);
        let block_root = block.message.tree_hash_root();
        let sidecar = data_column_sidecar(0, &block);
        let mut checker: DataAvailabilityChecker<()> =
            DataAvailabilityChecker::new(std::collections::HashSet::from([0]));

        db.column_sidecars_provider()
            .insert(ColumnIdentifier::new(block_root, 0), sidecar)
            .unwrap();
        checker.insert_pending(block_root, block, ());
        assert_eq!(
            checker.status(&block_root),
            AvailabilityEntryStatus::PendingBlock
        );

        let pending =
            backfill_data_availability_columns_from_db(&db, &mut checker, block_root).unwrap();

        assert!(pending.is_some());
        assert_eq!(checker.status(&block_root), AvailabilityEntryStatus::Absent);
    }

    #[test]
    fn pending_availability_cutoff_preserves_slots_after_finalized_checkpoint() {
        let finalized_epoch = 10;
        let finalized_slot = compute_start_slot_at_epoch(finalized_epoch);
        let cutoff_slot = pending_availability_cutoff_slot(finalized_epoch, finalized_epoch, 4096);
        let finalized_root = B256::repeat_byte(1);
        let later_root = B256::repeat_byte(2);
        let mut checker: DataAvailabilityChecker<()> =
            DataAvailabilityChecker::new(std::collections::HashSet::from([0]));

        checker.add_column(finalized_root, 0, finalized_slot);
        checker.add_column(later_root, 0, finalized_slot + 1);

        assert_eq!(cutoff_slot, finalized_slot + 1);
        assert_eq!(checker.prune(cutoff_slot), 1);
        assert_eq!(
            checker.status(&finalized_root),
            AvailabilityEntryStatus::Absent
        );
        assert_eq!(
            checker.status(&later_root),
            AvailabilityEntryStatus::ColumnsOnly
        );
    }

    #[test]
    fn pending_availability_cutoff_keeps_retention_boundary() {
        let retention_epochs = 4;
        let current_epoch = 10;
        let retention_cutoff_slot = compute_start_slot_at_epoch(current_epoch - retention_epochs);
        let cutoff_slot =
            pending_availability_cutoff_slot(GENESIS_EPOCH, current_epoch, retention_epochs);
        let before_root = B256::repeat_byte(3);
        let boundary_root = B256::repeat_byte(4);
        let mut checker: DataAvailabilityChecker<()> =
            DataAvailabilityChecker::new(std::collections::HashSet::from([0]));

        checker.add_column(before_root, 0, retention_cutoff_slot - 1);
        checker.add_column(boundary_root, 0, retention_cutoff_slot);

        assert_eq!(cutoff_slot, retention_cutoff_slot);
        assert_eq!(checker.prune(cutoff_slot), 1);
        assert_eq!(
            checker.status(&before_root),
            AvailabilityEntryStatus::Absent
        );
        assert_eq!(
            checker.status(&boundary_root),
            AvailabilityEntryStatus::ColumnsOnly
        );
    }
}
