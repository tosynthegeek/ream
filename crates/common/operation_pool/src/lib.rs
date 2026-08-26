use std::collections::HashMap;

use alloy_primitives::{Address, B256, map::HashSet};
use parking_lot::RwLock;
use ream_bls::{BLSSignature, traits::Aggregatable};
use ream_consensus_beacon::{
    attestation::Attestation, attester_slashing::AttesterSlashing,
    bls_to_execution_change::SignedBLSToExecutionChange, electra::beacon_state::BeaconState,
    proposer_slashing::ProposerSlashing, sync_aggregate::SyncAggregate,
    voluntary_exit::SignedVoluntaryExit,
};
use ream_consensus_misc::{
    constants::beacon::MIN_ATTESTATION_INCLUSION_DELAY,
    deposit::Deposit,
    misc::{compute_epoch_at_slot, get_committee_indices},
};
use tree_hash::TreeHash;

/// Electra's `MAX_ATTESTATIONS_ELECTRA`: the most attestations a block body can carry.
const MAX_ATTESTATIONS_ELECTRA: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposerPreparation {
    pub fee_recipient: Address,
    pub submission_epoch: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct AttestationKey {
    slot: u64,
    attestation_data_root: B256,
    committee_index: u64,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct SyncAggregateKey {
    slot: u64,
    beacon_block_root: B256,
}

#[derive(Debug, Default)]
pub struct OperationPool {
    signed_voluntary_exits: RwLock<HashMap<u64, SignedVoluntaryExit>>,
    signed_bls_to_execution_changes: RwLock<HashMap<B256, SignedBLSToExecutionChange>>,
    proposer_preparations: RwLock<HashMap<u64, ProposerPreparation>>,
    attester_slashings: RwLock<HashSet<AttesterSlashing>>,
    proposer_slashings: RwLock<HashSet<ProposerSlashing>>,
    attestations: RwLock<HashMap<AttestationKey, Vec<Attestation>>>,
    included_attestation_bits: RwLock<HashMap<AttestationKey, HashSet<usize>>>,
    sync_aggregates: RwLock<HashMap<SyncAggregateKey, SyncAggregate>>,
    deposits: RwLock<HashSet<Deposit>>,
}

impl OperationPool {
    pub fn insert_signed_voluntary_exit(&self, signed_voluntary_exit: SignedVoluntaryExit) {
        self.signed_voluntary_exits.write().insert(
            signed_voluntary_exit.message.validator_index,
            signed_voluntary_exit,
        );
    }

    pub fn get_signed_voluntary_exits(&self) -> Vec<SignedVoluntaryExit> {
        self.signed_voluntary_exits
            .read()
            .values()
            .cloned()
            .collect()
    }

    pub fn clean_signed_voluntary_exits(&self, beacon_state: &BeaconState) {
        self.signed_voluntary_exits
            .write()
            .retain(|&validator_index, _| {
                beacon_state.validators[validator_index as usize].exit_epoch
                    >= beacon_state.finalized_checkpoint.epoch
            });
    }

    pub fn insert_signed_bls_to_execution_change(
        &self,
        signed_bls_to_execution_change: SignedBLSToExecutionChange,
    ) {
        self.signed_bls_to_execution_changes.write().insert(
            signed_bls_to_execution_change.tree_hash_root(),
            signed_bls_to_execution_change,
        );
    }

    pub fn get_signed_bls_to_execution_changes(&self) -> Vec<SignedBLSToExecutionChange> {
        self.signed_bls_to_execution_changes
            .read()
            .values()
            .cloned()
            .collect()
    }

    pub fn remove_signed_bls_to_execution_change(&self, root: B256) {
        self.signed_bls_to_execution_changes.write().remove(&root);
    }

    pub fn insert_proposer_preparation(
        &self,
        validator_index: u64,
        fee_recipient: Address,
        submission_epoch: u64,
    ) {
        self.proposer_preparations.write().insert(
            validator_index,
            ProposerPreparation {
                fee_recipient,
                submission_epoch,
            },
        );
    }

    pub fn get_proposer_preparation(&self, validator_index: u64) -> Option<Address> {
        self.proposer_preparations
            .read()
            .get(&validator_index)
            .map(|preparation| preparation.fee_recipient)
    }

    pub fn get_all_proposer_preparations(&self) -> HashMap<u64, Address> {
        self.proposer_preparations
            .read()
            .iter()
            .map(|(&index, preparation)| (index, preparation.fee_recipient))
            .collect()
    }

    pub fn clean_proposer_preparations(&self, current_epoch: u64) {
        self.proposer_preparations.write().retain(|_, preparation| {
            // Keep preparations that are still valid
            // They persist through the epoch of submission and for 2 more epochs after that
            current_epoch <= preparation.submission_epoch + 2
        });
    }

    pub fn insert_attester_slashing(&self, slashing: AttesterSlashing) {
        self.attester_slashings.write().insert(slashing);
    }

    pub fn get_all_attester_slashings(&self) -> Vec<AttesterSlashing> {
        self.attester_slashings.read().iter().cloned().collect()
    }

    pub fn get_all_proposer_slahsings(&self) -> Vec<ProposerSlashing> {
        self.proposer_slashings.read().iter().cloned().collect()
    }

    pub fn insert_proposer_slashing(&self, slashing: ProposerSlashing) {
        self.proposer_slashings.write().insert(slashing);
    }

    pub fn get_attestations(
        &self,
        slot: u64,
        committee_index: Option<u64>,
        attestation_data_root: Option<B256>,
    ) -> Vec<Attestation> {
        self.attestations
            .read()
            .iter()
            .filter(|(key, _)| {
                if key.slot != slot {
                    return false;
                }

                if let Some(c_index) = committee_index
                    && key.committee_index != c_index
                {
                    return false;
                }

                if let Some(data_root) = attestation_data_root
                    && key.attestation_data_root != data_root
                {
                    return false;
                }

                true
            })
            .flat_map(|(_, attestations)| attestations.iter().cloned())
            .collect()
    }

    pub fn get_all_attestations(&self) -> Vec<Attestation> {
        self.attestations
            .read()
            .values()
            .flat_map(|attestations| attestations.clone())
            .collect()
    }

    pub fn insert_attestation(&self, attestation: Attestation, committee_index: u64) {
        let key = AttestationKey {
            slot: attestation.data.slot,
            attestation_data_root: attestation.data.tree_hash_root(),
            committee_index,
        };
        let mut map = self.attestations.write();
        if let Some(attestations) = map.get_mut(&key) {
            attestations.push(attestation);
        } else {
            map.insert(key, vec![attestation]);
        }
    }

    /// Select attestations that can be included in the block.
    ///
    /// Only keep attestations whose target epoch is current or previous, whose minimum inclusion
    /// delay has passed, and aggregate non-overlapping votes by key.
    pub fn get_attestations_for_block(&self, state: &BeaconState) -> Vec<Attestation> {
        let current_epoch = state.get_current_epoch();
        let previous_epoch = state.get_previous_epoch();
        let attestations = self.attestations.read();
        let included_attestation_bits = self.included_attestation_bits.read();

        let mut keys: Vec<&AttestationKey> = attestations
            .keys()
            .filter(|key| {
                let target_epoch = compute_epoch_at_slot(key.slot);
                (target_epoch == current_epoch || target_epoch == previous_epoch)
                    && key.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot
            })
            .collect();
        keys.sort_by_key(|key| std::cmp::Reverse(key.slot));

        keys.into_iter()
            .filter_map(|key| {
                let already_included = included_attestation_bits
                    .get(key)
                    .cloned()
                    .unwrap_or_default();
                aggregate_attestation_group(&attestations[key], &already_included)
            })
            .take(MAX_ATTESTATIONS_ELECTRA)
            .collect()
    }

    /// Record aggregation-bit positions from attestations that have been included in an
    /// imported block so attestations without new votes can be skipped during future packing.
    pub fn mark_attestations_included(&self, attestations: &[Attestation]) {
        let mut included_attestation_bits = self.included_attestation_bits.write();
        for attestation in attestations {
            let committee_indices = get_committee_indices(&attestation.committee_bits);
            let [committee_index] = committee_indices.as_slice() else {
                continue;
            };

            let key = AttestationKey {
                slot: attestation.data.slot,
                attestation_data_root: attestation.data.tree_hash_root(),
                committee_index: *committee_index,
            };

            let set_bits = (0..attestation.aggregation_bits.len())
                .filter(|&index| attestation.aggregation_bits.get(index).unwrap_or(false));

            included_attestation_bits
                .entry(key)
                .or_default()
                .extend(set_bits);
        }
    }

    /// Keep only attestations (and their inclusion-tracking bits) from the current or previous
    /// epoch.
    pub fn clean_attestations(&self, current_epoch: u64) {
        let is_live = |key: &AttestationKey| {
            let target_epoch = compute_epoch_at_slot(key.slot);
            target_epoch + 1 >= current_epoch
        };
        self.attestations.write().retain(|key, _| is_live(key));
        self.included_attestation_bits
            .write()
            .retain(|key, _| is_live(key));
    }

    pub fn get_sync_aggregate(&self, slot: u64, beacon_block_root: B256) -> Option<SyncAggregate> {
        let key = SyncAggregateKey {
            slot,
            beacon_block_root,
        };
        self.sync_aggregates.read().get(&key).cloned()
    }

    pub fn get_all_sync_aggregates(&self) -> Vec<SyncAggregate> {
        self.sync_aggregates.read().values().cloned().collect()
    }

    pub fn insert_sync_aggregate(
        &self,
        sync_aggregate: SyncAggregate,
        slot: u64,
        beacon_block_root: B256,
    ) {
        let key = SyncAggregateKey {
            slot,
            beacon_block_root,
        };

        let mut map = self.sync_aggregates.write();
        map.insert(key, sync_aggregate);
    }

    pub fn get_all_deposits(&self) -> Vec<Deposit> {
        self.deposits.read().iter().cloned().collect()
    }

    pub fn insert_deposit(&self, deposit: Deposit) {
        self.deposits.write().insert(deposit);
    }
}

/// Aggregates non-overlapping attestations that contain votes not present in `already_included`.
/// The selected attestations retain every signed bit so their aggregate signature stays valid.
fn aggregate_attestation_group(
    group: &[Attestation],
    already_included: &HashSet<usize>,
) -> Option<Attestation> {
    let mut aggregate = group.first()?.clone();
    let mut aggregation_bits = aggregate.aggregation_bits.clone();
    let mut seen = HashSet::<usize>::default();
    let mut signatures = Vec::new();

    for index in 0..aggregation_bits.len() {
        aggregation_bits.set(index, false).ok()?;
    }

    for attestation in group {
        if attestation.committee_bits != aggregate.committee_bits {
            continue;
        }

        let set_bits: Vec<usize> = (0..attestation.aggregation_bits.len())
            .filter(|&index| attestation.aggregation_bits.get(index).unwrap_or(false))
            .collect();

        if set_bits.is_empty()
            || set_bits
                .iter()
                .any(|position| *position >= aggregation_bits.len())
            || set_bits.iter().any(|position| seen.contains(position))
            || set_bits
                .iter()
                .all(|position| already_included.contains(position))
        {
            continue;
        }

        for position in &set_bits {
            seen.insert(*position);
            aggregation_bits.set(*position, true).ok()?;
        }

        signatures.push(&attestation.signature);
    }

    if signatures.is_empty() {
        return None;
    }

    aggregate.aggregation_bits = aggregation_bits;
    aggregate.signature = BLSSignature::aggregate(&signatures).ok()?;
    Some(aggregate)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::map::{DefaultHashBuilder, HashSet};
    use ream_consensus_misc::{attestation_data::AttestationData, checkpoint::Checkpoint};
    use ssz_types::{BitList, BitVector};

    use super::*;

    /// Build an `Attestation` for committee `committee_index` at `slot`, with `set_bit_indices`
    /// set within a `bitlist_len`-bit aggregation bitfield. `target_epoch` only needs to be
    /// distinct per test scenario; it feeds into `attestation_data_root` via the rest of the
    /// (otherwise-fixed) `AttestationData`, so distinct `target_epoch`/`slot` pairs produce
    /// distinct `AttestationKey`s.
    fn make_attestation(
        slot: u64,
        committee_index: u64,
        target_epoch: u64,
        bitlist_len: usize,
        set_bit_indices: &[usize],
    ) -> Attestation {
        let mut aggregation_bits =
            BitList::<ssz_types::typenum::U131072>::with_capacity(bitlist_len)
                .expect("valid bitlist capacity");
        for &index in set_bit_indices {
            aggregation_bits
                .set(index, true)
                .expect("index within bitlist capacity");
        }

        let mut committee_bits = BitVector::<ssz_types::typenum::U64>::default();
        committee_bits
            .set(committee_index as usize, true)
            .expect("committee index within bitvector capacity");

        Attestation {
            aggregation_bits,
            data: AttestationData {
                slot,
                index: 0,
                beacon_block_root: B256::repeat_byte(0xAB),
                source: Checkpoint::default(),
                target: Checkpoint {
                    epoch: target_epoch,
                    root: B256::repeat_byte(0xCD),
                },
            },
            signature: BLSSignature::infinity(),
            committee_bits,
        }
    }

    #[test]
    fn aggregate_attestation_group_preserves_signed_bits_for_partial_overlap() {
        // Two validators (bits 0 and 1) attested for the same data; bit 0 already landed
        // on-chain in an earlier block.
        let attestation = make_attestation(10, 0, 1, 4, &[0, 1]);
        let mut already_included = HashSet::with_hasher(DefaultHashBuilder::default());
        already_included.insert(0);

        let aggregate = aggregate_attestation_group(&[attestation], &already_included)
            .expect("bit 1 is new and should still be aggregated");

        assert!(aggregate.aggregation_bits.get(0).unwrap());
        assert!(aggregate.aggregation_bits.get(1).unwrap());
    }

    #[test]
    fn aggregate_attestation_group_returns_none_when_fully_included() {
        // Single attester (bit 0), and that bit has already landed on-chain: nothing new to
        // offer, so the group should not consume a block-attestation slot.
        let attestation = make_attestation(10, 0, 1, 4, &[0]);
        let mut already_included = HashSet::with_hasher(DefaultHashBuilder::default());
        already_included.insert(0);

        assert!(aggregate_attestation_group(&[attestation], &already_included).is_none());
    }

    #[test]
    fn aggregate_attestation_group_with_no_exclusions_matches_prior_behavior() {
        let attestation = make_attestation(10, 0, 1, 4, &[0, 2]);

        let aggregate = aggregate_attestation_group(
            &[attestation],
            &HashSet::with_hasher(DefaultHashBuilder::default()),
        )
        .expect("no exclusions, both bits should be aggregated");

        assert!(aggregate.aggregation_bits.get(0).unwrap());
        assert!(aggregate.aggregation_bits.get(2).unwrap());
    }

    #[test]
    fn mark_attestations_included_records_bit_positions_per_key() {
        let operation_pool = OperationPool::default();
        let included_in_block = make_attestation(10, 3, 1, 4, &[1, 2]);

        operation_pool.mark_attestations_included(std::slice::from_ref(&included_in_block));

        let key = AttestationKey {
            slot: included_in_block.data.slot,
            attestation_data_root: included_in_block.data.tree_hash_root(),
            committee_index: 3,
        };
        let recorded = operation_pool
            .included_attestation_bits
            .read()
            .get(&key)
            .cloned()
            .unwrap_or_default();

        assert_eq!(recorded, HashSet::from_iter([1, 2]));
    }

    #[test]
    fn mark_attestations_included_ignores_multi_committee_attestations() {
        // An attestation whose committee_bits spans more than one committee doesn't match the
        // single-committee shape this pool ever produces itself; it should be left alone rather
        // than mis-recorded under an arbitrary committee index.
        let mut multi_committee = make_attestation(10, 0, 1, 4, &[0]);
        multi_committee
            .committee_bits
            .set(1, true)
            .expect("committee index within bitvector capacity");

        let operation_pool = OperationPool::default();
        operation_pool.mark_attestations_included(&[multi_committee]);

        assert!(operation_pool.included_attestation_bits.read().is_empty());
    }

    #[test]
    fn repeated_inclusion_of_same_bits_does_not_starve_new_votes() {
        let operation_pool = OperationPool::default();
        let key = AttestationKey {
            slot: 10,
            attestation_data_root: make_attestation(10, 0, 1, 4, &[]).data.tree_hash_root(),
            committee_index: 0,
        };

        // First validator's vote lands on-chain.
        let first_voter = make_attestation(10, 0, 1, 4, &[0]);
        operation_pool.mark_attestations_included(std::slice::from_ref(&first_voter));

        // A second validator's vote for the same attestation data arrives late and is still in
        // the pool alongside a duplicate of the first (as would happen via gossip).
        let second_voter = make_attestation(10, 0, 1, 4, &[1]);
        let group = vec![first_voter, second_voter];

        let already_included = operation_pool
            .included_attestation_bits
            .read()
            .get(&key)
            .cloned()
            .unwrap_or_default();
        let aggregate = aggregate_attestation_group(&group, &already_included)
            .expect("second voter's bit is new and must still be selectable");

        assert!(!aggregate.aggregation_bits.get(0).unwrap());
        assert!(aggregate.aggregation_bits.get(1).unwrap());
    }

    #[test]
    fn clean_attestations_also_prunes_included_bits_for_expired_keys() {
        let operation_pool = OperationPool::default();
        let old_attestation = make_attestation(0, 0, 0, 4, &[0]);
        operation_pool.mark_attestations_included(std::slice::from_ref(&old_attestation));

        assert!(!operation_pool.included_attestation_bits.read().is_empty());

        // Far enough in the future that epoch 0's target is no longer current/previous.
        operation_pool.clean_attestations(1_000);

        assert!(operation_pool.included_attestation_bits.read().is_empty());
    }

    #[test]
    fn test_proposer_preparation_operations() {
        let operation_pool = OperationPool::default();
        let fee_recipient1 = Address::from([0x11; 20]);
        let fee_recipient2 = Address::from([0x22; 20]);

        assert_eq!(operation_pool.get_proposer_preparation(1), None);

        operation_pool.insert_proposer_preparation(1, fee_recipient1, 100);
        assert_eq!(
            operation_pool.get_proposer_preparation(1),
            Some(fee_recipient1)
        );

        operation_pool.insert_proposer_preparation(2, fee_recipient2, 100);
        let all_preparations = operation_pool.get_all_proposer_preparations();
        assert_eq!(all_preparations.len(), 2);
        assert_eq!(all_preparations.get(&1), Some(&fee_recipient1));
        assert_eq!(all_preparations.get(&2), Some(&fee_recipient2));

        operation_pool.insert_proposer_preparation(1, fee_recipient2, 101);
        assert_eq!(
            operation_pool.get_proposer_preparation(1),
            Some(fee_recipient2)
        );
    }

    #[test]
    fn test_proposer_preparation_expiration() {
        let operation_pool = OperationPool::default();
        let fee_recipient1 = Address::from([0x11; 20]);
        let fee_recipient2 = Address::from([0x22; 20]);
        let fee_recipient3 = Address::from([0x33; 20]);

        // Insert preparations at different epochs
        operation_pool.insert_proposer_preparation(1, fee_recipient1, 100);
        operation_pool.insert_proposer_preparation(2, fee_recipient2, 101);
        operation_pool.insert_proposer_preparation(3, fee_recipient3, 102);

        // All should be present initially
        assert_eq!(operation_pool.get_all_proposer_preparations().len(), 3);

        // Clean at epoch 102 - all should still be valid
        operation_pool.clean_proposer_preparations(102);
        assert_eq!(operation_pool.get_all_proposer_preparations().len(), 3);

        // Clean at epoch 103 - validator 1 (epoch 100) should be expired
        operation_pool.clean_proposer_preparations(103);
        let remaining = operation_pool.get_all_proposer_preparations();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining.get(&1), None);
        assert_eq!(remaining.get(&2), Some(&fee_recipient2));
        assert_eq!(remaining.get(&3), Some(&fee_recipient3));

        // Clean at epoch 104 - validators 1 and 2 should be expired
        operation_pool.clean_proposer_preparations(104);
        let remaining = operation_pool.get_all_proposer_preparations();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining.get(&3), Some(&fee_recipient3));

        // Clean at epoch 105 - all should be expired
        operation_pool.clean_proposer_preparations(105);
        assert_eq!(operation_pool.get_all_proposer_preparations().len(), 0);
    }

    #[test]
    fn test_proposer_preparation_edge_cases() {
        let operation_pool = OperationPool::default();
        let fee_recipient = Address::from([0x11; 20]);

        // Test exact boundary - submission at epoch 100 is valid through epoch 102
        operation_pool.insert_proposer_preparation(1, fee_recipient, 100);

        // Should be valid at epoch 102
        operation_pool.clean_proposer_preparations(102);
        assert_eq!(
            operation_pool.get_proposer_preparation(1),
            Some(fee_recipient)
        );

        // Should be expired at epoch 103
        operation_pool.clean_proposer_preparations(103);
        assert_eq!(operation_pool.get_proposer_preparation(1), None);
    }
}
