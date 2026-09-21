use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::{
    electra::beacon_state::BeaconState, proposer_slashing::ProposerSlashing,
};
use ream_storage::cache::BeaconCacheDB;

use super::result::ValidationResult;

pub async fn validate_proposer_slashing(
    proposer_slashing: &ProposerSlashing,
    beacon_chain: &BeaconChain,
    cached_db: &BeaconCacheDB,
) -> anyhow::Result<ValidationResult> {
    let proposer_index = proposer_slashing.signed_header_1.message.proposer_index;

    // [IGNORE] The proposer slashing is the first valid proposer slashing received for the proposer
    // with index proposer_slashing.signed_header_1.message.proposer_index
    if cached_db
        .seen_proposer_slashings
        .read()
        .await
        .contains(&proposer_index)
    {
        return Ok(ValidationResult::Ignore(
            "The proposer slashing is not the first valid".into(),
        ));
    }

    // `process_proposer_slashing` mutates the state, so work on an owned copy of the cached head
    // state; the store lock is not involved.
    let mut state = BeaconState::clone(&beacon_chain.head()?.state);

    // [REJECT] All of the conditions within process_proposer_slashing pass validation
    if let Err(err) = state.process_proposer_slashing(proposer_slashing) {
        return Ok(ValidationResult::Reject(format!(
            "Not all of the conditions within process_proposer_slashing pass validation: {err}"
        )));
    }

    cached_db
        .seen_proposer_slashings
        .write()
        .await
        .put(proposer_index, ());

    Ok(ValidationResult::Accept)
}
