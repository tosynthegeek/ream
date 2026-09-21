use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::voluntary_exit::SignedVoluntaryExit;
use ream_storage::cache::BeaconCacheDB;

use super::result::ValidationResult;

pub async fn validate_voluntary_exit(
    voluntary_exit: &SignedVoluntaryExit,
    beacon_chain: &BeaconChain,
    cached_db: &BeaconCacheDB,
) -> anyhow::Result<ValidationResult> {
    let head = beacon_chain.head()?;
    let state = head.state.as_ref();

    // [IGNORE] The voluntary exit is the first valid voluntary exit received for the validator with
    // index signed_voluntary_exit.message.validator_index
    if cached_db
        .seen_voluntary_exit
        .read()
        .await
        .contains(&voluntary_exit.message.validator_index)
    {
        let index = voluntary_exit.message.validator_index;
        return Ok(ValidationResult::Ignore(format!(
            "The voluntary_exit is not the first valid voluntary exit received for the validator with index: {index}"
        )));
    }

    // [REJECT] All of the conditions within process_voluntary_exit pass validation.
    if let Err(err) = state.validate_voluntary_exit(voluntary_exit) {
        return Ok(ValidationResult::Reject(format!(
            "All of the conditions within validate_voluntary_exit pass validation fail: {err}"
        )));
    }

    cached_db
        .seen_voluntary_exit
        .write()
        .await
        .put(voluntary_exit.message.validator_index, ());

    Ok(ValidationResult::Accept)
}
