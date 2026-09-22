use alloy_primitives::B256;
use anyhow::anyhow;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::electra::{beacon_block::SignedBeaconBlock, beacon_state::BeaconState};
use ream_storage::{db::beacon::BeaconDB, tables::table::REDBTable};
use tree_hash::TreeHash;

/// A parent block found by [`find_parent`].
pub enum ParentBlock {
    /// The parent is imported. `state` is `None` if the database has the block but not its state.
    Imported {
        block: SignedBeaconBlock,
        state: Option<BeaconState>,
    },
    /// The parent passed validation but is waiting for its data columns.
    PendingAvailability {
        block: SignedBeaconBlock,
        state: BeaconState,
    },
}

fn load_imported_parent(db: &BeaconDB, parent_root: B256) -> anyhow::Result<Option<ParentBlock>> {
    let Some(block) = db.block_provider().get(parent_root)? else {
        return Ok(None);
    };
    let state = db.state_provider().get(parent_root)?;
    Ok(Some(ParentBlock::Imported { block, state }))
}

/// Looks up `parent_root` among imported blocks, then among blocks pending data availability.
pub async fn find_parent(
    beacon_chain: &BeaconChain,
    parent_root: B256,
) -> anyhow::Result<Option<ParentBlock>> {
    // The importer writes a block and its state in separate transactions, so without the store lock
    // a block can be visible before its state.
    if let Some(parent @ ParentBlock::Imported { state: Some(_), .. }) =
        load_imported_parent(beacon_chain.db(), parent_root)?
    {
        return Ok(Some(parent));
    }

    let store = beacon_chain.store.lock().await;
    if let Some(pending) = store.data_availability_checker.pending_block(&parent_root) {
        if pending.signed_block.message.tree_hash_root() != parent_root {
            return Err(anyhow!(
                "pending availability block root does not match lookup key"
            ));
        }
        return Ok(Some(ParentBlock::PendingAvailability {
            block: pending.signed_block.clone(),
            state: pending.post_state.clone(),
        }));
    }
    load_imported_parent(&store.db, parent_root)
}
