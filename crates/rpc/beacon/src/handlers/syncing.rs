use std::sync::Arc;

use actix_web::{HttpResponse, Responder, get, web::Data};
use ream_api_types_beacon::{
    responses::{DataResponse, EXECUTION_OPTIMISTIC},
    sync::SyncStatus,
};
use ream_api_types_common::error::ApiError;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_execution_engine::ExecutionEngine;
use tracing::error;

pub async fn calculate_sync_status(
    beacon_chain: &BeaconChain,
    execution_engine: &Option<ExecutionEngine>,
) -> Result<SyncStatus, ApiError> {
    // One published view keeps the head and clock coherent during block import.
    let head = beacon_chain
        .head()
        .map_err(|err| ApiError::InternalError(format!("Failed to get head snapshot: {err:?}")))?;
    let head_slot = head.head_slot;
    let sync_distance = head.current_slot.saturating_sub(head_slot);

    // get el_offline
    let el_offline = match execution_engine {
        Some(execution_engine) => match execution_engine.eth_chain_id().await {
            Ok(_) => false,
            Err(err) => {
                error!("Execution engine is offline or erroring, error: {err:?}");
                true
            }
        },
        None => true,
    };

    Ok(SyncStatus {
        head_slot,
        sync_distance,
        is_syncing: sync_distance > 1,
        el_offline,
        is_optimistic: EXECUTION_OPTIMISTIC,
    })
}

/// Called by `eth/v1/node/syncing` to get the Node Version.
#[get("/node/syncing")]
pub async fn get_syncing_status(
    beacon_chain: Data<Arc<BeaconChain>>,
    execution_engine: Data<Option<ExecutionEngine>>,
) -> Result<impl Responder, ApiError> {
    let sync_status = calculate_sync_status(&beacon_chain, &execution_engine).await?;

    // `data` is the syncing status itself: wrapping it in another object makes every
    // spec-compliant consumer report the endpoint as unsupported and the node as offline.
    Ok(HttpResponse::Ok().json(DataResponse::new(sync_status)))
}
