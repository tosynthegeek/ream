use alloy_primitives::B256;
use anyhow::{Result, anyhow, ensure};
use ream_consensus_beacon::{
    data_column_sidecar::{DataColumnSidecar, NUMBER_OF_COLUMNS},
    matrix_entry::{MatrixEntry, das_context, recover_matrix},
};
use ream_consensus_misc::constants::beacon::CELLS_PER_EXT_BLOB;
use ssz_types::VariableList;
use tree_hash::TreeHash;

/// Minimum distinct column sidecars required before attempting PeerDAS recovery.
/// Matches `matrix_entry` tests: half of the extended column count.
pub fn reconstruction_column_threshold() -> usize {
    (CELLS_PER_EXT_BLOB as usize).div_ceil(2)
}

/// Build a partial matrix from stored sidecars, run `recover_matrix`, and return
/// sidecars only for `missing` column indices.
///
/// Pure: no store access. Caller is responsible for persistence and DAC updates.
pub fn reconstruct_sidecars_for_block(
    block_root: B256,
    present: &[DataColumnSidecar],
    missing: &[u64],
) -> Result<Vec<DataColumnSidecar>> {
    if present.is_empty() || missing.is_empty() {
        return Ok(vec![]);
    }

    let min_columns = reconstruction_column_threshold();
    ensure!(
        present.len() >= min_columns,
        "not enough columns to reconstruct: have {}, need >= {min_columns}",
        present.len()
    );

    let template = &present[0];
    let blob_count = template.kzg_commitments.len() as u64;
    ensure!(
        blob_count > 0,
        "cannot reconstruct a block with zero blob commitments"
    );

    for sc in present {
        let root = sc.signed_block_header.message.tree_hash_root();
        ensure!(
            root == block_root,
            "sidecar root {root:?} does not match target {block_root:?}"
        );
        ensure!(
            sc.kzg_commitments.len() as u64 == blob_count,
            "sidecar column {} commitment count {}, expected {blob_count}",
            sc.index,
            sc.kzg_commitments.len()
        );
        ensure!(
            sc.column.len() == blob_count as usize,
            "sidecar column {} cell count {}, expected {blob_count}",
            sc.index,
            sc.column.len()
        );
        ensure!(
            sc.kzg_proofs.len() == blob_count as usize,
            "sidecar column {} proof count {}, expected {blob_count}",
            sc.index,
            sc.kzg_proofs.len()
        );
        ensure!(
            sc.index < NUMBER_OF_COLUMNS,
            "sidecar column index {} out of range",
            sc.index
        );
    }

    let mut partial_matrix = Vec::with_capacity(present.len() * blob_count as usize);
    for sc in present {
        for (row_index, (cell, kzg_proof)) in sc
            .column
            .iter()
            .cloned()
            .zip(sc.kzg_proofs.iter().cloned())
            .enumerate()
        {
            partial_matrix.push(MatrixEntry::new(
                cell,
                kzg_proof,
                sc.index,
                row_index as u64,
            ));
        }
    }

    let recovered = recover_matrix(partial_matrix, blob_count, das_context())?;

    let mut by_column: Vec<Vec<MatrixEntry>> = (0..CELLS_PER_EXT_BLOB)
        .map(|_| Vec::with_capacity(blob_count as usize))
        .collect();

    for entry in recovered {
        ensure!(
            entry.column_index() < CELLS_PER_EXT_BLOB,
            "recovered column_index {} out of range",
            entry.column_index()
        );
        by_column[entry.column_index() as usize].push(entry);
    }

    let missing_set: std::collections::HashSet<u64> = missing.iter().copied().collect();
    let mut out = Vec::with_capacity(missing.len());

    for column_index in 0..CELLS_PER_EXT_BLOB {
        if !missing_set.contains(&column_index) {
            continue;
        }

        let mut entries = std::mem::take(&mut by_column[column_index as usize]);
        entries.sort_by_key(|entry| entry.row_index());

        ensure!(
            entries.len() == blob_count as usize,
            "recovered column {column_index} has {} rows, expected {blob_count}",
            entries.len()
        );

        let mut cells = Vec::with_capacity(blob_count as usize);
        let mut proofs = Vec::with_capacity(blob_count as usize);
        for (expected_row, entry) in entries.into_iter().enumerate() {
            ensure!(
                entry.row_index() == expected_row as u64,
                "recovered column {column_index} row gap: got {}, expected {expected_row}",
                entry.row_index()
            );
            cells.push(entry.cell().clone());
            proofs.push(entry.kzg_proof().clone());
        }

        let column =
            VariableList::new(cells).map_err(|err| anyhow!("recovered column cells: {err:?}"))?;
        let kzg_proofs =
            VariableList::new(proofs).map_err(|err| anyhow!("recovered column proofs: {err:?}"))?;

        out.push(DataColumnSidecar {
            index: column_index,
            column,
            kzg_commitments: template.kzg_commitments.clone(),
            kzg_proofs,
            signed_block_header: template.signed_block_header.clone(),
            kzg_commitments_inclusion_proof: template.kzg_commitments_inclusion_proof.clone(),
        });
    }

    Ok(out)
}
