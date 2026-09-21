use std::sync::Arc;

use ream_consensus_beacon::fork_choice::latest_message::LatestMessage;
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};

use crate::{
    errors::StoreError,
    tables::{ssz_encoder::SSZEncoding, table::REDBTable},
};

pub struct LatestMessagesTable {
    pub db: Arc<Database>,
}

impl LatestMessagesTable {
    /// Returns every stored latest message as `(validator_index, message)` from a single read
    /// transaction. Used to rebuild in-memory fork choice state on startup.
    pub fn get_all(&self) -> Result<Vec<(u64, LatestMessage)>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(Self::TABLE_DEFINITION)?;

        let mut entries = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            entries.push((key.value(), value.value()));
        }
        Ok(entries)
    }

    pub fn insert_batch(
        &self,
        entries: impl IntoIterator<Item = (u64, LatestMessage)>,
    ) -> Result<(), StoreError> {
        let mut write_txn = self.db.begin_write()?;
        write_txn.set_durability(Durability::Immediate)?;
        {
            let mut table = write_txn.open_table(Self::TABLE_DEFINITION)?;
            for (index, message) in entries {
                table.insert(index, message)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }
}

/// Table definition for the Latest Message table
///
/// Key: latest_messages
/// Value: LatestMessage
impl REDBTable for LatestMessagesTable {
    const TABLE_DEFINITION: TableDefinition<'_, u64, SSZEncoding<LatestMessage>> =
        TableDefinition::new("beacon_latest_messages");

    type Key = u64;

    type KeyTableDefinition = u64;

    type Value = LatestMessage;

    type ValueTableDefinition = SSZEncoding<LatestMessage>;

    fn database(&self) -> Arc<Database> {
        self.db.clone()
    }
}
