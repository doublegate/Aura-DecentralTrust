use crate::storage::Storage;
use aura_common::{AuraDid, AuraError, BlockNumber, Result};
use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct RevocationList {
    pub list_id: String,
    pub issuer_did: AuraDid,
    pub revoked_indices: HashSet<u32>,
    pub last_updated_block: u64,
}

pub struct RevocationRegistry {
    storage: Arc<Storage>,
}

impl RevocationRegistry {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    pub fn create_revocation_list(
        &mut self,
        list_id: &str,
        issuer_did: &AuraDid,
        block_number: BlockNumber,
    ) -> Result<()> {
        // Check if list already exists
        if self.get_revocation_list(list_id)?.is_some() {
            return Err(AuraError::AlreadyExists(format!(
                "Revocation list {} already exists",
                list_id
            )));
        }

        let revocation_list = RevocationList {
            list_id: list_id.to_string(),
            issuer_did: issuer_did.clone(),
            revoked_indices: HashSet::new(),
            last_updated_block: block_number.0,
        };

        self.put_revocation_list(&revocation_list)?;
        Ok(())
    }

    pub fn update_revocation_list(
        &mut self,
        list_id: &str,
        issuer_did: &AuraDid,
        revoked_indices: Vec<u32>,
        block_number: BlockNumber,
    ) -> Result<()> {
        // Get existing list
        let mut revocation_list = self
            .get_revocation_list(list_id)?
            .ok_or_else(|| AuraError::NotFound(format!("Revocation list {} not found", list_id)))?;

        // Verify ownership
        if &revocation_list.issuer_did != issuer_did {
            return Err(AuraError::Unauthorized);
        }

        // Add new revoked indices
        for index in revoked_indices {
            revocation_list.revoked_indices.insert(index);
        }

        revocation_list.last_updated_block = block_number.0;

        self.put_revocation_list(&revocation_list)?;
        Ok(())
    }

    pub fn is_credential_revoked(&self, list_id: &str, index: u32) -> Result<bool> {
        if let Some(list) = self.get_revocation_list(list_id)? {
            Ok(list.revoked_indices.contains(&index))
        } else {
            Ok(false)
        }
    }

    pub fn get_revocation_list(&self, list_id: &str) -> Result<Option<RevocationList>> {
        let cf = self
            .storage
            .db
            .cf_handle("revocation")
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        let key = list_id.as_bytes();

        match self.storage.db.get_cf(cf, key) {
            Ok(Some(data)) => {
                let list = bincode::decode_from_slice(&data, bincode::config::standard())
                    .map(|(list, _)| list)
                    .map_err(|e| AuraError::Serialization(e.to_string()))?;
                Ok(Some(list))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AuraError::Storage(e.to_string())),
        }
    }

    fn put_revocation_list(&self, list: &RevocationList) -> Result<()> {
        let cf = self
            .storage
            .db
            .cf_handle("revocation")
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        let key = list.list_id.as_bytes();
        let value = bincode::encode_to_vec(list, bincode::config::standard())
            .map_err(|e| AuraError::Serialization(e.to_string()))?;

        self.storage
            .db
            .put_cf(cf, key, value)
            .map_err(|e| AuraError::Storage(e.to_string()))?;

        Ok(())
    }
}
