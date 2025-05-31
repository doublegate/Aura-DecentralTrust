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
                "Revocation list {list_id} already exists"
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
            .ok_or_else(|| AuraError::NotFound(format!("Revocation list {list_id} not found")))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_registry() -> (RevocationRegistry, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());
        let registry = RevocationRegistry::new(storage);
        (registry, temp_dir)
    }

    #[test]
    fn test_create_revocation_list() {
        let (mut registry, _temp_dir) = setup_registry();
        let list_id = "list123";
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        let result = registry.create_revocation_list(
            list_id,
            &issuer_did,
            BlockNumber(1),
        );
        
        assert!(result.is_ok());
        
        // Verify list was created
        let list = registry.get_revocation_list(list_id).unwrap();
        assert!(list.is_some());
        
        let list = list.unwrap();
        assert_eq!(list.list_id, list_id);
        assert_eq!(list.issuer_did, issuer_did);
        assert!(list.revoked_indices.is_empty());
        assert_eq!(list.last_updated_block, 1);
    }

    #[test]
    fn test_create_duplicate_revocation_list() {
        let (mut registry, _temp_dir) = setup_registry();
        let list_id = "list123";
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        // Create first list
        registry.create_revocation_list(
            list_id,
            &issuer_did,
            BlockNumber(1),
        ).unwrap();
        
        // Try to create duplicate
        let result = registry.create_revocation_list(
            list_id,
            &issuer_did,
            BlockNumber(2),
        );
        
        assert!(result.is_err());
        match result {
            Err(AuraError::AlreadyExists(_)) => {},
            _ => panic!("Expected AlreadyExists error"),
        }
    }

    #[test]
    fn test_update_revocation_list() {
        let (mut registry, _temp_dir) = setup_registry();
        let list_id = "list123";
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        // Create list
        registry.create_revocation_list(
            list_id,
            &issuer_did,
            BlockNumber(1),
        ).unwrap();
        
        // Update with revoked indices
        let revoked = vec![1, 5, 10];
        registry.update_revocation_list(
            list_id,
            &issuer_did,
            revoked.clone(),
            BlockNumber(2),
        ).unwrap();
        
        // Verify update
        let list = registry.get_revocation_list(list_id).unwrap().unwrap();
        assert_eq!(list.revoked_indices.len(), 3);
        for index in &revoked {
            assert!(list.revoked_indices.contains(index));
        }
        assert_eq!(list.last_updated_block, 2);
    }

    #[test]
    fn test_update_revocation_list_cumulative() {
        let (mut registry, _temp_dir) = setup_registry();
        let list_id = "list123";
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        // Create list
        registry.create_revocation_list(
            list_id,
            &issuer_did,
            BlockNumber(1),
        ).unwrap();
        
        // First update
        registry.update_revocation_list(
            list_id,
            &issuer_did,
            vec![1, 2, 3],
            BlockNumber(2),
        ).unwrap();
        
        // Second update (should add to existing)
        registry.update_revocation_list(
            list_id,
            &issuer_did,
            vec![4, 5, 6],
            BlockNumber(3),
        ).unwrap();
        
        // Third update with some duplicates
        registry.update_revocation_list(
            list_id,
            &issuer_did,
            vec![3, 6, 7, 8],
            BlockNumber(4),
        ).unwrap();
        
        // Verify all indices are present
        let list = registry.get_revocation_list(list_id).unwrap().unwrap();
        assert_eq!(list.revoked_indices.len(), 8); // 1,2,3,4,5,6,7,8
        for i in 1..=8 {
            assert!(list.revoked_indices.contains(&i));
        }
    }

    #[test]
    fn test_update_nonexistent_list() {
        let (mut registry, _temp_dir) = setup_registry();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        let result = registry.update_revocation_list(
            "nonexistent",
            &issuer_did,
            vec![1, 2, 3],
            BlockNumber(1),
        );
        
        assert!(result.is_err());
        match result {
            Err(AuraError::NotFound(_)) => {},
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_update_wrong_issuer() {
        let (mut registry, _temp_dir) = setup_registry();
        let list_id = "list123";
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        let wrong_issuer = AuraDid("did:aura:wrong".to_string());
        
        // Create list
        registry.create_revocation_list(
            list_id,
            &issuer_did,
            BlockNumber(1),
        ).unwrap();
        
        // Try to update with wrong issuer
        let result = registry.update_revocation_list(
            list_id,
            &wrong_issuer,
            vec![1, 2, 3],
            BlockNumber(2),
        );
        
        assert!(result.is_err());
        match result {
            Err(AuraError::Unauthorized) => {},
            _ => panic!("Expected Unauthorized error"),
        }
    }

    #[test]
    fn test_is_credential_revoked() {
        let (mut registry, _temp_dir) = setup_registry();
        let list_id = "list123";
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        // Create list and add some revoked indices
        registry.create_revocation_list(
            list_id,
            &issuer_did,
            BlockNumber(1),
        ).unwrap();
        
        registry.update_revocation_list(
            list_id,
            &issuer_did,
            vec![5, 10, 15, 20],
            BlockNumber(2),
        ).unwrap();
        
        // Check revoked credentials
        assert!(registry.is_credential_revoked(list_id, 5).unwrap());
        assert!(registry.is_credential_revoked(list_id, 10).unwrap());
        assert!(registry.is_credential_revoked(list_id, 15).unwrap());
        assert!(registry.is_credential_revoked(list_id, 20).unwrap());
        
        // Check non-revoked credentials
        assert!(!registry.is_credential_revoked(list_id, 1).unwrap());
        assert!(!registry.is_credential_revoked(list_id, 7).unwrap());
        assert!(!registry.is_credential_revoked(list_id, 25).unwrap());
    }

    #[test]
    fn test_is_credential_revoked_nonexistent_list() {
        let (registry, _temp_dir) = setup_registry();
        
        // Checking a nonexistent list should return false
        assert!(!registry.is_credential_revoked("nonexistent", 1).unwrap());
    }

    #[test]
    fn test_multiple_revocation_lists() {
        let (mut registry, _temp_dir) = setup_registry();
        let issuer1 = AuraDid("did:aura:issuer1".to_string());
        let issuer2 = AuraDid("did:aura:issuer2".to_string());
        
        // Create multiple lists
        registry.create_revocation_list("list1", &issuer1, BlockNumber(1)).unwrap();
        registry.create_revocation_list("list2", &issuer2, BlockNumber(2)).unwrap();
        registry.create_revocation_list("list3", &issuer1, BlockNumber(3)).unwrap();
        
        // Update different lists
        registry.update_revocation_list("list1", &issuer1, vec![1, 2], BlockNumber(4)).unwrap();
        registry.update_revocation_list("list2", &issuer2, vec![3, 4], BlockNumber(5)).unwrap();
        registry.update_revocation_list("list3", &issuer1, vec![5, 6], BlockNumber(6)).unwrap();
        
        // Verify lists are independent
        assert!(registry.is_credential_revoked("list1", 1).unwrap());
        assert!(!registry.is_credential_revoked("list1", 3).unwrap());
        
        assert!(registry.is_credential_revoked("list2", 3).unwrap());
        assert!(!registry.is_credential_revoked("list2", 1).unwrap());
        
        assert!(registry.is_credential_revoked("list3", 5).unwrap());
        assert!(!registry.is_credential_revoked("list3", 1).unwrap());
    }

    #[test]
    fn test_large_revocation_indices() {
        let (mut registry, _temp_dir) = setup_registry();
        let list_id = "list123";
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        registry.create_revocation_list(
            list_id,
            &issuer_did,
            BlockNumber(1),
        ).unwrap();
        
        // Add large indices
        let large_indices = vec![1000000, 2000000, u32::MAX - 1, u32::MAX];
        registry.update_revocation_list(
            list_id,
            &issuer_did,
            large_indices.clone(),
            BlockNumber(2),
        ).unwrap();
        
        // Verify large indices work correctly
        for index in &large_indices {
            assert!(registry.is_credential_revoked(list_id, *index).unwrap());
        }
    }

    #[test]
    fn test_empty_revocation_update() {
        let (mut registry, _temp_dir) = setup_registry();
        let list_id = "list123";
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        registry.create_revocation_list(
            list_id,
            &issuer_did,
            BlockNumber(1),
        ).unwrap();
        
        // Update with empty list (should still update block number)
        registry.update_revocation_list(
            list_id,
            &issuer_did,
            vec![],
            BlockNumber(2),
        ).unwrap();
        
        let list = registry.get_revocation_list(list_id).unwrap().unwrap();
        assert!(list.revoked_indices.is_empty());
        assert_eq!(list.last_updated_block, 2);
    }

    #[test]
    fn test_revocation_list_persistence() {
        let (mut registry, _temp_dir) = setup_registry();
        let list_id = "persist_test";
        let issuer_did = AuraDid("did:aura:issuer".to_string());
        
        // Create and update list
        registry.create_revocation_list(list_id, &issuer_did, BlockNumber(1)).unwrap();
        registry.update_revocation_list(
            list_id,
            &issuer_did,
            vec![10, 20, 30],
            BlockNumber(2),
        ).unwrap();
        
        // Retrieve multiple times to ensure persistence
        for _ in 0..5 {
            let list = registry.get_revocation_list(list_id).unwrap().unwrap();
            assert_eq!(list.revoked_indices.len(), 3);
            assert!(list.revoked_indices.contains(&10));
            assert!(list.revoked_indices.contains(&20));
            assert!(list.revoked_indices.contains(&30));
        }
    }
}
