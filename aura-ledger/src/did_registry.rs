use crate::storage::Storage;
use aura_common::{AuraDid, AuraError, BlockNumber, DidDocument, DidRecord, Result};
use aura_crypto::{hashing, PublicKey};
use std::sync::Arc;

pub struct DidRegistry {
    storage: Arc<Storage>,
}

impl DidRegistry {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    pub fn register_did(
        &mut self,
        did_document: &DidDocument,
        owner_public_key: PublicKey,
        block_number: BlockNumber,
    ) -> Result<()> {
        let did_id = &did_document.id;

        // Check if DID already exists
        if self.get_did_record(did_id)?.is_some() {
            return Err(AuraError::AlreadyExists(format!(
                "DID {did_id} already exists"
            )));
        }

        // Create DID record
        let did_record = DidRecord {
            did_id: did_id.clone(),
            did_document_hash: hashing::blake3_json(did_document)
                .map_err(|e| AuraError::Crypto(e.to_string()))?
                .to_vec(),
            owner_public_key: owner_public_key.to_bytes().to_vec(),
            last_updated_block: block_number.0,
            active: true,
        };

        // Store the record
        self.storage.put_did_record(did_id, &did_record)?;

        // Store the actual DID document
        self.storage.put_did_document(did_id, did_document)?;

        Ok(())
    }

    pub fn update_did(
        &mut self,
        did_id: &AuraDid,
        new_did_document: &DidDocument,
        owner_public_key: &PublicKey,
        block_number: BlockNumber,
    ) -> Result<()> {
        // Get existing record
        let mut did_record = self
            .get_did_record(did_id)?
            .ok_or_else(|| AuraError::NotFound(format!("DID {did_id} not found")))?;

        // Verify ownership
        let stored_key = PublicKey::from_bytes(&did_record.owner_public_key)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;
        if stored_key.to_bytes() != owner_public_key.to_bytes() {
            return Err(AuraError::Unauthorized);
        }

        // Check if DID is active
        if !did_record.active {
            return Err(AuraError::Validation(
                "Cannot update deactivated DID".to_string(),
            ));
        }

        // Update record
        did_record.did_document_hash = hashing::blake3_json(new_did_document)
            .map_err(|e| AuraError::Crypto(e.to_string()))?
            .to_vec();
        did_record.last_updated_block = block_number.0;

        // Store updated record and document
        self.storage.put_did_record(did_id, &did_record)?;
        self.storage.put_did_document(did_id, new_did_document)?;

        Ok(())
    }

    pub fn deactivate_did(
        &mut self,
        did_id: &AuraDid,
        owner_public_key: &PublicKey,
        block_number: BlockNumber,
    ) -> Result<()> {
        // Get existing record
        let mut did_record = self
            .get_did_record(did_id)?
            .ok_or_else(|| AuraError::NotFound(format!("DID {did_id} not found")))?;

        // Verify ownership
        let stored_key = PublicKey::from_bytes(&did_record.owner_public_key)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;
        if stored_key.to_bytes() != owner_public_key.to_bytes() {
            return Err(AuraError::Unauthorized);
        }

        // Check if already deactivated
        if !did_record.active {
            return Err(AuraError::Validation("DID already deactivated".to_string()));
        }

        // Deactivate
        did_record.active = false;
        did_record.last_updated_block = block_number.0;

        // Store updated record
        self.storage.put_did_record(did_id, &did_record)?;

        Ok(())
    }

    pub fn resolve_did(&self, did_id: &AuraDid) -> Result<Option<(DidDocument, DidRecord)>> {
        if let Some(record) = self.get_did_record(did_id)? {
            if let Some(document) = self.storage.get_did_document(did_id)? {
                return Ok(Some((document, record)));
            }
        }
        Ok(None)
    }

    pub fn get_did_record(&self, did_id: &AuraDid) -> Result<Option<DidRecord>> {
        self.storage.get_did_record(did_id)
    }

    pub fn is_did_active(&self, did_id: &AuraDid) -> Result<bool> {
        if let Some(record) = self.get_did_record(did_id)? {
            Ok(record.active)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_crypto::KeyPair;
    use tempfile::TempDir;

    fn setup_registry() -> (DidRegistry, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());
        let registry = DidRegistry::new(storage);
        (registry, temp_dir)
    }

    fn create_test_did_document(did: &str) -> DidDocument {
        DidDocument::new(AuraDid(format!("did:aura:{}", did)))
    }

    #[test]
    fn test_register_did() {
        let (mut registry, _temp_dir) = setup_registry();
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document("test123");
        
        let result = registry.register_did(
            &did_doc,
            keypair.public_key().clone(),
            BlockNumber(1),
        );
        
        assert!(result.is_ok());
        
        // Verify the DID was registered
        let record = registry.get_did_record(&did_doc.id).unwrap();
        assert!(record.is_some());
        
        let record = record.unwrap();
        assert_eq!(record.did_id, did_doc.id);
        assert!(record.active);
        assert_eq!(record.last_updated_block, 1);
    }

    #[test]
    fn test_register_did_duplicate() {
        let (mut registry, _temp_dir) = setup_registry();
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document("test123");
        
        // Register once
        registry.register_did(
            &did_doc,
            keypair.public_key().clone(),
            BlockNumber(1),
        ).unwrap();
        
        // Try to register again
        let result = registry.register_did(
            &did_doc,
            keypair.public_key().clone(),
            BlockNumber(2),
        );
        
        assert!(result.is_err());
        match result {
            Err(AuraError::AlreadyExists(_)) => {},
            _ => panic!("Expected AlreadyExists error"),
        }
    }

    #[test]
    fn test_update_did() {
        let (mut registry, _temp_dir) = setup_registry();
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document("test123");
        
        // Register first
        registry.register_did(
            &did_doc,
            keypair.public_key().clone(),
            BlockNumber(1),
        ).unwrap();
        
        // Create updated document
        let mut updated_doc = did_doc.clone();
        updated_doc.updated = aura_common::Timestamp::now();
        
        // Update
        let result = registry.update_did(
            &did_doc.id,
            &updated_doc,
            keypair.public_key(),
            BlockNumber(2),
        );
        
        assert!(result.is_ok());
        
        // Verify update
        let record = registry.get_did_record(&did_doc.id).unwrap().unwrap();
        assert_eq!(record.last_updated_block, 2);
    }

    #[test]
    fn test_update_did_wrong_owner() {
        let (mut registry, _temp_dir) = setup_registry();
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document("test123");
        
        // Register with keypair1
        registry.register_did(
            &did_doc,
            keypair1.public_key().clone(),
            BlockNumber(1),
        ).unwrap();
        
        // Try to update with keypair2
        let result = registry.update_did(
            &did_doc.id,
            &did_doc,
            keypair2.public_key(),
            BlockNumber(2),
        );
        
        assert!(result.is_err());
        match result {
            Err(AuraError::Unauthorized) => {},
            _ => panic!("Expected Unauthorized error"),
        }
    }

    #[test]
    fn test_update_did_not_found() {
        let (mut registry, _temp_dir) = setup_registry();
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document("test123");
        
        let result = registry.update_did(
            &did_doc.id,
            &did_doc,
            keypair.public_key(),
            BlockNumber(1),
        );
        
        assert!(result.is_err());
        match result {
            Err(AuraError::NotFound(_)) => {},
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_deactivate_did() {
        let (mut registry, _temp_dir) = setup_registry();
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document("test123");
        
        // Register first
        registry.register_did(
            &did_doc,
            keypair.public_key().clone(),
            BlockNumber(1),
        ).unwrap();
        
        // Deactivate
        let result = registry.deactivate_did(
            &did_doc.id,
            keypair.public_key(),
            BlockNumber(2),
        );
        
        assert!(result.is_ok());
        
        // Verify deactivation
        let is_active = registry.is_did_active(&did_doc.id).unwrap();
        assert!(!is_active);
    }

    #[test]
    fn test_deactivate_did_wrong_owner() {
        let (mut registry, _temp_dir) = setup_registry();
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document("test123");
        
        // Register with keypair1
        registry.register_did(
            &did_doc,
            keypair1.public_key().clone(),
            BlockNumber(1),
        ).unwrap();
        
        // Try to deactivate with keypair2
        let result = registry.deactivate_did(
            &did_doc.id,
            keypair2.public_key(),
            BlockNumber(2),
        );
        
        assert!(result.is_err());
        match result {
            Err(AuraError::Unauthorized) => {},
            _ => panic!("Expected Unauthorized error"),
        }
    }

    #[test]
    fn test_deactivate_did_already_deactivated() {
        let (mut registry, _temp_dir) = setup_registry();
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document("test123");
        
        // Register and deactivate
        registry.register_did(
            &did_doc,
            keypair.public_key().clone(),
            BlockNumber(1),
        ).unwrap();
        
        registry.deactivate_did(
            &did_doc.id,
            keypair.public_key(),
            BlockNumber(2),
        ).unwrap();
        
        // Try to deactivate again
        let result = registry.deactivate_did(
            &did_doc.id,
            keypair.public_key(),
            BlockNumber(3),
        );
        
        assert!(result.is_err());
        match result {
            Err(AuraError::Validation(msg)) => {
                assert!(msg.contains("already deactivated"));
            },
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_update_deactivated_did() {
        let (mut registry, _temp_dir) = setup_registry();
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document("test123");
        
        // Register and deactivate
        registry.register_did(
            &did_doc,
            keypair.public_key().clone(),
            BlockNumber(1),
        ).unwrap();
        
        registry.deactivate_did(
            &did_doc.id,
            keypair.public_key(),
            BlockNumber(2),
        ).unwrap();
        
        // Try to update
        let result = registry.update_did(
            &did_doc.id,
            &did_doc,
            keypair.public_key(),
            BlockNumber(3),
        );
        
        assert!(result.is_err());
        match result {
            Err(AuraError::Validation(msg)) => {
                assert!(msg.contains("Cannot update deactivated DID"));
            },
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_resolve_did() {
        let (mut registry, _temp_dir) = setup_registry();
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document("test123");
        
        // Register
        registry.register_did(
            &did_doc,
            keypair.public_key().clone(),
            BlockNumber(1),
        ).unwrap();
        
        // Resolve
        let result = registry.resolve_did(&did_doc.id).unwrap();
        assert!(result.is_some());
        
        let (resolved_doc, resolved_record) = result.unwrap();
        assert_eq!(resolved_doc.id, did_doc.id);
        assert_eq!(resolved_record.did_id, did_doc.id);
        assert!(resolved_record.active);
    }

    #[test]
    fn test_resolve_did_not_found() {
        let (registry, _temp_dir) = setup_registry();
        let did = AuraDid("did:aura:nonexistent".to_string());
        
        let result = registry.resolve_did(&did).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_is_did_active() {
        let (mut registry, _temp_dir) = setup_registry();
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document("test123");
        
        // Before registration
        assert!(!registry.is_did_active(&did_doc.id).unwrap());
        
        // After registration
        registry.register_did(
            &did_doc,
            keypair.public_key().clone(),
            BlockNumber(1),
        ).unwrap();
        assert!(registry.is_did_active(&did_doc.id).unwrap());
        
        // After deactivation
        registry.deactivate_did(
            &did_doc.id,
            keypair.public_key(),
            BlockNumber(2),
        ).unwrap();
        assert!(!registry.is_did_active(&did_doc.id).unwrap());
    }

    #[test]
    fn test_did_document_hash_changes() {
        let (mut registry, _temp_dir) = setup_registry();
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document("test123");
        
        // Register
        registry.register_did(
            &did_doc,
            keypair.public_key().clone(),
            BlockNumber(1),
        ).unwrap();
        
        let record1 = registry.get_did_record(&did_doc.id).unwrap().unwrap();
        
        // Update with modified document
        let mut updated_doc = did_doc.clone();
        updated_doc.service.push(aura_common::ServiceEndpoint {
            id: "service1".to_string(),
            service_type: "test".to_string(),
            service_endpoint: "https://example.com".to_string(),
        });
        
        registry.update_did(
            &did_doc.id,
            &updated_doc,
            keypair.public_key(),
            BlockNumber(2),
        ).unwrap();
        
        let record2 = registry.get_did_record(&did_doc.id).unwrap().unwrap();
        
        // Hash should be different
        assert_ne!(record1.did_document_hash, record2.did_document_hash);
    }
}
