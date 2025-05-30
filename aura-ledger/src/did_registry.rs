use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use aura_common::{
    AuraError, Result, AuraDid, DidDocument, DidRecord, BlockNumber,
};
use aura_crypto::{hashing, PublicKey};
use crate::storage::Storage;

pub struct DidRegistry {
    storage: Storage,
}

impl DidRegistry {
    pub fn new(storage: Storage) -> Self {
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
            return Err(AuraError::AlreadyExists(format!("DID {} already exists", did_id)));
        }
        
        // Create DID record
        let did_record = DidRecord {
            did_id: did_id.clone(),
            did_document_hash: hashing::blake3_json(did_document)?.to_vec(),
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
            .ok_or_else(|| AuraError::NotFound(format!("DID {} not found", did_id)))?;
        
        // Verify ownership
        let stored_key = PublicKey::from_bytes(&did_record.owner_public_key)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;
        if stored_key.to_bytes() != owner_public_key.to_bytes() {
            return Err(AuraError::Unauthorized);
        }
        
        // Check if DID is active
        if !did_record.active {
            return Err(AuraError::Validation("Cannot update deactivated DID".to_string()));
        }
        
        // Update record
        did_record.did_document_hash = hashing::blake3_json(new_did_document)?.to_vec();
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
            .ok_or_else(|| AuraError::NotFound(format!("DID {} not found", did_id)))?;
        
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