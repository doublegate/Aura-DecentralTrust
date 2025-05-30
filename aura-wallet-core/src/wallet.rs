use aura_common::{
    AuraError, Result, AuraDid, DidDocument, VerifiableCredential, VerifiablePresentation,
};
use aura_crypto::{PublicKey, KeyPair};
use crate::{KeyManager, DidManager, VcStore, PresentationGenerator};

pub struct AuraWallet {
    key_manager: KeyManager,
    did_manager: DidManager,
    vc_store: VcStore,
    presentation_generator: PresentationGenerator,
}

impl AuraWallet {
    pub fn new() -> Self {
        let key_manager = KeyManager::new();
        let _did_manager = DidManager::new(key_manager);
        let _vc_store = VcStore::new();
        
        // We need to clone these for the presentation generator
        let key_manager_clone = KeyManager::new();
        let did_manager_clone = DidManager::new(key_manager_clone);
        let vc_store_clone = VcStore::new();
        let presentation_generator = PresentationGenerator::new(vc_store_clone, did_manager_clone);
        
        Self {
            key_manager: KeyManager::new(),
            did_manager: DidManager::new(KeyManager::new()),
            vc_store: VcStore::new(),
            presentation_generator,
        }
    }
    
    pub fn initialize(&mut self, password: &str) -> Result<()> {
        self.key_manager.initialize(password)?;
        
        // Derive encryption key for VC store
        let encryption_key = aura_crypto::encryption::generate_encryption_key();
        self.vc_store.initialize(encryption_key);
        
        // Reinitialize other components with initialized key manager
        self.did_manager = DidManager::new(self.key_manager.clone());
        self.presentation_generator = PresentationGenerator::new(
            self.vc_store.clone(),
            self.did_manager.clone(),
        );
        
        Ok(())
    }
    
    pub fn is_initialized(&self) -> bool {
        self.key_manager.is_initialized()
    }
    
    // DID Management
    pub fn create_did(&mut self) -> Result<(AuraDid, DidDocument, KeyPair)> {
        self.did_manager.create_did()
    }
    
    pub fn list_dids(&self) -> Vec<AuraDid> {
        self.did_manager.list_dids()
    }
    
    pub fn get_did_public_key(&self, did: &AuraDid) -> Result<PublicKey> {
        self.did_manager.get_public_key(did)
    }
    
    // Credential Management
    pub fn store_credential(
        &mut self,
        credential: VerifiableCredential,
        tags: Vec<String>,
    ) -> Result<String> {
        self.vc_store.store_credential(credential, tags)
    }
    
    pub fn get_credential(&self, id: &str) -> Result<Option<&crate::vc_store::StoredCredential>> {
        self.vc_store.get_credential(id)
    }
    
    pub fn list_credentials(&self) -> Vec<&crate::vc_store::StoredCredential> {
        self.vc_store.list_credentials()
    }
    
    pub fn find_credentials_by_type(&self, credential_type: &str) -> Vec<&crate::vc_store::StoredCredential> {
        self.vc_store.find_credentials_by_type(credential_type)
    }
    
    pub fn find_credentials_by_issuer(&self, issuer: &AuraDid) -> Vec<&crate::vc_store::StoredCredential> {
        self.vc_store.find_credentials_by_issuer(issuer)
    }
    
    pub fn find_credentials_by_subject(&self, subject: &AuraDid) -> Vec<&crate::vc_store::StoredCredential> {
        self.vc_store.find_credentials_by_subject(subject)
    }
    
    pub fn remove_credential(&mut self, id: &str) -> Result<()> {
        self.vc_store.remove_credential(id)
    }
    
    pub fn verify_credential(
        &self,
        credential: &VerifiableCredential,
        issuer_public_key: &PublicKey,
    ) -> Result<bool> {
        self.vc_store.verify_credential_signature(credential, issuer_public_key)
    }
    
    // Presentation Management
    pub fn create_presentation(
        &self,
        holder_did: &AuraDid,
        credential_ids: Vec<String>,
        challenge: Option<String>,
        domain: Option<String>,
    ) -> Result<VerifiablePresentation> {
        self.presentation_generator.create_presentation(
            holder_did,
            credential_ids,
            challenge,
            domain,
        )
    }
    
    pub fn create_selective_presentation(
        &self,
        holder_did: &AuraDid,
        credential_id: String,
        disclosed_claims: Vec<String>,
        challenge: Option<String>,
        domain: Option<String>,
    ) -> Result<VerifiablePresentation> {
        self.presentation_generator.create_selective_presentation(
            holder_did,
            credential_id,
            disclosed_claims,
            challenge,
            domain,
        )
    }
    
    pub fn verify_presentation(
        &self,
        presentation: &VerifiablePresentation,
        holder_public_key: &PublicKey,
        expected_challenge: Option<&str>,
        expected_domain: Option<&str>,
    ) -> Result<bool> {
        self.presentation_generator.verify_presentation(
            presentation,
            holder_public_key,
            expected_challenge,
            expected_domain,
        )
    }
    
    // Export/Import
    pub fn export_wallet(&self) -> Result<WalletBackup> {
        if !self.is_initialized() {
            return Err(AuraError::Internal("Wallet not initialized".to_string()));
        }
        
        Ok(WalletBackup {
            keys: self.key_manager.export_keys()?,
            credentials: self.vc_store.export_credentials()?,
        })
    }
    
    pub fn import_wallet(&mut self, backup: WalletBackup, password: &str) -> Result<()> {
        self.initialize(password)?;
        
        self.key_manager.import_keys(backup.keys)?;
        self.vc_store.import_credentials(&backup.credentials)?;
        
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBackup {
    pub keys: Vec<crate::key_manager::StoredKey>,
    pub credentials: Vec<u8>,
}

use serde::{Deserialize, Serialize};

// Implement Clone for components to fix the initialization issue
impl Clone for KeyManager {
    fn clone(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            master_key: self.master_key,
        }
    }
}

impl Clone for DidManager {
    fn clone(&self) -> Self {
        Self {
            key_manager: self.key_manager.clone(),
        }
    }
}

impl Clone for VcStore {
    fn clone(&self) -> Self {
        Self {
            credentials: self.credentials.clone(),
            encryption_key: self.encryption_key,
        }
    }
}