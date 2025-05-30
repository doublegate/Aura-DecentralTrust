use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use aura_common::{AuraError, Result, AuraDid};
use aura_crypto::{KeyPair, PrivateKey, PublicKey, encryption, hashing};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    pub did: AuraDid,
    pub public_key: PublicKey,
    pub encrypted_private_key: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub struct KeyManager {
    keys: HashMap<AuraDid, StoredKey>,
    master_key: Option<[u8; 32]>,
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            master_key: None,
        }
    }
    
    pub fn initialize(&mut self, password: &str) -> Result<()> {
        // Derive master key from password
        let salt = b"aura-wallet-salt"; // In production, use a random salt per wallet
        let master_key = self.derive_key_from_password(password, salt);
        self.master_key = Some(master_key);
        Ok(())
    }
    
    pub fn is_initialized(&self) -> bool {
        self.master_key.is_some()
    }
    
    pub fn generate_key_pair(&mut self, did: &AuraDid) -> Result<KeyPair> {
        if !self.is_initialized() {
            return Err(AuraError::Internal("Key manager not initialized".to_string()));
        }
        
        // Check if key already exists
        if self.keys.contains_key(did) {
            return Err(AuraError::AlreadyExists(format!("Key for DID {} already exists", did)));
        }
        
        // Generate new key pair
        let key_pair = KeyPair::generate()
            .map_err(|e| AuraError::Crypto(e.to_string()))?;
        
        // Encrypt and store the private key
        let master_key = self.master_key.as_ref().unwrap();
        let encrypted_private_key = encryption::encrypt(
            master_key,
            &key_pair.private_key().to_bytes(),
        )
        .map_err(|e| AuraError::Crypto(e.to_string()))?;
        
        let stored_key = StoredKey {
            did: did.clone(),
            public_key: key_pair.public_key().clone(),
            encrypted_private_key: bincode::serialize(&encrypted_private_key)
                .map_err(|e| AuraError::Serialization(serde_json::Error::custom(e)))?,
            created_at: chrono::Utc::now(),
        };
        
        self.keys.insert(did.clone(), stored_key);
        
        Ok(key_pair)
    }
    
    pub fn get_key_pair(&self, did: &AuraDid) -> Result<KeyPair> {
        if !self.is_initialized() {
            return Err(AuraError::Internal("Key manager not initialized".to_string()));
        }
        
        let stored_key = self.keys.get(did)
            .ok_or_else(|| AuraError::NotFound(format!("Key for DID {} not found", did)))?;
        
        // Decrypt the private key
        let master_key = self.master_key.as_ref().unwrap();
        let encrypted_data: encryption::EncryptedData = bincode::deserialize(&stored_key.encrypted_private_key)
            .map_err(|e| AuraError::Serialization(serde_json::Error::custom(e)))?;
        
        let private_key_bytes = encryption::decrypt(master_key, &encrypted_data)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;
        
        let private_key = PrivateKey::from_bytes(&private_key_bytes)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;
        
        Ok(KeyPair::from_private_key(private_key))
    }
    
    pub fn get_public_key(&self, did: &AuraDid) -> Result<PublicKey> {
        let stored_key = self.keys.get(did)
            .ok_or_else(|| AuraError::NotFound(format!("Key for DID {} not found", did)))?;
        
        Ok(stored_key.public_key.clone())
    }
    
    pub fn list_dids(&self) -> Vec<AuraDid> {
        self.keys.keys().cloned().collect()
    }
    
    pub fn remove_key(&mut self, did: &AuraDid) -> Result<()> {
        self.keys.remove(did)
            .ok_or_else(|| AuraError::NotFound(format!("Key for DID {} not found", did)))?;
        Ok(())
    }
    
    pub fn export_keys(&self) -> Result<Vec<StoredKey>> {
        if !self.is_initialized() {
            return Err(AuraError::Internal("Key manager not initialized".to_string()));
        }
        
        Ok(self.keys.values().cloned().collect())
    }
    
    pub fn import_keys(&mut self, keys: Vec<StoredKey>) -> Result<()> {
        if !self.is_initialized() {
            return Err(AuraError::Internal("Key manager not initialized".to_string()));
        }
        
        for key in keys {
            self.keys.insert(key.did.clone(), key);
        }
        
        Ok(())
    }
    
    fn derive_key_from_password(&self, password: &str, salt: &[u8]) -> [u8; 32] {
        // In production, use a proper KDF like Argon2
        let mut input = Vec::new();
        input.extend_from_slice(password.as_bytes());
        input.extend_from_slice(salt);
        hashing::sha256(&input)
    }
}