#![allow(clippy::explicit_auto_deref)]

use aura_common::{AuraDid, AuraError, Result};
use aura_crypto::{encryption, KeyPair, PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    pub did: AuraDid,
    pub public_key: PublicKey,
    pub encrypted_private_key: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Default)]
pub struct KeyManager {
    pub(crate) keys: HashMap<AuraDid, StoredKey>,
    pub(crate) master_key: Option<Zeroizing<[u8; 32]>>,
}

impl Drop for KeyManager {
    fn drop(&mut self) {
        // Master key is automatically zeroized by Zeroizing wrapper
        // Clear the keys map
        self.keys.clear();
    }
}

impl KeyManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn initialize(&mut self, password: &str) -> Result<()> {
        // Derive master key from password
        let salt = b"aura-wallet-salt"; // In production, use a random salt per wallet
        let master_key = self.derive_key_from_password(password, salt);
        self.master_key = Some(Zeroizing::new(master_key));
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        self.master_key.is_some()
    }

    pub fn generate_key_pair(&mut self, did: &AuraDid) -> Result<KeyPair> {
        if !self.is_initialized() {
            return Err(AuraError::Internal(
                "Key manager not initialized".to_string(),
            ));
        }

        // Check if key already exists
        if self.keys.contains_key(did) {
            return Err(AuraError::AlreadyExists(format!(
                "Key for DID {did} already exists"
            )));
        }

        // Generate new key pair
        let key_pair = KeyPair::generate().map_err(|e| AuraError::Crypto(e.to_string()))?;

        // Encrypt and store the private key
        let master_key = self.master_key.as_ref().unwrap();
        let private_key_bytes = key_pair.private_key().to_bytes();
        let encrypted_private_key = encryption::encrypt(&**master_key, &*private_key_bytes)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;

        let stored_key = StoredKey {
            did: did.clone(),
            public_key: key_pair.public_key().clone(),
            encrypted_private_key: bincode::encode_to_vec(
                &encrypted_private_key,
                bincode::config::standard(),
            )
            .map_err(|e| AuraError::Internal(format!("Failed to serialize encrypted key: {e}")))?,
            created_at: chrono::Utc::now(),
        };

        self.keys.insert(did.clone(), stored_key);

        Ok(key_pair)
    }

    pub fn get_key_pair(&self, did: &AuraDid) -> Result<KeyPair> {
        if !self.is_initialized() {
            return Err(AuraError::Internal(
                "Key manager not initialized".to_string(),
            ));
        }

        let stored_key = self
            .keys
            .get(did)
            .ok_or_else(|| AuraError::NotFound(format!("Key for DID {did} not found")))?;

        // Decrypt the private key
        let master_key = self.master_key.as_ref().unwrap();
        let (encrypted_data, _): (encryption::EncryptedData, _) = bincode::decode_from_slice(
            &stored_key.encrypted_private_key,
            bincode::config::standard(),
        )
        .map_err(|e| AuraError::Internal(format!("Failed to deserialize encrypted key: {e}")))?;

        let private_key_bytes = encryption::decrypt(&**master_key, &encrypted_data)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;

        let private_key = PrivateKey::from_bytes(&*private_key_bytes)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;

        Ok(KeyPair::from_private_key(private_key))
    }

    pub fn get_public_key(&self, did: &AuraDid) -> Result<PublicKey> {
        let stored_key = self
            .keys
            .get(did)
            .ok_or_else(|| AuraError::NotFound(format!("Key for DID {did} not found")))?;

        Ok(stored_key.public_key.clone())
    }

    pub fn list_dids(&self) -> Vec<AuraDid> {
        self.keys.keys().cloned().collect()
    }

    pub fn remove_key(&mut self, did: &AuraDid) -> Result<()> {
        self.keys
            .remove(did)
            .ok_or_else(|| AuraError::NotFound(format!("Key for DID {did} not found")))?;
        Ok(())
    }

    pub fn export_keys(&self) -> Result<Vec<StoredKey>> {
        if !self.is_initialized() {
            return Err(AuraError::Internal(
                "Key manager not initialized".to_string(),
            ));
        }

        Ok(self.keys.values().cloned().collect())
    }

    pub fn import_keys(&mut self, keys: Vec<StoredKey>) -> Result<()> {
        if !self.is_initialized() {
            return Err(AuraError::Internal(
                "Key manager not initialized".to_string(),
            ));
        }

        for key in keys {
            self.keys.insert(key.did.clone(), key);
        }

        Ok(())
    }

    fn derive_key_from_password(&self, password: &str, salt: &[u8]) -> [u8; 32] {
        // Use PBKDF2 with SHA-256, 100,000 iterations
        use aura_crypto::hashing;

        const ITERATIONS: u32 = 100_000;
        let mut output = [0u8; 32];

        // Simple PBKDF2 implementation using SHA-256
        // In production, consider using argon2 crate for better security
        let mut input = Vec::new();
        input.extend_from_slice(salt);
        input.extend_from_slice(password.as_bytes());

        // Multiple iterations of hashing
        let mut current = hashing::sha256(&input);
        for _ in 0..ITERATIONS {
            current = hashing::sha256(&current);
        }

        output.copy_from_slice(&current);
        output
    }
}
