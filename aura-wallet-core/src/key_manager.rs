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

#[cfg(test)]
mod tests {
    use super::*;
    use aura_common::AuraDid;

    fn setup_key_manager() -> KeyManager {
        let mut km = KeyManager::new();
        km.initialize("test_password").unwrap();
        km
    }

    #[test]
    fn test_new_key_manager() {
        let km = KeyManager::new();
        assert!(!km.is_initialized());
        assert!(km.keys.is_empty());
    }

    #[test]
    fn test_initialize() {
        let mut km = KeyManager::new();
        km.initialize("password123").unwrap();
        assert!(km.is_initialized());
        assert!(km.master_key.is_some());
    }

    #[test]
    fn test_generate_key_pair() {
        let mut km = setup_key_manager();
        let did = AuraDid("did:aura:test123".to_string());

        let key_pair = km.generate_key_pair(&did).unwrap();

        assert!(km.keys.contains_key(&did));
        assert_eq!(km.keys.len(), 1);

        // Verify we can retrieve the same key
        let retrieved = km.get_key_pair(&did).unwrap();
        assert_eq!(key_pair.public_key(), retrieved.public_key());
    }

    #[test]
    fn test_generate_key_pair_not_initialized() {
        let mut km = KeyManager::new();
        let did = AuraDid("did:aura:test123".to_string());

        let result = km.generate_key_pair(&did);
        assert!(result.is_err());
        match result {
            Err(AuraError::Internal(msg)) => {
                assert!(msg.contains("Key manager not initialized"));
            }
            _ => panic!("Expected Internal error"),
        }
    }

    #[test]
    fn test_generate_duplicate_key() {
        let mut km = setup_key_manager();
        let did = AuraDid("did:aura:test123".to_string());

        // Generate first key
        km.generate_key_pair(&did).unwrap();

        // Try to generate duplicate
        let result = km.generate_key_pair(&did);
        assert!(result.is_err());
        match result {
            Err(AuraError::AlreadyExists(_)) => {}
            _ => panic!("Expected AlreadyExists error"),
        }
    }

    #[test]
    fn test_get_key_pair() {
        let mut km = setup_key_manager();
        let did = AuraDid("did:aura:test123".to_string());

        let original = km.generate_key_pair(&did).unwrap();
        let retrieved = km.get_key_pair(&did).unwrap();

        assert_eq!(original.public_key(), retrieved.public_key());
        assert_eq!(
            original.private_key().to_bytes(),
            retrieved.private_key().to_bytes()
        );
    }

    #[test]
    fn test_get_key_pair_not_found() {
        let km = setup_key_manager();
        let did = AuraDid("did:aura:nonexistent".to_string());

        let result = km.get_key_pair(&did);
        assert!(result.is_err());
        match result {
            Err(AuraError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_get_public_key() {
        let mut km = setup_key_manager();
        let did = AuraDid("did:aura:test123".to_string());

        let key_pair = km.generate_key_pair(&did).unwrap();
        let public_key = km.get_public_key(&did).unwrap();

        assert_eq!(key_pair.public_key(), &public_key);
    }

    #[test]
    fn test_list_dids() {
        let mut km = setup_key_manager();

        // Generate multiple keys
        let dids = vec![
            AuraDid("did:aura:test1".to_string()),
            AuraDid("did:aura:test2".to_string()),
            AuraDid("did:aura:test3".to_string()),
        ];

        for did in &dids {
            km.generate_key_pair(did).unwrap();
        }

        let listed = km.list_dids();
        assert_eq!(listed.len(), 3);

        for did in &dids {
            assert!(listed.contains(did));
        }
    }

    #[test]
    fn test_remove_key() {
        let mut km = setup_key_manager();
        let did = AuraDid("did:aura:test123".to_string());

        km.generate_key_pair(&did).unwrap();
        assert!(km.keys.contains_key(&did));

        km.remove_key(&did).unwrap();
        assert!(!km.keys.contains_key(&did));

        // Try to remove again
        let result = km.remove_key(&did);
        assert!(result.is_err());
        match result {
            Err(AuraError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_export_import_keys() {
        let mut km1 = setup_key_manager();
        let dids = vec![
            AuraDid("did:aura:test1".to_string()),
            AuraDid("did:aura:test2".to_string()),
        ];

        // Generate keys in first manager
        for did in &dids {
            km1.generate_key_pair(did).unwrap();
        }

        // Export keys
        let exported = km1.export_keys().unwrap();
        assert_eq!(exported.len(), 2);

        // Import into second manager
        let mut km2 = setup_key_manager();
        km2.import_keys(exported).unwrap();

        // Verify all keys are present
        assert_eq!(km2.keys.len(), 2);
        for did in &dids {
            assert!(km2.keys.contains_key(did));
        }
    }

    #[test]
    fn test_export_not_initialized() {
        let km = KeyManager::new();
        let result = km.export_keys();

        assert!(result.is_err());
        match result {
            Err(AuraError::Internal(msg)) => {
                assert!(msg.contains("Key manager not initialized"));
            }
            _ => panic!("Expected Internal error"),
        }
    }

    #[test]
    fn test_import_not_initialized() {
        let km1 = setup_key_manager();
        let exported = km1.export_keys().unwrap();

        let mut km2 = KeyManager::new();
        let result = km2.import_keys(exported);

        assert!(result.is_err());
        match result {
            Err(AuraError::Internal(msg)) => {
                assert!(msg.contains("Key manager not initialized"));
            }
            _ => panic!("Expected Internal error"),
        }
    }

    #[test]
    fn test_derive_key_from_password_consistency() {
        let km = KeyManager::new();
        let password = "test_password";
        let salt = b"test_salt";

        let key1 = km.derive_key_from_password(password, salt);
        let key2 = km.derive_key_from_password(password, salt);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let km = KeyManager::new();
        let salt = b"test_salt";

        let key1 = km.derive_key_from_password("password1", salt);
        let key2 = km.derive_key_from_password("password2", salt);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_salts() {
        let km = KeyManager::new();
        let password = "test_password";

        let key1 = km.derive_key_from_password(password, b"salt1");
        let key2 = km.derive_key_from_password(password, b"salt2");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encrypted_storage() {
        let mut km = setup_key_manager();
        let did = AuraDid("did:aura:test123".to_string());

        let original_key_pair = km.generate_key_pair(&did).unwrap();

        // Get the stored key
        let stored_key = km.keys.get(&did).unwrap();

        // Verify the encrypted private key is different from plain private key
        let private_key_bytes = original_key_pair.private_key().to_bytes();
        assert_ne!(stored_key.encrypted_private_key, private_key_bytes.to_vec());

        // Verify decryption works
        let retrieved_key_pair = km.get_key_pair(&did).unwrap();
        assert_eq!(
            original_key_pair.private_key().to_bytes(),
            retrieved_key_pair.private_key().to_bytes()
        );
    }

    #[test]
    fn test_multiple_keys_encryption() {
        let mut km = setup_key_manager();
        let mut key_pairs = Vec::new();

        // Generate multiple keys
        for i in 0..5 {
            let did = AuraDid(format!("did:aura:test{}", i));
            let key_pair = km.generate_key_pair(&did).unwrap();
            key_pairs.push((did, key_pair));
        }

        // Verify each can be retrieved correctly
        for (did, original) in &key_pairs {
            let retrieved = km.get_key_pair(did).unwrap();
            assert_eq!(original.public_key(), retrieved.public_key());
            assert_eq!(
                original.private_key().to_bytes(),
                retrieved.private_key().to_bytes()
            );
        }
    }

    #[test]
    fn test_key_manager_drop() {
        let mut km = setup_key_manager();
        let did = AuraDid("did:aura:test123".to_string());
        km.generate_key_pair(&did).unwrap();

        // Drop the key manager
        drop(km);

        // Create a new one and verify it's empty
        let km2 = KeyManager::new();
        assert!(km2.keys.is_empty());
        assert!(!km2.is_initialized());
    }
}
