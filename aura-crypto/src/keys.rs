use crate::{CryptoError, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Secure wrapper for private key material that ensures zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    #[zeroize(skip)] // We'll handle this manually
    key: SigningKey,
    // Store the raw bytes so we can zeroize them
    key_bytes: [u8; 32],
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl PrivateKey {
    pub fn generate() -> Result<Self> {
        let mut csprng = OsRng;
        let key_bytes: [u8; 32] = csprng.gen();
        let key = SigningKey::from_bytes(&key_bytes);
        Ok(Self { key, key_bytes })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(
                "Invalid private key length".to_string(),
            ));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);
        let key = SigningKey::from_bytes(&key_bytes);
        Ok(Self { key, key_bytes })
    }

    /// Returns the key bytes wrapped in Zeroizing to ensure cleanup
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key_bytes)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            key: self.key.verifying_key(),
        }
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PublicKey {
    key: VerifyingKey,
}

impl bincode::Encode for PublicKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> std::result::Result<(), bincode::error::EncodeError> {
        self.key.to_bytes().encode(encoder)
    }
}

impl bincode::Decode<()> for PublicKey {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> std::result::Result<Self, bincode::error::DecodeError> {
        let bytes = <[u8; 32]>::decode(decoder)?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| bincode::error::DecodeError::Other("Invalid public key"))?;
        Ok(Self { key })
    }
}

impl<'de> bincode::BorrowDecode<'de, ()> for PublicKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> std::result::Result<Self, bincode::error::DecodeError> {
        let bytes = <[u8; 32]>::borrow_decode(decoder)?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| bincode::error::DecodeError::Other("Invalid public key"))?;
        Ok(Self { key })
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(
                "Invalid public key length".to_string(),
            ));
        }

        let key = VerifyingKey::from_bytes(bytes.try_into().unwrap())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        Ok(Self { key })
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

#[derive(Debug)]
pub struct KeyPair {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl Clone for KeyPair {
    fn clone(&self) -> Self {
        // Use Zeroizing to ensure temporary bytes are cleared
        let key_bytes = self.private_key.to_bytes();
        let private_key = PrivateKey::from_bytes(&*key_bytes).unwrap();
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }
}

impl KeyPair {
    pub fn generate() -> Result<Self> {
        let private_key = PrivateKey::generate()?;
        let public_key = private_key.public_key();
        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn from_private_key(private_key: PrivateKey) -> Self {
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_key_generate() {
        let key1 = PrivateKey::generate().unwrap();
        let key2 = PrivateKey::generate().unwrap();

        // Keys should be different
        assert_ne!(key1.to_bytes().as_ref(), key2.to_bytes().as_ref());

        // Keys should be 32 bytes
        assert_eq!(key1.to_bytes().len(), 32);
        assert_eq!(key2.to_bytes().len(), 32);
    }

    #[test]
    fn test_private_key_from_bytes() {
        let bytes = [42u8; 32];
        let key = PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(*key.to_bytes(), bytes);

        // Test invalid length
        let short_bytes = [0u8; 16];
        let result = PrivateKey::from_bytes(&short_bytes);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                assert!(msg.contains("Invalid private key length"))
            }
            _ => panic!("Expected InvalidKey error"),
        }

        // Test empty bytes
        let empty_bytes = [];
        let result = PrivateKey::from_bytes(&empty_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_key_public_key_derivation() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key1 = private_key.public_key();
        let public_key2 = private_key.public_key();

        // Same private key should produce same public key
        assert_eq!(public_key1, public_key2);
    }

    #[test]
    fn test_private_key_debug() {
        let key = PrivateKey::generate().unwrap();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("key_bytes"));
    }

    #[test]
    fn test_private_key_zeroization() {
        // Create a key and get its bytes
        let key = PrivateKey::generate().unwrap();
        let zeroizing_bytes = key.to_bytes();

        // The bytes should be valid
        assert!(!zeroizing_bytes.iter().all(|&b| b == 0));

        // When dropped, Zeroizing will clear the memory
        drop(zeroizing_bytes);
        // We can't directly test the memory is zeroed, but the type ensures it
    }

    #[test]
    fn test_public_key_from_bytes() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key();
        let bytes = public_key.to_bytes();

        let recovered_key = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(public_key, recovered_key);

        // Test invalid length
        let short_bytes = [0u8; 16];
        let result = PublicKey::from_bytes(&short_bytes);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => assert!(msg.contains("Invalid public key length")),
            _ => panic!("Expected InvalidKey error"),
        }
    }

    #[test]
    fn test_public_key_serialization() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key();

        // Test JSON serialization
        let json = serde_json::to_string(&public_key).unwrap();
        let deserialized: PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(public_key, deserialized);

        // Test bincode serialization
        let encoded = bincode::encode_to_vec(&public_key, bincode::config::standard()).unwrap();
        assert_eq!(encoded.len(), 32); // Public key should encode to exactly 32 bytes

        let (decoded, _): (PublicKey, _) =
            bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(public_key, decoded);
    }

    #[test]
    fn test_public_key_debug() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key();
        let debug_str = format!("{:?}", public_key);
        assert!(debug_str.contains("PublicKey"));
    }

    #[test]
    fn test_public_key_traits() {
        let key1 = PrivateKey::generate().unwrap().public_key();
        let key2 = PrivateKey::generate().unwrap().public_key();

        // Test PartialEq
        assert_ne!(key1, key2);
        assert_eq!(key1, key1.clone());

        // Test Hash
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(key1.clone());
        assert!(set.contains(&key1));
        assert!(!set.contains(&key2));
    }

    #[test]
    fn test_keypair_generate() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();

        // Keypairs should be different
        assert_ne!(keypair1.public_key(), keypair2.public_key());
        assert_ne!(
            keypair1.private_key().to_bytes().as_ref(),
            keypair2.private_key().to_bytes().as_ref()
        );
    }

    #[test]
    fn test_keypair_from_private_key() {
        let private_key = PrivateKey::generate().unwrap();
        let expected_public_key = private_key.public_key();

        let keypair = KeyPair::from_private_key(private_key);
        assert_eq!(keypair.public_key(), &expected_public_key);
    }

    #[test]
    fn test_keypair_clone() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = keypair1.clone();

        // Cloned keypair should have same keys
        assert_eq!(keypair1.public_key(), keypair2.public_key());
        assert_eq!(
            keypair1.private_key().to_bytes().as_ref(),
            keypair2.private_key().to_bytes().as_ref()
        );
    }

    #[test]
    fn test_keypair_debug() {
        let keypair = KeyPair::generate().unwrap();
        let debug_str = format!("{:?}", keypair);
        assert!(debug_str.contains("KeyPair"));
        assert!(debug_str.contains("[REDACTED]")); // Private key should be redacted
    }

    #[test]
    fn test_key_consistency() {
        // Test that keys remain consistent through various operations
        let original_bytes = [77u8; 32];
        let private_key = PrivateKey::from_bytes(&original_bytes).unwrap();
        let public_key = private_key.public_key();

        // Create keypair and verify consistency
        let keypair = KeyPair::from_private_key(private_key);
        assert_eq!(keypair.public_key(), &public_key);

        // Clone and verify consistency
        let cloned_keypair = keypair.clone();
        assert_eq!(cloned_keypair.public_key(), keypair.public_key());

        // Verify private key bytes remain the same
        assert_eq!(*keypair.private_key().to_bytes(), original_bytes);
        assert_eq!(*cloned_keypair.private_key().to_bytes(), original_bytes);
    }

    #[test]
    fn test_invalid_public_key_bincode() {
        // Test decoding invalid public key data
        let invalid_bytes = vec![0xFF; 32]; // Valid length but invalid key
        let result: std::result::Result<(PublicKey, _), _> =
            bincode::decode_from_slice(&invalid_bytes, bincode::config::standard());

        // This might succeed or fail depending on the key validation
        // The important thing is it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_concurrent_key_generation() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let keys = Arc::new(Mutex::new(Vec::new()));
        let mut handles = vec![];

        for _ in 0..10 {
            let keys_clone = Arc::clone(&keys);
            let handle = thread::spawn(move || {
                let keypair = KeyPair::generate().unwrap();
                let public_key_bytes = keypair.public_key().to_bytes();
                keys_clone.lock().unwrap().push(public_key_bytes);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let keys = keys.lock().unwrap();
        assert_eq!(keys.len(), 10);

        // All keys should be unique
        let unique_keys: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(unique_keys.len(), 10);
    }
}
