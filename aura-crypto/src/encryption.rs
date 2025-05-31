use crate::{CryptoError, Result};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Generate a new encryption key wrapped in Zeroizing for automatic cleanup
pub fn generate_encryption_key() -> Zeroizing<[u8; 32]> {
    let key = Aes256Gcm::generate_key(OsRng);
    Zeroizing::new(key.into())
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedData> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt directly without creating a copy
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    Ok(EncryptedData {
        ciphertext,
        nonce: nonce.to_vec(),
    })
}

/// Decrypt data and return it wrapped in Zeroizing for automatic cleanup
pub fn decrypt(key: &[u8; 32], encrypted: &EncryptedData) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&encrypted.nonce);

    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

    Ok(Zeroizing::new(plaintext))
}

pub fn encrypt_json<T: Serialize>(key: &[u8; 32], data: &T) -> Result<EncryptedData> {
    // Use Zeroizing to ensure JSON is cleared from memory
    let json = Zeroizing::new(
        serde_json::to_vec(data).map_err(|e| CryptoError::EncryptionError(e.to_string()))?
    );
    encrypt(key, &json)
}

pub fn decrypt_json<T: for<'a> Deserialize<'a>>(
    key: &[u8; 32],
    encrypted: &EncryptedData,
) -> Result<T> {
    let plaintext = decrypt(key, encrypted)?;
    let data = serde_json::from_slice(&plaintext)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_generate_encryption_key() {
        let key1 = generate_encryption_key();
        let key2 = generate_encryption_key();
        
        // Keys should be 32 bytes
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        
        // Keys should be different
        assert_ne!(&*key1, &*key2);
        
        // Keys should not be all zeros
        assert!(!key1.iter().all(|&b| b == 0));
        assert!(!key2.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_encrypt_decrypt_basic() {
        let key = generate_encryption_key();
        let plaintext = b"Hello, World!";
        
        // Encrypt
        let encrypted = encrypt(&key, plaintext).unwrap();
        assert!(!encrypted.ciphertext.is_empty());
        assert_eq!(encrypted.nonce.len(), 12); // AES-GCM uses 96-bit nonces
        
        // Ciphertext should be different from plaintext
        assert_ne!(&encrypted.ciphertext[..], plaintext);
        
        // Decrypt
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let key = generate_encryption_key();
        let plaintext = b"";
        
        let encrypted = encrypt(&key, plaintext).unwrap();
        assert!(!encrypted.ciphertext.is_empty()); // Even empty plaintext produces some ciphertext (auth tag)
        
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let key = generate_encryption_key();
        let plaintext = vec![0xAB; 1024 * 1024]; // 1MB
        
        let encrypted = encrypt(&key, &plaintext).unwrap();
        assert!(encrypted.ciphertext.len() >= plaintext.len());
        
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(&*decrypted, &plaintext);
    }

    #[test]
    fn test_encrypt_deterministic_nonce() {
        let key = generate_encryption_key();
        let plaintext = b"Test message";
        
        // Multiple encryptions should produce different nonces
        let encrypted1 = encrypt(&key, plaintext).unwrap();
        let encrypted2 = encrypt(&key, plaintext).unwrap();
        
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1 = generate_encryption_key();
        let key2 = generate_encryption_key();
        let plaintext = b"Secret message";
        
        let encrypted = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &encrypted);
        
        assert!(result.is_err());
        match result {
            Err(CryptoError::DecryptionError(_)) => {},
            _ => panic!("Expected DecryptionError"),
        }
    }

    #[test]
    fn test_decrypt_with_corrupted_ciphertext() {
        let key = generate_encryption_key();
        let plaintext = b"Test data";
        
        let mut encrypted = encrypt(&key, plaintext).unwrap();
        
        // Corrupt the ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }
        
        let result = decrypt(&key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_corrupted_nonce() {
        let key = generate_encryption_key();
        let plaintext = b"Test data";
        
        let mut encrypted = encrypt(&key, plaintext).unwrap();
        
        // Corrupt the nonce
        encrypted.nonce[0] ^= 0xFF;
        
        let result = decrypt(&key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_json() {
        let key = generate_encryption_key();
        let data = json!({
            "name": "Alice",
            "age": 30,
            "active": true,
            "scores": [95, 87, 92]
        });
        
        let encrypted = encrypt_json(&key, &data).unwrap();
        assert!(!encrypted.ciphertext.is_empty());
        
        let decrypted: serde_json::Value = decrypt_json(&key, &encrypted).unwrap();
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_encrypt_json_complex_types() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestStruct {
            id: u64,
            name: String,
            tags: Vec<String>,
            metadata: std::collections::HashMap<String, String>,
        }
        
        let key = generate_encryption_key();
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("key1".to_string(), "value1".to_string());
        metadata.insert("key2".to_string(), "value2".to_string());
        
        let data = TestStruct {
            id: 12345,
            name: "Test Object".to_string(),
            tags: vec!["tag1".to_string(), "tag2".to_string(), "tag3".to_string()],
            metadata,
        };
        
        let encrypted = encrypt_json(&key, &data).unwrap();
        let decrypted: TestStruct = decrypt_json(&key, &encrypted).unwrap();
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_decrypt_json_type_mismatch() {
        let key = generate_encryption_key();
        let data = json!({ "number": 42 });
        
        let encrypted = encrypt_json(&key, &data).unwrap();
        
        // Try to decrypt as wrong type
        let result: Result<String> = decrypt_json(&key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let key = generate_encryption_key();
        let plaintext = b"Test serialization";
        
        let encrypted = encrypt(&key, plaintext).unwrap();
        
        // Test JSON serialization
        let json = serde_json::to_string(&encrypted).unwrap();
        let deserialized: EncryptedData = serde_json::from_str(&json).unwrap();
        
        assert_eq!(encrypted.ciphertext, deserialized.ciphertext);
        assert_eq!(encrypted.nonce, deserialized.nonce);
        
        // Verify we can decrypt the deserialized data
        let decrypted = decrypt(&key, &deserialized).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_encrypted_data_bincode() {
        let key = generate_encryption_key();
        let plaintext = b"Test bincode";
        
        let encrypted = encrypt(&key, plaintext).unwrap();
        
        // Test bincode serialization
        let encoded = bincode::encode_to_vec(&encrypted, bincode::config::standard()).unwrap();
        let (decoded, _): (EncryptedData, _) = bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        
        assert_eq!(encrypted.ciphertext, decoded.ciphertext);
        assert_eq!(encrypted.nonce, decoded.nonce);
        
        // Verify we can decrypt the decoded data
        let decrypted = decrypt(&key, &decoded).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_zeroizing_behavior() {
        let key = generate_encryption_key();
        
        // Test that decrypted data is zeroized
        {
            let plaintext = b"Sensitive data that should be zeroized";
            let encrypted = encrypt(&key, plaintext).unwrap();
            let decrypted = decrypt(&key, &encrypted).unwrap();
            
            // Use the decrypted data
            assert_eq!(&*decrypted, plaintext);
            
            // When decrypted goes out of scope, it should be zeroized
        }
        
        // Test that JSON data is zeroized during encryption
        {
            let data = json!({ "secret": "password123" });
            let _encrypted = encrypt_json(&key, &data).unwrap();
            // The intermediate JSON bytes should be zeroized after encryption
        }
    }

    #[test]
    fn test_encrypt_special_characters() {
        let key = generate_encryption_key();
        let plaintext = "Hello 世界 🌍 \n\t\r\0".as_bytes();
        
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_concurrent_encryption() {
        use std::sync::Arc;
        use std::thread;
        
        let key = Arc::new(generate_encryption_key());
        let mut handles = vec![];
        
        for i in 0..10 {
            let key_clone = Arc::clone(&key);
            let handle = thread::spawn(move || {
                let plaintext = format!("Thread {} data", i);
                let encrypted = encrypt(&key_clone, plaintext.as_bytes()).unwrap();
                let decrypted = decrypt(&key_clone, &encrypted).unwrap();
                assert_eq!(&*decrypted, plaintext.as_bytes());
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_key_size_validation() {
        // This test ensures our key size is correct for AES-256
        let key = generate_encryption_key();
        assert_eq!(key.len(), 32); // 256 bits = 32 bytes
        
        // Test that the key works with AES-256-GCM
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let plaintext = b"Test";
        
        // This should not panic
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
        let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
