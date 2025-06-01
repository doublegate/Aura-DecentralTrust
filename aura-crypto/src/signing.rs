use crate::{CryptoError, PrivateKey, PublicKey, Result};
use bincode::{Decode, Encode};
use ed25519_dalek::{Signature as Ed25519Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Signature(pub Vec<u8>);

impl Signature {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidKey(
                "Invalid signature length".to_string(),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub fn sign(private_key: &PrivateKey, message: &[u8]) -> Result<Signature> {
    let signature = private_key.signing_key().sign(message);
    Ok(Signature(signature.to_vec()))
}

pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool> {
    if signature.0.len() != 64 {
        return Ok(false);
    }

    let sig = Ed25519Signature::from_slice(&signature.0)
        .map_err(|e| CryptoError::VerificationError(e.to_string()))?;

    match public_key.verifying_key().verify(message, &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn sign_json<T: Serialize>(private_key: &PrivateKey, data: &T) -> Result<Signature> {
    let json = serde_json::to_vec(data).map_err(|e| CryptoError::SigningError(e.to_string()))?;
    sign(private_key, &json)
}

pub fn verify_json<T: Serialize>(
    public_key: &PublicKey,
    data: &T,
    signature: &Signature,
) -> Result<bool> {
    let json =
        serde_json::to_vec(data).map_err(|e| CryptoError::VerificationError(e.to_string()))?;
    verify(public_key, &json, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;
    use serde_json::json;

    #[test]
    fn test_signature_from_bytes() {
        let valid_bytes = vec![0x42; 64];
        let sig = Signature::from_bytes(valid_bytes.clone()).unwrap();
        assert_eq!(sig.to_bytes(), &valid_bytes[..]);

        // Test invalid length - too short
        let short_bytes = vec![0x42; 32];
        let result = Signature::from_bytes(short_bytes);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(msg)) => assert!(msg.contains("Invalid signature length")),
            _ => panic!("Expected InvalidKey error"),
        }

        // Test invalid length - too long
        let long_bytes = vec![0x42; 128];
        let result = Signature::from_bytes(long_bytes);
        assert!(result.is_err());

        // Test empty bytes
        let empty_bytes = vec![];
        let result = Signature::from_bytes(empty_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_verify_basic() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Hello, World!";

        // Sign message
        let signature = sign(keypair.private_key(), message).unwrap();
        assert_eq!(signature.to_bytes().len(), 64);

        // Verify with correct public key
        let valid = verify(keypair.public_key(), message, &signature).unwrap();
        assert!(valid);

        // Verify with wrong message
        let wrong_message = b"Hello, World!!";
        let invalid = verify(keypair.public_key(), wrong_message, &signature).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_sign_verify_empty_message() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"";

        let signature = sign(keypair.private_key(), message).unwrap();
        let valid = verify(keypair.public_key(), message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sign_verify_large_message() {
        let keypair = KeyPair::generate().unwrap();
        let message = vec![0xAB; 1024 * 1024]; // 1MB

        let signature = sign(keypair.private_key(), &message).unwrap();
        let valid = verify(keypair.public_key(), &message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_public_key() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();
        let message = b"Test message";

        // Sign with keypair1
        let signature = sign(keypair1.private_key(), message).unwrap();

        // Verify with keypair2's public key
        let valid = verify(keypair2.public_key(), message, &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_corrupted_signature() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Test message";

        let mut signature = sign(keypair.private_key(), message).unwrap();

        // Corrupt the signature
        signature.0[0] ^= 0xFF;

        let valid = verify(keypair.public_key(), message, &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_invalid_signature_length() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Test message";

        // Create invalid signature with wrong length
        let invalid_sig = Signature(vec![0x42; 32]); // Wrong length

        let valid = verify(keypair.public_key(), message, &invalid_sig).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_sign_json_basic() {
        let keypair = KeyPair::generate().unwrap();
        let data = json!({
            "name": "Alice",
            "age": 30,
            "active": true
        });

        let signature = sign_json(keypair.private_key(), &data).unwrap();
        assert_eq!(signature.to_bytes().len(), 64);

        let valid = verify_json(keypair.public_key(), &data, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sign_json_complex() {
        #[derive(Debug, Serialize, PartialEq)]
        struct TestData {
            id: u64,
            name: String,
            scores: Vec<i32>,
            metadata: std::collections::HashMap<String, String>,
        }

        let keypair = KeyPair::generate().unwrap();
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("key1".to_string(), "value1".to_string());
        metadata.insert("key2".to_string(), "value2".to_string());

        let data = TestData {
            id: 12345,
            name: "Test".to_string(),
            scores: vec![95, 87, 92],
            metadata,
        };

        let signature = sign_json(keypair.private_key(), &data).unwrap();
        let valid = verify_json(keypair.public_key(), &data, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_json_modified_data() {
        let keypair = KeyPair::generate().unwrap();
        let data1 = json!({ "value": 100 });
        let data2 = json!({ "value": 101 });

        let signature = sign_json(keypair.private_key(), &data1).unwrap();
        let valid = verify_json(keypair.public_key(), &data2, &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Test serialization";
        let signature = sign(keypair.private_key(), message).unwrap();

        // Test JSON serialization
        let json = serde_json::to_string(&signature).unwrap();
        let deserialized: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(signature.to_bytes(), deserialized.to_bytes());

        // Verify deserialized signature still works
        let valid = verify(keypair.public_key(), message, &deserialized).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_signature_bincode() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Test bincode";
        let signature = sign(keypair.private_key(), message).unwrap();

        // Test bincode serialization
        let encoded = bincode::encode_to_vec(&signature, bincode::config::standard()).unwrap();
        let (decoded, _): (Signature, _) =
            bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap();

        assert_eq!(signature.to_bytes(), decoded.to_bytes());

        // Verify decoded signature still works
        let valid = verify(keypair.public_key(), message, &decoded).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_deterministic_signing() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Deterministic test";

        let sig1 = sign(keypair.private_key(), message).unwrap();
        let sig2 = sign(keypair.private_key(), message).unwrap();

        // Ed25519 is deterministic - same key and message should produce same signature
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_sign_special_characters() {
        let keypair = KeyPair::generate().unwrap();
        let message = "Hello 世界 🌍 \n\t\r\0".as_bytes();

        let signature = sign(keypair.private_key(), message).unwrap();
        let valid = verify(keypair.public_key(), message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_concurrent_signing() {
        use std::sync::Arc;
        use std::thread;

        let keypair = Arc::new(KeyPair::generate().unwrap());
        let mut handles = vec![];

        for i in 0..10 {
            let keypair_clone = Arc::clone(&keypair);
            let handle = thread::spawn(move || {
                let message = format!("Thread {} message", i);
                let signature = sign(keypair_clone.private_key(), message.as_bytes()).unwrap();
                let valid =
                    verify(keypair_clone.public_key(), message.as_bytes(), &signature).unwrap();
                assert!(valid);
                (message, signature)
            });
            handles.push(handle);
        }

        let mut results = vec![];
        for handle in handles {
            results.push(handle.join().unwrap());
        }

        // Verify all signatures
        for (message, signature) in results {
            let valid = verify(keypair.public_key(), message.as_bytes(), &signature).unwrap();
            assert!(valid);
        }
    }

    #[test]
    fn test_signature_debug() {
        let sig = Signature(vec![0x42; 64]);
        let debug_str = format!("{:?}", sig);
        assert!(debug_str.contains("Signature"));
    }

    #[test]
    fn test_json_null_handling() {
        let keypair = KeyPair::generate().unwrap();

        // Test with null values
        let data = json!({ "field": null });
        let signature = sign_json(keypair.private_key(), &data).unwrap();
        let valid = verify_json(keypair.public_key(), &data, &signature).unwrap();
        assert!(valid);

        // Test that null != "null" string
        let data2 = json!({ "field": "null" });
        let invalid = verify_json(keypair.public_key(), &data2, &signature).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_json_array_order_matters() {
        let keypair = KeyPair::generate().unwrap();

        let data1 = json!({ "items": [1, 2, 3] });
        let data2 = json!({ "items": [3, 2, 1] });

        let signature = sign_json(keypair.private_key(), &data1).unwrap();

        // Order matters in JSON arrays
        let valid1 = verify_json(keypair.public_key(), &data1, &signature).unwrap();
        assert!(valid1);

        let valid2 = verify_json(keypair.public_key(), &data2, &signature).unwrap();
        assert!(!valid2);
    }

    #[test]
    fn test_multiple_signatures_same_key() {
        let keypair = KeyPair::generate().unwrap();

        let messages = vec![
            b"Message 1".to_vec(),
            b"Message 2".to_vec(),
            b"Message 3".to_vec(),
        ];

        let signatures: Vec<Signature> = messages
            .iter()
            .map(|msg| sign(keypair.private_key(), msg).unwrap())
            .collect();

        // Verify each signature matches its message
        for (i, (msg, sig)) in messages.iter().zip(signatures.iter()).enumerate() {
            let valid = verify(keypair.public_key(), msg, sig).unwrap();
            assert!(valid, "Signature {} should be valid", i);

            // Verify signature doesn't validate other messages
            for (j, other_msg) in messages.iter().enumerate() {
                if i != j {
                    let invalid = verify(keypair.public_key(), other_msg, sig).unwrap();
                    assert!(
                        !invalid,
                        "Signature {} should not validate message {}",
                        i, j
                    );
                }
            }
        }
    }
}
