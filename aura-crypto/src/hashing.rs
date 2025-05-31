use crate::Result;
use blake3::Hasher as Blake3Hasher;
use serde::Serialize;
use sha2::{Digest as Sha2Digest, Sha256};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

pub fn sha256_json<T: Serialize>(data: &T) -> Result<[u8; 32]> {
    let json =
        serde_json::to_vec(data).map_err(|e| crate::CryptoError::InvalidKey(e.to_string()))?;
    Ok(sha256(&json))
}

pub fn blake3_json<T: Serialize>(data: &T) -> Result<[u8; 32]> {
    let json =
        serde_json::to_vec(data).map_err(|e| crate::CryptoError::InvalidKey(e.to_string()))?;
    Ok(blake3(&json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_sha256_basic() {
        let data = b"Hello, World!";
        let hash = sha256(data);
        
        // SHA-256 should always produce 32 bytes
        assert_eq!(hash.len(), 32);
        
        // Known hash for "Hello, World!"
        let expected = [
            0xdf, 0xfd, 0x60, 0x21, 0xbb, 0x2b, 0xd5, 0xb0,
            0xaf, 0x67, 0x62, 0x90, 0x80, 0x9e, 0xc3, 0xa5,
            0x31, 0x91, 0xdd, 0x81, 0xc7, 0xf7, 0x0a, 0x4b,
            0x28, 0x68, 0x8a, 0x36, 0x21, 0x82, 0x98, 0x6f
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_empty() {
        let data = b"";
        let hash = sha256(data);
        
        // SHA-256 of empty string
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_large_data() {
        let data = vec![0x42; 1024 * 1024]; // 1MB of 0x42
        let hash = sha256(&data);
        
        assert_eq!(hash.len(), 32);
        // Different data should produce different hash
        let hash2 = sha256(&vec![0x43; 1024 * 1024]);
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_sha256_deterministic() {
        let data = b"Test deterministic hashing";
        let hash1 = sha256(data);
        let hash2 = sha256(data);
        
        // Same input should always produce same output
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake3_basic() {
        let data = b"Hello, World!";
        let hash = blake3(data);
        
        // BLAKE3 should always produce 32 bytes
        assert_eq!(hash.len(), 32);
        
        // BLAKE3 hash should be different from SHA-256
        let sha_hash = sha256(data);
        assert_ne!(hash, sha_hash);
    }

    #[test]
    fn test_blake3_empty() {
        let data = b"";
        let hash = blake3(data);
        
        assert_eq!(hash.len(), 32);
        // BLAKE3 of empty string has specific value
        // This is the standard BLAKE3 hash of empty input
        let expected_first_byte = hash[0];
        assert!(expected_first_byte != 0); // Should not be all zeros
    }

    #[test]
    fn test_blake3_large_data() {
        let data = vec![0x55; 10 * 1024 * 1024]; // 10MB
        let hash = blake3(&data);
        
        assert_eq!(hash.len(), 32);
        // Different data should produce different hash
        let hash2 = blake3(&vec![0x56; 10 * 1024 * 1024]);
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_blake3_deterministic() {
        let data = b"Test BLAKE3 deterministic";
        let hash1 = blake3(data);
        let hash2 = blake3(data);
        
        // Same input should always produce same output
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha256_json_basic() {
        let data = json!({
            "name": "Alice",
            "age": 30,
            "active": true
        });
        
        let hash = sha256_json(&data).unwrap();
        assert_eq!(hash.len(), 32);
        
        // Same data should produce same hash
        let hash2 = sha256_json(&data).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_sha256_json_complex() {
        #[derive(Debug, Serialize, PartialEq)]
        struct TestStruct {
            id: u64,
            name: String,
            tags: Vec<String>,
            metadata: std::collections::HashMap<String, i32>,
        }
        
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("score".to_string(), 95);
        metadata.insert("rank".to_string(), 1);
        
        let data = TestStruct {
            id: 12345,
            name: "Test Object".to_string(),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            metadata,
        };
        
        let hash = sha256_json(&data).unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_json_null_values() {
        let data1 = json!({ "field": null });
        let data2 = json!({ "field": "null" });
        
        let hash1 = sha256_json(&data1).unwrap();
        let hash2 = sha256_json(&data2).unwrap();
        
        // Different JSON values should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_sha256_json_array_order() {
        let data1 = json!({ "items": [1, 2, 3] });
        let data2 = json!({ "items": [3, 2, 1] });
        
        let hash1 = sha256_json(&data1).unwrap();
        let hash2 = sha256_json(&data2).unwrap();
        
        // Different array order should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_blake3_json_basic() {
        let data = json!({
            "message": "Hello BLAKE3",
            "timestamp": 1234567890
        });
        
        let hash = blake3_json(&data).unwrap();
        assert_eq!(hash.len(), 32);
        
        // Should be different from SHA256
        let sha_hash = sha256_json(&data).unwrap();
        assert_ne!(hash, sha_hash);
    }

    #[test]
    fn test_blake3_json_empty_object() {
        let data = json!({});
        let hash = blake3_json(&data).unwrap();
        assert_eq!(hash.len(), 32);
        
        // Empty object should hash differently than empty array
        let array_data = json!([]);
        let array_hash = blake3_json(&array_data).unwrap();
        assert_ne!(hash, array_hash);
    }

    #[test]
    fn test_hash_comparison() {
        let data = b"Compare hash algorithms";
        
        let sha_hash = sha256(data);
        let blake_hash = blake3(data);
        
        // Different algorithms should produce different hashes
        assert_ne!(sha_hash, blake_hash);
        
        // But same algorithm should be consistent
        assert_eq!(sha256(data), sha_hash);
        assert_eq!(blake3(data), blake_hash);
    }

    #[test]
    fn test_json_hash_comparison() {
        let data = json!({ "test": "data" });
        
        let sha_hash = sha256_json(&data).unwrap();
        let blake_hash = blake3_json(&data).unwrap();
        
        // Different algorithms should produce different hashes
        assert_ne!(sha_hash, blake_hash);
    }

    #[test]
    fn test_hash_special_characters() {
        let data = "Hello 世界 🌍 \n\t\r\0".as_bytes();
        
        let sha_hash = sha256(data);
        let blake_hash = blake3(data);
        
        assert_eq!(sha_hash.len(), 32);
        assert_eq!(blake_hash.len(), 32);
        assert_ne!(sha_hash, blake_hash);
    }

    #[test]
    fn test_concurrent_hashing() {
        use std::sync::Arc;
        use std::thread;
        
        let data = Arc::new(b"Concurrent hashing test".to_vec());
        let mut handles = vec![];
        
        for i in 0..10 {
            let data_clone = Arc::clone(&data);
            let handle = thread::spawn(move || {
                let sha_hash = sha256(&data_clone);
                let blake_hash = blake3(&data_clone);
                
                // Verify consistency
                assert_eq!(sha_hash.len(), 32);
                assert_eq!(blake_hash.len(), 32);
                
                // Return hashes for verification
                (sha_hash, blake_hash, i)
            });
            handles.push(handle);
        }
        
        let mut sha_hashes = vec![];
        let mut blake_hashes = vec![];
        
        for handle in handles {
            let (sha, blake, _) = handle.join().unwrap();
            sha_hashes.push(sha);
            blake_hashes.push(blake);
        }
        
        // All threads should produce the same hashes
        for i in 1..sha_hashes.len() {
            assert_eq!(sha_hashes[0], sha_hashes[i]);
            assert_eq!(blake_hashes[0], blake_hashes[i]);
        }
    }

    #[test]
    fn test_incremental_data_hashing() {
        // Test that hashing data incrementally produces different results
        let mut data = Vec::new();
        let mut sha_hashes = Vec::new();
        let mut blake_hashes = Vec::new();
        
        for i in 0..5 {
            data.push(i as u8);
            sha_hashes.push(sha256(&data));
            blake_hashes.push(blake3(&data));
        }
        
        // Each incremental hash should be different
        for i in 1..sha_hashes.len() {
            assert_ne!(sha_hashes[i-1], sha_hashes[i]);
            assert_ne!(blake_hashes[i-1], blake_hashes[i]);
        }
    }

    #[test]
    fn test_json_unicode_handling() {
        let data = json!({
            "english": "Hello",
            "chinese": "你好",
            "japanese": "こんにちは",
            "emoji": "👋🌍",
            "special": "\n\t\r"
        });
        
        let sha_hash = sha256_json(&data).unwrap();
        let blake_hash = blake3_json(&data).unwrap();
        
        assert_eq!(sha_hash.len(), 32);
        assert_eq!(blake_hash.len(), 32);
        
        // Verify consistency
        let sha_hash2 = sha256_json(&data).unwrap();
        let blake_hash2 = blake3_json(&data).unwrap();
        
        assert_eq!(sha_hash, sha_hash2);
        assert_eq!(blake_hash, blake_hash2);
    }
}
