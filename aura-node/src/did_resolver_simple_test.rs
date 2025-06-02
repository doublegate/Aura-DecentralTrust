#[cfg(test)]
mod tests {
    use crate::did_resolver::DIDResolver;
    use aura_common::did::{DidDocument, VerificationMethod, VerificationRelationship};
    use aura_common::{AuraDid, Timestamp};
    use aura_crypto::keys::PrivateKey;
    use aura_ledger::did_registry::DidRegistry;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    
    #[tokio::test]
    async fn test_extract_public_key_all_formats() {
        // This test doesn't need a full registry, just tests key extraction
        let private_key = PrivateKey::generate();
        let public_key = private_key.public_key();
        let key_bytes = public_key.to_bytes();
        
        // Create a dummy registry (won't be used)
        let dummy_storage = Arc::new(aura_ledger::storage::Storage::new_memory().unwrap());
        let registry = Arc::new(RwLock::new(DidRegistry::new(dummy_storage)));
        let resolver = DIDResolver::new(registry);
        
        // Test JWK format
        let method_jwk = VerificationMethod {
            id: "did:aura:test#key-1".to_string(),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            controller: AuraDid("did:aura:test".to_string()),
            public_key_jwk: Some(serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&key_bytes)
            })),
            public_key_base58: None,
            public_key_multibase: None,
        };
        
        let extracted = resolver.extract_public_key(&method_jwk).unwrap();
        assert_eq!(extracted.to_bytes(), key_bytes);
        
        // Test base58 format
        let method_base58 = VerificationMethod {
            id: "did:aura:test#key-2".to_string(),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            controller: AuraDid("did:aura:test".to_string()),
            public_key_jwk: None,
            public_key_base58: Some(bs58::encode(&key_bytes).into_string()),
            public_key_multibase: None,
        };
        
        let extracted = resolver.extract_public_key(&method_base58).unwrap();
        assert_eq!(extracted.to_bytes(), key_bytes);
        
        // Test multibase format with Ed25519 multicodec
        let mut multibase_bytes = vec![0xed, 0x01]; // Ed25519 multicodec prefix
        multibase_bytes.extend_from_slice(&key_bytes);
        
        let method_multibase = VerificationMethod {
            id: "did:aura:test#key-3".to_string(),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            controller: AuraDid("did:aura:test".to_string()),
            public_key_jwk: None,
            public_key_base58: None,
            public_key_multibase: Some(format!("z{}", bs58::encode(&multibase_bytes).into_string())),
        };
        
        let extracted = resolver.extract_public_key(&method_multibase).unwrap();
        assert_eq!(extracted.to_bytes(), key_bytes);
        
        // Test multibase format without multicodec prefix
        let method_multibase_raw = VerificationMethod {
            id: "did:aura:test#key-4".to_string(),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            controller: AuraDid("did:aura:test".to_string()),
            public_key_jwk: None,
            public_key_base58: None,
            public_key_multibase: Some(format!("z{}", bs58::encode(&key_bytes).into_string())),
        };
        
        let extracted = resolver.extract_public_key(&method_multibase_raw).unwrap();
        assert_eq!(extracted.to_bytes(), key_bytes);
    }
    
    #[tokio::test]
    async fn test_verification_method_validation() {
        // Test that at least one key format must be provided
        let invalid_method = VerificationMethod {
            id: "did:aura:test#key-1".to_string(),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            controller: AuraDid("did:aura:test".to_string()),
            public_key_jwk: None,
            public_key_base58: None,
            public_key_multibase: None,
        };
        
        assert!(invalid_method.validate().is_err());
        
        // Test that having any format makes it valid
        let valid_method = VerificationMethod {
            id: "did:aura:test#key-1".to_string(),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            controller: AuraDid("did:aura:test".to_string()),
            public_key_jwk: None,
            public_key_base58: Some("test".to_string()),
            public_key_multibase: None,
        };
        
        assert!(valid_method.validate().is_ok());
    }
}