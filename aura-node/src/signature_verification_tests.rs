#[cfg(test)]
mod tests {
    use crate::api::{ApiState, TransactionRequest, TransactionTypeRequest};
    use crate::did_resolver::DIDResolver;
    use aura_common::did::{DIDDocument, VerificationMethod};
    use aura_crypto::keys::{PrivateKey, PublicKey};
    use aura_crypto::signing::{Signer, Signature};
    use aura_ledger::did_registry::DIDRegistry;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    
    async fn setup_test_did(did: &str) -> (Arc<RwLock<DIDRegistry>>, PrivateKey) {
        let registry = Arc::new(RwLock::new(DIDRegistry::new()));
        let private_key = PrivateKey::generate();
        let public_key = private_key.public_key();
        
        // Create DID document with the key
        let verification_method = VerificationMethod {
            id: format!("{did}#key-1"),
            type_field: "Ed25519VerificationKey2020".to_string(),
            controller: did.to_string(),
            public_key_jwk: Some(serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(public_key.as_bytes())
            })),
            public_key_base58: None,
            public_key_multibase: None,
        };
        
        let doc = DIDDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_string()],
            id: did.to_string(),
            verification_method: vec![verification_method.clone()],
            authentication: vec![verification_method.id.clone()],
            assertion_method: Some(vec![verification_method.id.clone()]),
            key_agreement: None,
            capability_invocation: None,
            capability_delegation: None,
            service: None,
        };
        
        let mut registry_write = registry.write().await;
        registry_write.register_did(did, doc).unwrap();
        drop(registry_write);
        
        (registry, private_key)
    }
    
    fn sign_transaction(request: &TransactionRequest, private_key: &PrivateKey) -> String {
        // Create the same structure used for signing
        let tx_for_signing = serde_json::json!({
            "transaction_type": &request.transaction_type,
            "nonce": request.nonce,
            "chain_id": &request.chain_id,
            "timestamp": request.timestamp,
            "signer_did": &request.signer_did
        });
        
        let message = serde_json::to_vec(&tx_for_signing).unwrap();
        let signature = private_key.sign(&message);
        hex::encode(signature.to_bytes())
    }
    
    #[tokio::test]
    async fn test_valid_signature_verification() {
        let did = "did:aura:test_signer";
        let (registry, private_key) = setup_test_did(did).await;
        let did_resolver = Some(Arc::new(DIDResolver::new(registry)));
        
        let mut request = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: serde_json::json!({
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": "did:aura:new_did",
                }),
            },
            nonce: 12345,
            chain_id: "test-chain".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            signer_did: did.to_string(),
            signature: String::new(),
        };
        
        // Sign the transaction
        request.signature = sign_transaction(&request, &private_key);
        
        // Verify signature
        let result = crate::api::verify_transaction_signature(&request, &did_resolver).await;
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_invalid_signature_verification() {
        let did = "did:aura:test_signer";
        let (registry, _) = setup_test_did(did).await;
        let did_resolver = Some(Arc::new(DIDResolver::new(registry)));
        
        let request = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: serde_json::json!({
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": "did:aura:new_did",
                }),
            },
            nonce: 12345,
            chain_id: "test-chain".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            signer_did: did.to_string(),
            signature: hex::encode([0u8; 64]), // Invalid signature
        };
        
        // Verify signature
        let result = crate::api::verify_transaction_signature(&request, &did_resolver).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("all zeros"));
    }
    
    #[tokio::test]
    async fn test_wrong_signature_verification() {
        let did = "did:aura:test_signer";
        let (registry, _) = setup_test_did(did).await;
        let did_resolver = Some(Arc::new(DIDResolver::new(registry)));
        
        // Use a different key to sign
        let wrong_key = PrivateKey::generate();
        
        let mut request = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: serde_json::json!({
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": "did:aura:new_did",
                }),
            },
            nonce: 12345,
            chain_id: "test-chain".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            signer_did: did.to_string(),
            signature: String::new(),
        };
        
        // Sign with wrong key
        request.signature = sign_transaction(&request, &wrong_key);
        
        // Verify signature
        let result = crate::api::verify_transaction_signature(&request, &did_resolver).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Signature verification failed"));
    }
    
    #[tokio::test]
    async fn test_unknown_did_verification() {
        let registry = Arc::new(RwLock::new(DIDRegistry::new()));
        let did_resolver = Some(Arc::new(DIDResolver::new(registry)));
        
        let private_key = PrivateKey::generate();
        
        let mut request = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: serde_json::json!({
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": "did:aura:new_did",
                }),
            },
            nonce: 12345,
            chain_id: "test-chain".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            signer_did: "did:aura:unknown".to_string(),
            signature: String::new(),
        };
        
        // Sign the transaction
        request.signature = sign_transaction(&request, &private_key);
        
        // Verify signature
        let result = crate::api::verify_transaction_signature(&request, &did_resolver).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to resolve signer DID"));
    }
    
    #[tokio::test]
    async fn test_signature_without_resolver() {
        // Test that basic validation still works without a resolver
        let did_resolver = None;
        
        let request = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: serde_json::json!({
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": "did:aura:new_did",
                }),
            },
            nonce: 12345,
            chain_id: "test-chain".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            signer_did: "did:aura:test".to_string(),
            signature: hex::encode([1u8; 64]), // Non-zero signature
        };
        
        // Should pass basic validation
        let result = crate::api::verify_transaction_signature(&request, &did_resolver).await;
        assert!(result.is_ok());
    }
}