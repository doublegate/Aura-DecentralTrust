#[cfg(test)]
mod tests {
    use crate::api::{verify_transaction_signature, TransactionRequest, TransactionTypeRequest};
    use aura_crypto::keys::PrivateKey;
    use aura_crypto::signing::Signer;
    
    fn sign_transaction_simple(request: &TransactionRequest, private_key: &PrivateKey) -> String {
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
    async fn test_basic_signature_validation() {
        // Test without DID resolver - just basic validation
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
        let result = verify_transaction_signature(&request, &None).await;
        assert!(result.is_ok());
        
        // Test with all-zero signature
        let mut bad_request = request.clone();
        bad_request.signature = hex::encode([0u8; 64]);
        
        let result = verify_transaction_signature(&bad_request, &None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("all zeros"));
        
        // Test with invalid hex
        let mut bad_request = request.clone();
        bad_request.signature = "not-hex".to_string();
        
        let result = verify_transaction_signature(&bad_request, &None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature format"));
        
        // Test with wrong length
        let mut bad_request = request;
        bad_request.signature = hex::encode([1u8; 32]); // Too short
        
        let result = verify_transaction_signature(&bad_request, &None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature length"));
    }
    
    #[tokio::test] 
    async fn test_signature_generation_format() {
        let private_key = PrivateKey::generate();
        
        let request = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: serde_json::json!({
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": "did:aura:test123",
                }),
            },
            nonce: 99999,
            chain_id: "main".to_string(),
            timestamp: 1234567890,
            signer_did: "did:aura:signer".to_string(),
            signature: String::new(),
        };
        
        let signature = sign_transaction_simple(&request, &private_key);
        
        // Verify signature format
        assert_eq!(signature.len(), 128); // 64 bytes = 128 hex chars
        assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));
        
        // Verify it decodes correctly
        let bytes = hex::decode(&signature).unwrap();
        assert_eq!(bytes.len(), 64);
    }
}