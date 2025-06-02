#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{ApiState, TransactionRequest, TransactionTypeRequest};
    use crate::auth;
    use crate::nonce_tracker::NonceTracker;
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use std::sync::Arc;
    use tempfile::TempDir;
    
    async fn setup_test_server() -> (TestServer, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        
        // Initialize auth
        auth::initialize_auth(b"test_secret".to_vec(), None).unwrap();
        
        // Create nonce tracker
        let nonce_tracker = NonceTracker::new(temp_dir.path())
            .map(|tracker| Arc::new(tracker))
            .ok();
        
        let state = ApiState {
            config: None,
            nonce_tracker,
        };
        
        // Create test app
        let app = crate::api::create_router(state);
        let server = TestServer::new(app).unwrap();
        
        (server, temp_dir)
    }
    
    #[tokio::test]
    async fn test_nonce_replay_protection() {
        let (server, _temp_dir) = setup_test_server().await;
        
        // Get auth token
        let login_response = server
            .post("/auth/login")
            .json(&serde_json::json!({
                "node_id": "test-node",
                "password": "test-password"
            }))
            .await;
        
        let token = login_response
            .json::<serde_json::Value>()
            .data
            .unwrap()["token"]
            .as_str()
            .unwrap();
        
        // Create a transaction
        let transaction = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: serde_json::json!({
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": "did:aura:test123",
                }),
            },
            signer_did: "did:aura:signer123".to_string(),
            signature: "mock_signature".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            nonce: "unique-nonce-123".to_string(),
            chain_id: "test-chain".to_string(),
        };
        
        // First submission should succeed
        let response = server
            .post("/transaction")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&transaction)
            .await;
        
        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<serde_json::Value>();
        assert!(body["success"].as_bool().unwrap());
        
        // Second submission with same nonce should fail
        let response = server
            .post("/transaction")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&transaction)
            .await;
        
        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<serde_json::Value>();
        assert!(!body["success"].as_bool().unwrap());
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("nonce already used"));
    }
    
    #[tokio::test]
    async fn test_nonce_expiry() {
        let (server, _temp_dir) = setup_test_server().await;
        
        // Get auth token
        let login_response = server
            .post("/auth/login")
            .json(&serde_json::json!({
                "node_id": "test-node",
                "password": "test-password"
            }))
            .await;
        
        let token = login_response
            .json::<serde_json::Value>()
            .data
            .unwrap()["token"]
            .as_str()
            .unwrap();
        
        // Create a transaction with old timestamp
        let old_transaction = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: serde_json::json!({
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": "did:aura:test456",
                }),
            },
            signer_did: "did:aura:signer456".to_string(),
            signature: "mock_signature".to_string(),
            timestamp: chrono::Utc::now().timestamp() - 400, // 400 seconds ago
            nonce: "old-nonce-456".to_string(),
            chain_id: "test-chain".to_string(),
        };
        
        // Submission with old timestamp should fail
        let response = server
            .post("/transaction")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&old_transaction)
            .await;
        
        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<serde_json::Value>();
        assert!(!body["success"].as_bool().unwrap());
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("timestamp too old"));
    }
    
    #[tokio::test]
    async fn test_unique_nonces_succeed() {
        let (server, _temp_dir) = setup_test_server().await;
        
        // Get auth token
        let login_response = server
            .post("/auth/login")
            .json(&serde_json::json!({
                "node_id": "test-node",
                "password": "test-password"
            }))
            .await;
        
        let token = login_response
            .json::<serde_json::Value>()
            .data
            .unwrap()["token"]
            .as_str()
            .unwrap();
        
        // Submit multiple transactions with unique nonces
        for i in 0..5 {
            let transaction = TransactionRequest {
                transaction_type: TransactionTypeRequest::RegisterDid {
                    did_document: serde_json::json!({
                        "@context": ["https://www.w3.org/ns/did/v1"],
                        "id": format!("did:aura:test{}", i),
                    }),
                },
                signer_did: format!("did:aura:signer{}", i),
                signature: "mock_signature".to_string(),
                timestamp: chrono::Utc::now().timestamp(),
                nonce: format!("unique-nonce-{}", uuid::Uuid::new_v4()),
                chain_id: "test-chain".to_string(),
            };
            
            let response = server
                .post("/transaction")
                .add_header("Authorization", format!("Bearer {}", token))
                .json(&transaction)
                .await;
            
            assert_eq!(response.status_code(), StatusCode::OK);
            let body = response.json::<serde_json::Value>();
            assert!(body["success"].as_bool().unwrap());
        }
    }
}