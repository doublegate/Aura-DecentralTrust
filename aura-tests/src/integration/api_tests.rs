//! Integration tests for Aura Node API
//! 
//! These tests verify the API functionality. Some tests require a running node.

#[cfg(test)]
mod tests {
    use aura_common::{AuraDid, DidDocument, TransactionId, Timestamp};
    use aura_crypto::KeyPair;
    use aura_ledger::{
        storage::Storage,
        did_registry::DidRegistry,
        transaction::{Transaction, TransactionType},
    };
    use std::sync::Arc;
    use tempfile::TempDir;
    use serde_json::json;

    // Helper to get auth token from running node
    async fn get_auth_token(client: &reqwest::Client, base_url: &str) -> Option<String> {
        let response = client
            .post(&format!("{}/auth/login", base_url))
            .json(&json!({
                "node_id": "validator-node-1",
                "password": "validator-password-1"
            }))
            .send()
            .await
            .ok()?;
        
        if response.status() != 200 {
            return None;
        }
        
        let body: serde_json::Value = response.json().await.ok()?;
        body["token"].as_str().map(|s| s.to_string())
    }

    #[tokio::test]
    async fn test_api_workflow_simulation() {
        // This test simulates what the API would do without actually running the server
        
        // 1. Setup storage
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());
        
        // 2. Create DID registry
        let mut did_registry = DidRegistry::new(storage.clone());
        
        // 3. Create a DID
        let keypair = KeyPair::generate().unwrap();
        let did = AuraDid::new("test-user");
        let did_doc = DidDocument::new(did.clone());
        
        // 4. Register DID (simulating API endpoint)
        did_registry.register_did(
            &did_doc,
            keypair.public_key().clone(),
            aura_common::types::BlockNumber(1)
        ).unwrap();
        
        // 5. Resolve DID (simulating API endpoint)
        let resolved = did_registry.resolve_did(&did).unwrap();
        assert!(resolved.is_some());
        let (resolved_doc, _record) = resolved.unwrap();
        assert_eq!(resolved_doc.id, did);
    }

    #[tokio::test]
    async fn test_root_endpoint() {
        let client = reqwest::Client::new();
        let base_url = "http://127.0.0.1:8080";
        
        let response = client
            .get(base_url)
            .send()
            .await;
        
        if let Ok(resp) = response {
            assert_eq!(resp.status(), 200);
            let text = resp.text().await.unwrap();
            assert_eq!(text, "Aura Node API v1.0.0");
        } else {
            eprintln!("Skipping test - node not running");
        }
    }
    
    #[tokio::test]
    async fn test_auth_login_success() {
        let client = reqwest::Client::new();
        let base_url = "http://127.0.0.1:8080";
        
        let response = client
            .post(&format!("{}/auth/login", base_url))
            .json(&json!({
                "node_id": "validator-node-1",
                "password": "validator-password-1"
            }))
            .send()
            .await;
        
        if let Ok(resp) = response {
            assert_eq!(resp.status(), 200);
            
            let body: serde_json::Value = resp.json().await.unwrap();
            assert!(body["token"].is_string());
            assert_eq!(body["expires_in"], 86400);
        } else {
            eprintln!("Skipping test - node not running");
        }
    }
    
    #[tokio::test]
    async fn test_auth_login_failure() {
        let client = reqwest::Client::new();
        let base_url = "http://127.0.0.1:8080";
        
        let response = client
            .post(&format!("{}/auth/login", base_url))
            .json(&json!({
                "node_id": "invalid-node",
                "password": "wrong-password"
            }))
            .send()
            .await;
        
        if let Ok(resp) = response {
            assert_eq!(resp.status(), 401);
        } else {
            eprintln!("Skipping test - node not running");
        }
    }
    
    #[tokio::test]
    async fn test_protected_endpoint_without_auth() {
        let client = reqwest::Client::new();
        let base_url = "http://127.0.0.1:8080";
        
        let response = client
            .get(&format!("{}/node/info", base_url))
            .send()
            .await;
        
        if let Ok(resp) = response {
            assert_eq!(resp.status(), 401);
        } else {
            eprintln!("Skipping test - node not running");
        }
    }
    
    #[tokio::test]
    async fn test_node_info_with_auth() {
        let client = reqwest::Client::new();
        let base_url = "http://127.0.0.1:8080";
        
        // Skip if node not running
        if client.get(base_url).send().await.is_err() {
            eprintln!("Skipping test - node not running");
            return;
        }
        
        if let Some(token) = get_auth_token(&client, base_url).await {
            let response = client
                .get(&format!("{}/node/info", base_url))
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await
                .unwrap();
            
            assert_eq!(response.status(), 200);
            
            let body: serde_json::Value = response.json().await.unwrap();
            assert!(body["success"].as_bool().unwrap());
            assert!(body["data"]["version"].is_string());
            assert!(body["data"]["node_type"].is_string());
        }
    }
    
    #[tokio::test]
    async fn test_did_resolution() {
        let client = reqwest::Client::new();
        let base_url = "http://127.0.0.1:8080";
        
        // Skip if node not running
        if client.get(base_url).send().await.is_err() {
            eprintln!("Skipping test - node not running");
            return;
        }
        
        if let Some(token) = get_auth_token(&client, base_url).await {
            // Try to resolve a DID
            let test_did = "did:aura:test123";
            let response = client
                .get(&format!("{}/did/{}", base_url, test_did))
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await
                .unwrap();
            
            // Should return 404 for non-existent DID
            assert_eq!(response.status(), 404);
        }
    }

    #[tokio::test]
    async fn test_transaction_submission() {
        let client = reqwest::Client::new();
        let base_url = "http://127.0.0.1:8080";
        
        // Skip if node not running
        if client.get(base_url).send().await.is_err() {
            eprintln!("Skipping test - node not running");
            return;
        }
        
        if let Some(token) = get_auth_token(&client, base_url).await {
            // Create a test transaction
            let keypair = KeyPair::generate().unwrap();
            let did = AuraDid::new("test-user");
            let did_doc = DidDocument::new(did.clone());
            
            let tx = Transaction {
                id: TransactionId(uuid::Uuid::new_v4().to_string()),
                transaction_type: TransactionType::RegisterDid { did_document: did_doc },
                timestamp: Timestamp::now(),
                sender: keypair.public_key().clone(),
                signature: aura_crypto::Signature(vec![0; 64]), // Would be real signature
                nonce: 1,
                chain_id: "test-chain".to_string(),
                expires_at: None,
            };
            
            let response = client
                .post(&format!("{}/transaction", base_url))
                .header("Authorization", format!("Bearer {token}"))
                .json(&tx)
                .send()
                .await
                .unwrap();
            
            // API should accept the transaction (even if it's not fully valid)
            assert!(response.status().is_success() || response.status() == 400);
        }
    }

    #[test]
    fn test_transaction_creation() {
        // Test what the API would do to create transactions
        let keypair = KeyPair::generate().unwrap();
        let did = AuraDid::new("test-user");
        let did_doc = DidDocument::new(did.clone());
        
        let tx = Transaction {
            id: TransactionId(uuid::Uuid::new_v4().to_string()),
            transaction_type: TransactionType::RegisterDid { did_document: did_doc },
            timestamp: Timestamp::now(),
            sender: keypair.public_key().clone(),
            signature: aura_crypto::Signature(vec![0; 64]),
            nonce: 1,
            chain_id: "test-chain".to_string(),
            expires_at: None,
        };
        
        // Validate transaction structure manually
        assert!(!tx.id.0.is_empty());
        assert!(tx.nonce > 0);
        assert!(!tx.chain_id.is_empty());
    }

    #[tokio::test]
    async fn test_concurrent_did_operations() {
        use tokio::sync::RwLock;
        
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());
        let did_registry = Arc::new(RwLock::new(DidRegistry::new(storage)));
        
        // Simulate concurrent DID registrations
        let mut handles = vec![];
        
        for i in 0..5 {
            let registry = did_registry.clone();
            let handle = tokio::spawn(async move {
                let keypair = KeyPair::generate().unwrap();
                let did = AuraDid::new(&format!("user-{}", i));
                let did_doc = DidDocument::new(did.clone());
                
                let mut reg = registry.write().await;
                reg.register_did(
                    &did_doc,
                    keypair.public_key().clone(),
                    aura_common::types::BlockNumber(i as u64 + 1)
                ).unwrap();
                
                drop(reg);
                
                // Verify registration
                let reg = registry.read().await;
                let resolved = reg.resolve_did(&did).unwrap();
                assert!(resolved.is_some());
            });
            
            handles.push(handle);
        }
        
        // Wait for all registrations
        for handle in handles {
            handle.await.unwrap();
        }
        
        // Verify all DIDs were registered
        let reg = did_registry.read().await;
        for i in 0..5 {
            let did = AuraDid::new(&format!("user-{}", i));
            assert!(reg.resolve_did(&did).unwrap().is_some());
        }
    }
}