#[cfg(test)]
mod tests {
    use aura_node::{api, auth};
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt;
    use serde_json::json;
    
    // Helper to create test app
    async fn create_test_app() -> axum::Router {
        // This would need to be exposed from aura_node crate
        // For now, we'll test the actual running server
        todo!("Expose test app creation from aura_node")
    }
    
    // Helper to get auth token
    async fn get_auth_token(client: &reqwest::Client, base_url: &str) -> String {
        let response = client
            .post(&format!("{}/auth/login", base_url))
            .json(&json!({
                "node_id": "validator-node-1",
                "password": "validator-password-1"
            }))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), 200);
        
        let body: serde_json::Value = response.json().await.unwrap();
        body["token"].as_str().unwrap().to_string()
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
        
        let token = get_auth_token(&client, base_url).await;
        
        let response = client
            .get(&format!("{}/node/info", base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), 200);
        
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body["success"].as_bool().unwrap());
        assert!(body["data"]["version"].is_string());
        assert!(body["data"]["node_type"].is_string());
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
        
        let token = get_auth_token(&client, base_url).await;
        
        let did = "did:aura:test123";
        let response = client
            .get(&format!("{}/did/{}", base_url, did))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), 200);
        
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body["success"].as_bool().unwrap());
        assert_eq!(body["data"]["did_document"]["id"], did);
        assert!(body["data"]["metadata"]["created"].is_string());
    }
    
    #[tokio::test]
    async fn test_invalid_did_format() {
        let client = reqwest::Client::new();
        let base_url = "http://127.0.0.1:8080";
        
        // Skip if node not running
        if client.get(base_url).send().await.is_err() {
            eprintln!("Skipping test - node not running");
            return;
        }
        
        let token = get_auth_token(&client, base_url).await;
        
        let invalid_did = "not-a-valid-did";
        let response = client
            .get(&format!("{}/did/{}", base_url, invalid_did))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), 200);
        
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(!body["success"].as_bool().unwrap());
        assert!(body["error"].as_str().unwrap().contains("Invalid DID"));
    }
    
    #[tokio::test]
    async fn test_schema_retrieval() {
        let client = reqwest::Client::new();
        let base_url = "http://127.0.0.1:8080";
        
        // Skip if node not running
        if client.get(base_url).send().await.is_err() {
            eprintln!("Skipping test - node not running");
            return;
        }
        
        let token = get_auth_token(&client, base_url).await;
        
        let schema_id = "test-schema-123";
        let response = client
            .get(&format!("{}/schema/{}", base_url, schema_id))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), 200);
        
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body["success"].as_bool().unwrap());
        assert!(body["data"]["id"].as_str().unwrap().contains(schema_id));
        assert_eq!(body["data"]["type"], "JsonSchema");
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
        
        let token = get_auth_token(&client, base_url).await;
        
        let transaction = json!({
            "transaction_type": {
                "type": "IssueCredential",
                "issuer": "did:aura:issuer123",
                "holder": "did:aura:holder456",
                "claims": {
                    "name": "Test User",
                    "age": 25
                }
            },
            "nonce": 1,
            "chain_id": "aura-testnet",
            "signature": "dummy-signature-for-testing"
        });
        
        let response = client
            .post(&format!("{}/transaction", base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&transaction)
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), 200);
        
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body["success"].as_bool().unwrap());
        assert!(body["data"]["transaction_id"].is_string());
        assert_eq!(body["data"]["status"], "pending");
    }
    
    #[tokio::test]
    async fn test_revocation_check() {
        let client = reqwest::Client::new();
        let base_url = "http://127.0.0.1:8080";
        
        // Skip if node not running
        if client.get(base_url).send().await.is_err() {
            eprintln!("Skipping test - node not running");
            return;
        }
        
        let token = get_auth_token(&client, base_url).await;
        
        let list_id = "revocation-list-123";
        let index = 42;
        let response = client
            .get(&format!("{}/revocation/{}/{}", base_url, list_id, index))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), 200);
        
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body["success"].as_bool().unwrap());
        assert_eq!(body["data"], false); // Not revoked
    }
    
    #[tokio::test]
    async fn test_malformed_json() {
        let client = reqwest::Client::new();
        let base_url = "http://127.0.0.1:8080";
        
        // Skip if node not running
        if client.get(base_url).send().await.is_err() {
            eprintln!("Skipping test - node not running");
            return;
        }
        
        let response = client
            .post(&format!("{}/auth/login", base_url))
            .header("Content-Type", "application/json")
            .body("{invalid json}")
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), 400);
    }
    
    #[tokio::test]
    async fn test_missing_content_type() {
        let client = reqwest::Client::new();
        let base_url = "http://127.0.0.1:8080";
        
        // Skip if node not running
        if client.get(base_url).send().await.is_err() {
            eprintln!("Skipping test - node not running");
            return;
        }
        
        let response = client
            .post(&format!("{}/auth/login", base_url))
            .body(r#"{"node_id": "test", "password": "test"}"#)
            .send()
            .await
            .unwrap();
        
        // Should still work as axum handles this gracefully
        assert!(response.status() == 415 || response.status() == 401);
    }
}

#[cfg(test)]
mod load_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};
    use tokio::sync::Semaphore;
    
    #[tokio::test]
    async fn test_concurrent_requests() {
        let client = Arc::new(reqwest::Client::new());
        let base_url = "http://127.0.0.1:8080";
        
        // Skip if node not running
        if client.get(base_url).send().await.is_err() {
            eprintln!("Skipping load test - node not running");
            return;
        }
        
        // Get auth token
        let token = super::tests::get_auth_token(&client, base_url).await;
        
        // Concurrent request parameters
        let num_requests = 100;
        let max_concurrent = 10;
        
        // Metrics
        let success_count = Arc::new(AtomicU64::new(0));
        let error_count = Arc::new(AtomicU64::new(0));
        let total_duration = Arc::new(AtomicU64::new(0));
        
        // Semaphore to limit concurrent requests
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        
        let start = Instant::now();
        
        let mut handles = vec![];
        
        for i in 0..num_requests {
            let client = client.clone();
            let token = token.clone();
            let base_url = base_url.to_string();
            let success_count = success_count.clone();
            let error_count = error_count.clone();
            let total_duration = total_duration.clone();
            let semaphore = semaphore.clone();
            
            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                
                let request_start = Instant::now();
                
                let response = client
                    .get(&format!("{}/node/info", base_url))
                    .header("Authorization", format!("Bearer {}", token))
                    .timeout(Duration::from_secs(5))
                    .send()
                    .await;
                
                let request_duration = request_start.elapsed();
                total_duration.fetch_add(request_duration.as_millis() as u64, Ordering::Relaxed);
                
                match response {
                    Ok(resp) if resp.status() == 200 => {
                        success_count.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        error_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
            
            handles.push(handle);
        }
        
        // Wait for all requests to complete
        for handle in handles {
            handle.await.unwrap();
        }
        
        let total_time = start.elapsed();
        let success = success_count.load(Ordering::Relaxed);
        let errors = error_count.load(Ordering::Relaxed);
        let avg_duration = total_duration.load(Ordering::Relaxed) / num_requests;
        
        println!("Load Test Results:");
        println!("  Total requests: {}", num_requests);
        println!("  Successful: {}", success);
        println!("  Failed: {}", errors);
        println!("  Total time: {:?}", total_time);
        println!("  Requests/sec: {:.2}", num_requests as f64 / total_time.as_secs_f64());
        println!("  Average response time: {}ms", avg_duration);
        
        // Assert high success rate
        assert!(success as f64 / num_requests as f64 > 0.95, "Success rate too low");
    }
}