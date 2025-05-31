use crate::auth::{self, AuthRequest, AuthResponse};
use crate::validation;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    middleware,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::info;

#[derive(Clone)]
pub struct ApiState {
    // In a real implementation, this would contain references to the node components
    pub config: Option<crate::config::NodeConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub version: String,
    pub node_type: String,
    pub peer_id: String,
    pub block_height: u64,
    pub connected_peers: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DidResolutionResponse {
    pub did_document: serde_json::Value,
    pub metadata: DidMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DidMetadata {
    pub created: String,
    pub updated: String,
    pub deactivated: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionRequest {
    pub transaction_type: TransactionTypeRequest,
    pub nonce: u64,
    pub chain_id: String,
    pub timestamp: i64,
    pub signer_did: String,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TransactionTypeRequest {
    RegisterDid {
        did_document: serde_json::Value,
    },
    IssueCredential {
        issuer: String,
        holder: String,
        claims: serde_json::Value,
    },
    UpdateRevocation {
        list_id: String,
        indices: Vec<u32>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub transaction_id: String,
    pub status: String,
}

pub async fn start_api_server(
    addr: &str,
    enable_tls: bool,
    data_dir: std::path::PathBuf,
    config: Option<crate::config::NodeConfig>,
) -> anyhow::Result<()> {
    // Get rate limit config
    let (max_rpm, max_rph) = config.as_ref()
        .map(|c| (c.security.rate_limit_rpm, c.security.rate_limit_rph))
        .unwrap_or((60, 1000));

    // Create rate limiter
    let rate_limiter = crate::rate_limit::RateLimiter::new(max_rpm, max_rph);
    
    // Spawn cleanup task
    crate::rate_limit::spawn_cleanup_task(rate_limiter.clone());

    let state = ApiState { config };

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/", get(root))
        .route("/auth/login", post(login));

    // Protected routes (auth required)
    let protected_routes = Router::new()
        .route("/node/info", get(get_node_info))
        .route("/did/{did}", get(resolve_did))
        .route("/schema/{id}", get(get_schema))
        .route("/transaction", post(submit_transaction))
        .route("/revocation/{list_id}/{index}", get(check_revocation))
        .route_layer(middleware::from_fn(auth_middleware));

    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(CorsLayer::permissive())
        .layer(auth::create_body_limit_layer())
        .layer(middleware::from_fn_with_state(
            rate_limiter,
            crate::rate_limit::rate_limit_middleware,
        ))
        .with_state(Arc::new(state));

    let addr: SocketAddr = addr.parse()?;

    if enable_tls {
        // Setup TLS
        let tls_config = crate::tls::setup_tls(&data_dir).await?;

        info!("API server listening on https://{}", addr);

        // Use axum-server for TLS support
        let server_config = tls_config.into_server_config()?;
        let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(
            server_config,
        ));
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        info!("API server listening on http://{}", addr);
        info!("WARNING: Running without TLS. Use --enable-tls for production!");

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener, 
            app.into_make_service_with_connect_info::<SocketAddr>()
        ).await?;
    }

    Ok(())
}

async fn root() -> &'static str {
    "Aura Node API v1.0.0"
}

async fn login(
    State(state): State<Arc<ApiState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let ip_address = addr.ip().to_string();
    
    // Validate credentials
    if !auth::validate_credentials(&req.node_id, &req.password) {
        // Log failed authentication attempt
        crate::audit::log_security_event(
            crate::audit::SecurityEvent::AuthenticationAttempt {
                node_id: req.node_id.clone(),
                success: false,
                ip_address,
                reason: Some("Invalid credentials".to_string()),
            },
            None,
        ).await;
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Get role
    let role = auth::get_node_role(&req.node_id)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Get token expiry from config (default to 24 hours)
    let expiry_hours = state.config
        .as_ref()
        .map(|c| c.security.token_expiry_hours)
        .unwrap_or(24);

    // Create token
    let token = auth::create_token(&req.node_id, &role, expiry_hours)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Log successful authentication
    crate::audit::log_security_event(
        crate::audit::SecurityEvent::AuthenticationAttempt {
            node_id: req.node_id.clone(),
            success: true,
            ip_address,
            reason: None,
        },
        None,
    ).await;

    Ok(Json(AuthResponse {
        token,
        expires_in: expiry_hours * 3600, // Convert to seconds
    }))
}

async fn auth_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    use tracing::debug;

    debug!("Auth middleware called for path: {}", req.uri().path());

    // Extract and validate token from Authorization header
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());

    debug!("Auth header present: {}", auth_header.is_some());

    let auth_header = auth_header.ok_or_else(|| {
        debug!("No Authorization header found");
        StatusCode::UNAUTHORIZED
    })?;

    if !auth_header.starts_with("Bearer ") {
        debug!("Invalid auth header format");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = &auth_header[7..];
    auth::verify_token(token).map_err(|e| {
        debug!("Token verification failed: {:?}", e);
        StatusCode::UNAUTHORIZED
    })?;

    debug!("Auth successful for path: {}", req.uri().path());
    Ok(next.run(req).await)
}

async fn get_node_info(State(_state): State<Arc<ApiState>>) -> Json<ApiResponse<NodeInfo>> {
    let info = NodeInfo {
        version: "1.0.0".to_string(),
        node_type: "query".to_string(),
        peer_id: "12D3KooW...".to_string(), // Placeholder
        block_height: 0,
        connected_peers: 0,
    };

    Json(ApiResponse::success(info))
}

async fn resolve_did(
    Path(did): Path<String>,
    State(_state): State<Arc<ApiState>>,
) -> Result<Json<ApiResponse<DidResolutionResponse>>, StatusCode> {
    // Validate DID format
    if let Err(e) = validation::validate_did(&did) {
        use crate::error_sanitizer::sanitize_error_message;
        return Ok(Json(ApiResponse::error(sanitize_error_message(&e.to_string()).to_string())));
    }

    // TODO: In a real implementation, this would query the DID registry
    // For now, return a mock response
    let response = DidResolutionResponse {
        did_document: serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#key-1"),
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }],
            "authentication": [format!("{did}#key-1")],
            "assertionMethod": [format!("{did}#key-1")]
        }),
        metadata: DidMetadata {
            created: chrono::Utc::now().to_rfc3339(),
            updated: chrono::Utc::now().to_rfc3339(),
            deactivated: false,
        },
    };

    Ok(Json(ApiResponse::success(response)))
}

async fn get_schema(
    Path(schema_id): Path<String>,
    State(_state): State<Arc<ApiState>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    // Validate schema ID
    if let Err(e) = validation::validate_schema_id(&schema_id) {
        return Ok(Json(ApiResponse::error(format!("Invalid schema ID: {e}"))));
    }

    // TODO: In a real implementation, this would query the schema registry
    // For now, return a mock schema
    let schema = serde_json::json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/vc-json-schemas/v1"
        ],
        "id": format!("did:aura:schema:{schema_id}"),
        "type": "JsonSchema",
        "version": "1.0",
        "name": "Example Credential Schema",
        "description": "A schema for example credentials",
        "schema": {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "The name of the credential subject"
                },
                "dateOfBirth": {
                    "type": "string",
                    "format": "date",
                    "description": "The date of birth of the credential subject"
                }
            },
            "required": ["name"]
        },
        "metadata": {
            "created": chrono::Utc::now().to_rfc3339(),
            "updated": chrono::Utc::now().to_rfc3339()
        }
    });

    Ok(Json(ApiResponse::success(schema)))
}

async fn submit_transaction(
    State(_state): State<Arc<ApiState>>,
    Json(request): Json<TransactionRequest>,
) -> Json<ApiResponse<TransactionResponse>> {
    // Validate transaction data size
    if let Ok(serialized) = serde_json::to_vec(&request) {
        if let Err(e) = validation::validate_transaction_size(&serialized) {
            return Json(ApiResponse::error(format!("Invalid transaction: {e}")));
        }
    }

    // Validate signer DID
    if let Err(e) = validation::validate_did(&request.signer_did) {
        return Json(ApiResponse::error(format!("Invalid signer DID: {e}")));
    }

    // Verify transaction signature
    if let Err(e) = verify_transaction_signature(&request) {
        return Json(ApiResponse::error(format!("Invalid signature: {e}")));
    }

    // Check timestamp is recent (within 5 minutes)
    let now = chrono::Utc::now().timestamp();
    if (now - request.timestamp).abs() > 300 {
        return Json(ApiResponse::error("Transaction timestamp too old or in future".to_string()));
    }

    // TODO: Check nonce hasn't been used before (requires state storage)

    // Validate transaction type specific data
    match &request.transaction_type {
        TransactionTypeRequest::RegisterDid { did_document: _ } => {
            // This would validate the DID document
        }
        TransactionTypeRequest::IssueCredential { claims, .. } => {
            if let Err(e) = validation::validate_credential_claims(claims) {
                return Json(ApiResponse::error(format!("Invalid claims: {e}")));
            }
        }
        _ => {}
    }

    // In a real implementation, this would submit the transaction
    let response = TransactionResponse {
        transaction_id: uuid::Uuid::new_v4().to_string(),
        status: "pending".to_string(),
    };

    Json(ApiResponse::success(response))
}

async fn check_revocation(
    Path((list_id, index)): Path<(String, u32)>,
    State(_state): State<Arc<ApiState>>,
) -> Json<ApiResponse<bool>> {
    // Validate list ID format
    let sanitized_list_id = validation::sanitize_string(&list_id);
    if sanitized_list_id.is_empty() || sanitized_list_id.len() > 64 {
        return Json(ApiResponse::error("Invalid revocation list ID".to_string()));
    }

    // Validate index range
    if index > 1_000_000 {
        return Json(ApiResponse::error("Invalid revocation index".to_string()));
    }

    // In a real implementation, this would check the revocation registry
    Json(ApiResponse::success(false))
}

/// Verify transaction signature
fn verify_transaction_signature(request: &TransactionRequest) -> Result<(), String> {
    // Create a copy of the transaction without the signature for verification
    let tx_for_signing = serde_json::json!({
        "transaction_type": &request.transaction_type,
        "nonce": request.nonce,
        "chain_id": &request.chain_id,
        "timestamp": request.timestamp,
        "signer_did": &request.signer_did
    });
    
    // Serialize to get consistent bytes for verification
    let _message = serde_json::to_vec(&tx_for_signing)
        .map_err(|e| format!("Failed to serialize transaction: {}", e))?;
    
    // Decode the signature from hex
    let signature_bytes = hex::decode(&request.signature)
        .map_err(|e| format!("Invalid signature format: {}", e))?;
    
    if signature_bytes.len() != 64 {
        return Err("Invalid signature length".to_string());
    }
    
    // TODO: In production, this would:
    // 1. Resolve the signer's DID to get their public key
    // 2. Verify the signature using the public key
    // For now, we'll do basic validation
    
    // Basic validation: signature should not be all zeros
    if signature_bytes.iter().all(|&b| b == 0) {
        return Err("Invalid signature: all zeros".to_string());
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Method, Request, StatusCode};
    use tower::ServiceExt;
    use serde_json::json;
    
    #[test]
    fn test_api_response_success() {
        let data = "test data";
        let response = ApiResponse::success(data);
        
        assert!(response.success);
        assert_eq!(response.data, Some(data));
        assert!(response.error.is_none());
    }
    
    #[test]
    fn test_api_response_error() {
        let error_msg = "Something went wrong";
        let response: ApiResponse<String> = ApiResponse::error(error_msg.to_string());
        
        assert!(!response.success);
        assert!(response.data.is_none());
        assert_eq!(response.error, Some(error_msg.to_string()));
    }
    
    #[test]
    fn test_node_info_serialization() {
        let info = NodeInfo {
            version: "1.0.0".to_string(),
            node_type: "validator".to_string(),
            peer_id: "12D3KooW...".to_string(),
            block_height: 100,
            connected_peers: 5,
        };
        
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: NodeInfo = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.version, info.version);
        assert_eq!(deserialized.node_type, info.node_type);
        assert_eq!(deserialized.peer_id, info.peer_id);
        assert_eq!(deserialized.block_height, info.block_height);
        assert_eq!(deserialized.connected_peers, info.connected_peers);
    }
    
    #[test]
    fn test_did_resolution_response_serialization() {
        let response = DidResolutionResponse {
            did_document: json!({
                "id": "did:aura:test123",
                "verificationMethod": []
            }),
            metadata: DidMetadata {
                created: "2024-01-01T00:00:00Z".to_string(),
                updated: "2024-01-01T00:00:00Z".to_string(),
                deactivated: false,
            },
        };
        
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: DidResolutionResponse = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.did_document, response.did_document);
        assert_eq!(deserialized.metadata.created, response.metadata.created);
        assert_eq!(deserialized.metadata.deactivated, response.metadata.deactivated);
    }
    
    #[test]
    fn test_transaction_request_serialization() {
        let request = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: json!({
                    "id": "did:aura:test123"
                }),
            },
            nonce: 123,
            chain_id: "mainnet".to_string(),
            timestamp: 1234567890,
            signer_did: "did:aura:signer123".to_string(),
            signature: "abcd1234".to_string(),
        };
        
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"type\":\"RegisterDid\""));
        
        let deserialized: TransactionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.nonce, request.nonce);
        assert_eq!(deserialized.chain_id, request.chain_id);
    }
    
    #[test]
    fn test_transaction_type_variants() {
        // Test RegisterDid
        let register_did = TransactionTypeRequest::RegisterDid {
            did_document: json!({"id": "did:aura:test"}),
        };
        let json = serde_json::to_string(&register_did).unwrap();
        assert!(json.contains("RegisterDid"));
        
        // Test IssueCredential
        let issue_cred = TransactionTypeRequest::IssueCredential {
            issuer: "did:aura:issuer".to_string(),
            holder: "did:aura:holder".to_string(),
            claims: json!({"name": "John"}),
        };
        let json = serde_json::to_string(&issue_cred).unwrap();
        assert!(json.contains("IssueCredential"));
        
        // Test UpdateRevocation
        let update_rev = TransactionTypeRequest::UpdateRevocation {
            list_id: "list123".to_string(),
            indices: vec![1, 2, 3],
        };
        let json = serde_json::to_string(&update_rev).unwrap();
        assert!(json.contains("UpdateRevocation"));
    }
    
    #[test]
    fn test_verify_transaction_signature_valid() {
        // Create a valid signature (64 bytes hex)
        let valid_sig = "a".repeat(128); // 64 bytes in hex
        let request = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: json!({}),
            },
            nonce: 1,
            chain_id: "test".to_string(),
            timestamp: 1234567890,
            signer_did: "did:aura:test".to_string(),
            signature: valid_sig,
        };
        
        let result = verify_transaction_signature(&request);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_verify_transaction_signature_invalid_hex() {
        let request = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: json!({}),
            },
            nonce: 1,
            chain_id: "test".to_string(),
            timestamp: 1234567890,
            signer_did: "did:aura:test".to_string(),
            signature: "invalid_hex!@#".to_string(),
        };
        
        let result = verify_transaction_signature(&request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature format"));
    }
    
    #[test]
    fn test_verify_transaction_signature_wrong_length() {
        let request = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: json!({}),
            },
            nonce: 1,
            chain_id: "test".to_string(),
            timestamp: 1234567890,
            signer_did: "did:aura:test".to_string(),
            signature: "abcd".to_string(), // Too short
        };
        
        let result = verify_transaction_signature(&request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature length"));
    }
    
    #[test]
    fn test_verify_transaction_signature_all_zeros() {
        let request = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: json!({}),
            },
            nonce: 1,
            chain_id: "test".to_string(),
            timestamp: 1234567890,
            signer_did: "did:aura:test".to_string(),
            signature: "0".repeat(128), // All zeros
        };
        
        let result = verify_transaction_signature(&request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature: all zeros"));
    }
    
    #[tokio::test]
    async fn test_root_endpoint() {
        let response = root().await;
        assert_eq!(response, "Aura Node API v1.0.0");
    }
    
    #[tokio::test]
    async fn test_get_node_info() {
        let state = Arc::new(ApiState { config: None });
        let response = get_node_info(State(state)).await;
        
        assert!(response.0.success);
        let info = response.0.data.unwrap();
        assert_eq!(info.version, "1.0.0");
        assert_eq!(info.node_type, "query");
    }
    
    #[tokio::test]
    async fn test_resolve_did_valid() {
        let state = Arc::new(ApiState { config: None });
        let did = "did:aura:test123".to_string();
        
        let response = resolve_did(Path(did.clone()), State(state)).await.unwrap();
        
        assert!(response.0.success);
        let data = response.0.data.unwrap();
        assert!(data.did_document["id"].as_str().unwrap().contains(&did));
        assert!(!data.metadata.deactivated);
    }
    
    #[tokio::test]
    async fn test_resolve_did_invalid() {
        let state = Arc::new(ApiState { config: None });
        let invalid_did = "not-a-did".to_string();
        
        let response = resolve_did(Path(invalid_did), State(state)).await.unwrap();
        
        assert!(!response.0.success);
        assert!(response.0.error.is_some());
    }
    
    #[tokio::test]
    async fn test_get_schema_valid() {
        let state = Arc::new(ApiState { config: None });
        let schema_id = "schema123".to_string();
        
        let response = get_schema(Path(schema_id.clone()), State(state)).await.unwrap();
        
        assert!(response.0.success);
        let schema = response.0.data.unwrap();
        assert!(schema["id"].as_str().unwrap().contains(&schema_id));
    }
    
    #[tokio::test]
    async fn test_get_schema_invalid() {
        let state = Arc::new(ApiState { config: None });
        let invalid_id = "schema!@#$%".to_string();
        
        let response = get_schema(Path(invalid_id), State(state)).await.unwrap();
        
        assert!(!response.0.success);
        assert!(response.0.error.unwrap().contains("Invalid schema ID"));
    }
    
    #[tokio::test]
    async fn test_submit_transaction_valid() {
        let state = Arc::new(ApiState { config: None });
        let request = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: json!({"id": "did:aura:test"}),
            },
            nonce: 1,
            chain_id: "test".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            signer_did: "did:aura:signer123".to_string(),
            signature: "a".repeat(128), // Valid hex signature
        };
        
        let response = submit_transaction(State(state), Json(request)).await;
        
        assert!(response.0.success);
        let data = response.0.data.unwrap();
        assert!(!data.transaction_id.is_empty());
        assert_eq!(data.status, "pending");
    }
    
    #[tokio::test]
    async fn test_submit_transaction_invalid_did() {
        let state = Arc::new(ApiState { config: None });
        let request = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: json!({}),
            },
            nonce: 1,
            chain_id: "test".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            signer_did: "invalid-did".to_string(),
            signature: "a".repeat(128),
        };
        
        let response = submit_transaction(State(state), Json(request)).await;
        
        assert!(!response.0.success);
        assert!(response.0.error.unwrap().contains("Invalid signer DID"));
    }
    
    #[tokio::test]
    async fn test_submit_transaction_old_timestamp() {
        let state = Arc::new(ApiState { config: None });
        let old_timestamp = chrono::Utc::now().timestamp() - 400; // 400 seconds ago
        
        let request = TransactionRequest {
            transaction_type: TransactionTypeRequest::RegisterDid {
                did_document: json!({}),
            },
            nonce: 1,
            chain_id: "test".to_string(),
            timestamp: old_timestamp,
            signer_did: "did:aura:test".to_string(),
            signature: "a".repeat(128),
        };
        
        let response = submit_transaction(State(state), Json(request)).await;
        
        assert!(!response.0.success);
        assert!(response.0.error.unwrap().contains("timestamp too old"));
    }
    
    #[tokio::test]
    async fn test_submit_transaction_invalid_claims() {
        let state = Arc::new(ApiState { config: None });
        let request = TransactionRequest {
            transaction_type: TransactionTypeRequest::IssueCredential {
                issuer: "did:aura:issuer".to_string(),
                holder: "did:aura:holder".to_string(),
                claims: json!("not an object"), // Invalid claims
            },
            nonce: 1,
            chain_id: "test".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            signer_did: "did:aura:test".to_string(),
            signature: "a".repeat(128),
        };
        
        let response = submit_transaction(State(state), Json(request)).await;
        
        assert!(!response.0.success);
        assert!(response.0.error.unwrap().contains("Invalid claims"));
    }
    
    #[tokio::test]
    async fn test_check_revocation_valid() {
        let state = Arc::new(ApiState { config: None });
        
        let response = check_revocation(
            Path(("list123".to_string(), 42)),
            State(state),
        ).await;
        
        assert!(response.0.success);
        assert_eq!(response.0.data, Some(false)); // Not revoked
    }
    
    #[tokio::test]
    async fn test_check_revocation_invalid_list_id() {
        let state = Arc::new(ApiState { config: None });
        let long_id = "a".repeat(100); // Too long
        
        let response = check_revocation(
            Path((long_id, 42)),
            State(state),
        ).await;
        
        assert!(!response.0.success);
        assert!(response.0.error.unwrap().contains("Invalid revocation list ID"));
    }
    
    #[tokio::test]
    async fn test_check_revocation_invalid_index() {
        let state = Arc::new(ApiState { config: None });
        
        let response = check_revocation(
            Path(("list123".to_string(), 2_000_000)), // Too large
            State(state),
        ).await;
        
        assert!(!response.0.success);
        assert!(response.0.error.unwrap().contains("Invalid revocation index"));
    }
    
    #[tokio::test]
    async fn test_auth_middleware_no_header() {
        let req = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();
        
        let next = axum::middleware::Next::<Body, _>::new(|_req| async {
            Ok::<_, StatusCode>(axum::response::Response::new(Body::empty()))
        });
        
        let result = auth_middleware(req, next).await;
        assert_eq!(result.err(), Some(StatusCode::UNAUTHORIZED));
    }
    
    #[tokio::test]
    async fn test_auth_middleware_invalid_format() {
        let req = Request::builder()
            .uri("/protected")
            .header(header::AUTHORIZATION, "Basic abc123") // Wrong format
            .body(Body::empty())
            .unwrap();
        
        let next = axum::middleware::Next::<Body, _>::new(|_req| async {
            Ok::<_, StatusCode>(axum::response::Response::new(Body::empty()))
        });
        
        let result = auth_middleware(req, next).await;
        assert_eq!(result.err(), Some(StatusCode::UNAUTHORIZED));
    }
}
