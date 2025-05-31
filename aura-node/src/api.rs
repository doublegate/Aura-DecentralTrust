use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
    middleware,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::info;
use crate::auth::{self, AuthRequest, AuthResponse};
use crate::validation;

#[derive(Clone)]
pub struct ApiState {
    // In a real implementation, this would contain references to the node components
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

pub async fn start_api_server(addr: &str, enable_tls: bool, data_dir: std::path::PathBuf) -> anyhow::Result<()> {
    let state = ApiState {};
    
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
        .with_state(Arc::new(state));
    
    let addr: SocketAddr = addr.parse()?;
    
    if enable_tls {
        // Setup TLS
        let tls_config = crate::tls::setup_tls(&data_dir).await?;
        let _tls_acceptor = tls_config.build_acceptor().await?;
        
        info!("API server listening on https://{}", addr);
        info!("WARNING: TLS support is not fully implemented yet. Using HTTP for now.");
        
        // For now, just use HTTP even when TLS is requested
        // Full TLS implementation would require axum-server or similar
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
    } else {
        info!("API server listening on http://{}", addr);
        info!("WARNING: Running without TLS. Use --enable-tls for production!");
        
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
    }
    
    Ok(())
}

async fn root() -> &'static str {
    "Aura Node API v1.0.0"
}

async fn login(
    State(_state): State<Arc<ApiState>>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    // Validate credentials
    if !auth::validate_credentials(&req.node_id, &req.password) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    // Get role
    let role = auth::get_node_role(&req.node_id);
    
    // Create token
    let token = auth::create_token(&req.node_id, role)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(AuthResponse {
        token,
        expires_in: 86400, // 24 hours
    }))
}

async fn auth_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    // Extract and validate token from Authorization header
    let auth_header = req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    let token = &auth_header[7..];
    auth::verify_token(token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    Ok(next.run(req).await)
}

async fn get_node_info(
    State(_state): State<Arc<ApiState>>,
) -> Json<ApiResponse<NodeInfo>> {
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
        return Ok(Json(ApiResponse::error(format!("Invalid DID: {}", e))));
    }
    
    // In a real implementation, this would query the DID registry
    Err(StatusCode::NOT_FOUND)
}

async fn get_schema(
    Path(schema_id): Path<String>,
    State(_state): State<Arc<ApiState>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    // Validate schema ID
    if let Err(e) = validation::validate_schema_id(&schema_id) {
        return Ok(Json(ApiResponse::error(format!("Invalid schema ID: {}", e))));
    }
    
    // In a real implementation, this would query the schema registry
    Err(StatusCode::NOT_FOUND)
}

async fn submit_transaction(
    State(_state): State<Arc<ApiState>>,
    Json(request): Json<TransactionRequest>,
) -> Json<ApiResponse<TransactionResponse>> {
    // Validate transaction data size
    if let Ok(serialized) = serde_json::to_vec(&request) {
        if let Err(e) = validation::validate_transaction_size(&serialized) {
            return Json(ApiResponse::error(format!("Invalid transaction: {}", e)));
        }
    }
    
    // Validate transaction type specific data
    match &request.transaction_type {
        TransactionTypeRequest::RegisterDid { did_document: _ } => {
            // This would validate the DID document
        },
        TransactionTypeRequest::IssueCredential { claims, .. } => {
            if let Err(e) = validation::validate_credential_claims(claims) {
                return Json(ApiResponse::error(format!("Invalid claims: {}", e)));
            }
        },
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