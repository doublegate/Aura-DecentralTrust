use axum::{
    extract::{Path, State},
    http::StatusCode,
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
    pub transaction_type: String,
    pub data: serde_json::Value,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub transaction_id: String,
    pub status: String,
}

pub async fn start_api_server(addr: &str) -> anyhow::Result<()> {
    let state = ApiState {};
    
    let app = Router::new()
        .route("/", get(root))
        .route("/node/info", get(get_node_info))
        .route("/did/:did", get(resolve_did))
        .route("/schema/:id", get(get_schema))
        .route("/transaction", post(submit_transaction))
        .route("/revocation/:list_id/:index", get(check_revocation))
        .layer(CorsLayer::permissive())
        .with_state(Arc::new(state));
    
    let addr: SocketAddr = addr.parse()?;
    info!("API server listening on {}", addr);
    
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;
    
    Ok(())
}

async fn root() -> &'static str {
    "Aura Node API v1.0.0"
}

async fn get_node_info(
    State(state): State<Arc<ApiState>>,
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
    State(state): State<Arc<ApiState>>,
) -> Result<Json<ApiResponse<DidResolutionResponse>>, StatusCode> {
    // In a real implementation, this would query the DID registry
    Err(StatusCode::NOT_FOUND)
}

async fn get_schema(
    Path(schema_id): Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    // In a real implementation, this would query the schema registry
    Err(StatusCode::NOT_FOUND)
}

async fn submit_transaction(
    State(state): State<Arc<ApiState>>,
    Json(request): Json<TransactionRequest>,
) -> Json<ApiResponse<TransactionResponse>> {
    // In a real implementation, this would validate and submit the transaction
    let response = TransactionResponse {
        transaction_id: uuid::Uuid::new_v4().to_string(),
        status: "pending".to_string(),
    };
    
    Json(ApiResponse::success(response))
}

async fn check_revocation(
    Path((list_id, index)): Path<(String, u32)>,
    State(state): State<Arc<ApiState>>,
) -> Json<ApiResponse<bool>> {
    // In a real implementation, this would check the revocation registry
    Json(ApiResponse::success(false))
}