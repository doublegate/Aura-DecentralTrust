# Security Implementation Guide

This guide provides step-by-step instructions for implementing the critical security fixes identified in the security review.

## Priority 1: Authentication & Authorization

### Step 1: Add JWT Dependencies

Add to `aura-node/Cargo.toml`:
```toml
jsonwebtoken = "9.3"
axum-extra = { version = "0.10", features = ["typed-header"] }
tower = { version = "0.5", features = ["util", "filter"] }
argon2 = "0.5"
```

### Step 2: Create Auth Module

Create `aura-node/src/auth.rs`:
```rust
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub token_expiry_secs: u64,
}

#[derive(Debug)]
pub struct AuthError {
    message: String,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": self.message
        }))).into_response()
    }
}

pub struct AuthenticatedUser {
    pub user_id: String,
    pub roles: Vec<String>,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| AuthError {
                message: "Missing authorization header".to_string(),
            })?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AuthError {
                message: "Invalid authorization header format".to_string(),
            })?;

        // In production, get secret from state
        let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string());
        
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|e| AuthError {
            message: format!("Invalid token: {}", e),
        })?;

        Ok(AuthenticatedUser {
            user_id: token_data.claims.sub,
            roles: token_data.claims.roles,
        })
    }
}

pub fn require_role(required_role: &str) -> impl Fn(&AuthenticatedUser) -> Result<(), StatusCode> + '_ {
    move |user: &AuthenticatedUser| {
        if user.roles.contains(&required_role.to_string()) {
            Ok(())
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }
}
```

### Step 3: Update API Routes

Update `aura-node/src/api.rs`:
```rust
mod auth;
use auth::{AuthenticatedUser, require_role};

// Protected endpoint example
async fn submit_transaction(
    auth_user: AuthenticatedUser,
    State(state): State<Arc<ApiState>>,
    Json(request): Json<TransactionRequest>,
) -> Result<Json<ApiResponse<TransactionResponse>>, StatusCode> {
    // Check if user has permission to submit transactions
    require_role("write")(&auth_user)?;
    
    // Validate request...
    
    // Process transaction...
}

// Public endpoint (no auth required)
async fn get_node_info(
    State(state): State<Arc<ApiState>>,
) -> Json<ApiResponse<NodeInfo>> {
    // ...existing implementation...
}

// Admin-only endpoint
async fn admin_endpoint(
    auth_user: AuthenticatedUser,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    require_role("admin")(&auth_user)?;
    
    // Admin functionality...
}
```

## Priority 2: Rate Limiting & DoS Protection

### Step 1: Create Rate Limiting Middleware

Create `aura-node/src/middleware.rs`:
```rust
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    pub async fn check_rate_limit(&self, ip: IpAddr) -> Result<(), StatusCode> {
        let now = Instant::now();
        let mut requests = self.requests.lock().await;
        
        let timestamps = requests.entry(ip).or_insert_with(Vec::new);
        
        // Remove old timestamps
        timestamps.retain(|&timestamp| now.duration_since(timestamp) < self.window);
        
        if timestamps.len() >= self.max_requests {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        
        timestamps.push(now);
        Ok(())
    }
}

pub async fn rate_limit_middleware(
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract IP address
    let ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|hv| hv.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .unwrap_or([127, 0, 0, 1].into());
    
    // Get rate limiter from request extensions or create default
    let rate_limiter = RateLimiter::new(100, Duration::from_secs(60));
    
    rate_limiter.check_rate_limit(ip).await?;
    
    Ok(next.run(req).await)
}

pub async fn validate_request_size(
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10MB
    
    if let Some(content_length) = req.headers().get("content-length") {
        if let Ok(size) = content_length.to_str().unwrap_or("0").parse::<usize>() {
            if size > MAX_BODY_SIZE {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
        }
    }
    
    Ok(next.run(req).await)
}
```

### Step 2: Apply Middleware to Routes

Update `aura-node/src/api.rs`:
```rust
use axum::middleware;
use crate::middleware::{rate_limit_middleware, validate_request_size};

pub async fn start_api_server(addr: &str) -> anyhow::Result<()> {
    let state = ApiState {};
    
    // Public routes (with rate limiting)
    let public_routes = Router::new()
        .route("/", get(root))
        .route("/node/info", get(get_node_info))
        .route("/did/:did", get(resolve_did))
        .route("/schema/:id", get(get_schema))
        .layer(middleware::from_fn(rate_limit_middleware));
    
    // Protected routes (auth required + rate limiting)
    let protected_routes = Router::new()
        .route("/transaction", post(submit_transaction))
        .layer(middleware::from_fn(validate_request_size))
        .layer(middleware::from_fn(rate_limit_middleware));
    
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(CorsLayer::new()
            .allow_origin(["http://localhost:3000".parse().unwrap()])
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]))
        .with_state(Arc::new(state));
    
    // ... rest of implementation
}
```

## Priority 3: Input Validation

### Step 1: Create Validation Module

Create `aura-node/src/validation.rs`:
```rust
use aura_common::{AuraDid, TransactionId};
use regex::Regex;
use serde_json::Value;
use lazy_static::lazy_static;

lazy_static! {
    static ref DID_REGEX: Regex = Regex::new(r"^did:aura:[a-zA-Z0-9._-]+$").unwrap();
    static ref SCHEMA_ID_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
    static ref HEX_REGEX: Regex = Regex::new(r"^[0-9a-fA-F]+$").unwrap();
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Invalid DID format")]
    InvalidDid,
    #[error("Invalid schema ID format")]
    InvalidSchemaId,
    #[error("Invalid signature format")]
    InvalidSignature,
    #[error("Invalid transaction data: {0}")]
    InvalidTransactionData(String),
    #[error("Data size exceeds limit")]
    DataSizeTooLarge,
}

pub fn validate_did(did: &str) -> Result<(), ValidationError> {
    if !DID_REGEX.is_match(did) {
        return Err(ValidationError::InvalidDid);
    }
    Ok(())
}

pub fn validate_schema_id(id: &str) -> Result<(), ValidationError> {
    if !SCHEMA_ID_REGEX.is_match(id) || id.len() > 256 {
        return Err(ValidationError::InvalidSchemaId);
    }
    Ok(())
}

pub fn validate_signature(signature: &str) -> Result<(), ValidationError> {
    if !HEX_REGEX.is_match(signature) || signature.len() != 128 {
        return Err(ValidationError::InvalidSignature);
    }
    Ok(())
}

pub fn validate_transaction_data(data: &Value) -> Result<(), ValidationError> {
    let data_str = serde_json::to_string(data)
        .map_err(|e| ValidationError::InvalidTransactionData(e.to_string()))?;
    
    if data_str.len() > 1_000_000 { // 1MB limit
        return Err(ValidationError::DataSizeTooLarge);
    }
    
    // Additional validation based on transaction type
    if let Some(tx_type) = data.get("type").and_then(Value::as_str) {
        match tx_type {
            "RegisterDid" => validate_did_document(data)?,
            "UpdateDid" => validate_did_update(data)?,
            "RegisterSchema" => validate_schema(data)?,
            _ => return Err(ValidationError::InvalidTransactionData("Unknown transaction type".to_string())),
        }
    }
    
    Ok(())
}

fn validate_did_document(data: &Value) -> Result<(), ValidationError> {
    // Validate required fields
    if !data.get("id").is_some() {
        return Err(ValidationError::InvalidTransactionData("Missing DID".to_string()));
    }
    
    if !data.get("verificationMethod").is_some() {
        return Err(ValidationError::InvalidTransactionData("Missing verification methods".to_string()));
    }
    
    Ok(())
}

fn validate_did_update(data: &Value) -> Result<(), ValidationError> {
    // Similar validation for updates
    Ok(())
}

fn validate_schema(data: &Value) -> Result<(), ValidationError> {
    // Validate schema structure
    Ok(())
}
```

### Step 2: Apply Validation to Endpoints

Update endpoints in `aura-node/src/api.rs`:
```rust
use crate::validation::{validate_did, validate_schema_id, validate_signature, validate_transaction_data};

async fn resolve_did(
    Path(did): Path<String>,
    State(state): State<Arc<ApiState>>,
) -> Result<Json<ApiResponse<DidResolutionResponse>>, StatusCode> {
    // Validate DID format
    validate_did(&did).map_err(|_| StatusCode::BAD_REQUEST)?;
    
    // Query DID registry...
    // ... existing implementation
}

async fn submit_transaction(
    auth_user: AuthenticatedUser,
    State(state): State<Arc<ApiState>>,
    Json(request): Json<TransactionRequest>,
) -> Result<Json<ApiResponse<TransactionResponse>>, StatusCode> {
    // Validate signature
    validate_signature(&request.signature).map_err(|_| StatusCode::BAD_REQUEST)?;
    
    // Validate transaction data
    validate_transaction_data(&request.data).map_err(|_| StatusCode::BAD_REQUEST)?;
    
    // Process transaction...
    // ... existing implementation
}
```

## Priority 4: Secure P2P Configuration

### Update Network Configuration

Update `aura-node/src/network.rs`:
```rust
use libp2p::core::upgrade::Version;
use libp2p::swarm::behaviour::ConnectionLimits;

impl NetworkManager {
    pub async fn new(config: NetworkConfig) -> anyhow::Result<Self> {
        // ... existing key generation code ...
        
        // Enhanced Gossipsub configuration
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .max_transmit_size(1_048_576) // 1MB max message
            .history_length(10)
            .history_gossip(5)
            .fanout_ttl(Duration::from_secs(60))
            .max_messages_per_rpc(Some(500))
            .max_ihave_length(100)
            .duplicate_cache_time(Duration::from_secs(60))
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build gossipsub config: {}", e))?;
        
        // ... existing gossipsub creation ...
        
        // Create Kademlia with limits
        let mut kademlia_config = kad::Config::default();
        kademlia_config.set_query_timeout(Duration::from_secs(30));
        kademlia_config.set_max_packet_size(8192);
        
        let kademlia = kad::Behaviour::with_config(
            local_peer_id,
            MemoryStore::new(local_peer_id),
            kademlia_config,
        );
        
        // ... existing identify creation ...
        
        // Add connection limits
        let limits = ConnectionLimits::default()
            .with_max_pending_incoming(Some(30))
            .with_max_pending_outgoing(Some(30))
            .with_max_established_incoming(Some(200))
            .with_max_established_outgoing(Some(200))
            .with_max_established_per_peer(Some(2));
        
        // Create swarm with enhanced security
        let mut swarm = SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default()
                    .set_window_update_mode(yamux::WindowUpdateMode::on_read())
            )
            .map_err(|e| anyhow::anyhow!("Failed to configure TCP transport: {:?}", e))?
            .with_bandwidth_logging()
            .with_behaviour(|_key| {
                let behaviour = AuraNetworkBehaviour {
                    gossipsub,
                    kademlia,
                    identify,
                    limits,
                };
                Ok(behaviour)
            })
            .map_err(|e| anyhow::anyhow!("Failed to configure behaviour: {:?}", e))?
            .build();
        
        // ... rest of implementation
    }
}
```

## Testing Security Implementations

### Create Security Tests

Create `aura-node/tests/security_tests.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    
    #[tokio::test]
    async fn test_rate_limiting() {
        let app = create_test_app();
        
        // Send multiple requests
        for i in 0..150 {
            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/node/info")
                        .header("x-forwarded-for", "192.168.1.1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            
            if i < 100 {
                assert_eq!(response.status(), StatusCode::OK);
            } else {
                assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            }
        }
    }
    
    #[tokio::test]
    async fn test_authentication_required() {
        let app = create_test_app();
        
        // Request without auth header
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/transaction")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"test": "data"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    
    #[tokio::test]
    async fn test_input_validation() {
        let app = create_test_app();
        
        // Invalid DID format
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/did/invalid-did-format")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
```

## Deployment Security Checklist

1. **Environment Variables**
   ```bash
   export JWT_SECRET=$(openssl rand -hex 32)
   export API_TLS_CERT=/path/to/cert.pem
   export API_TLS_KEY=/path/to/key.pem
   export RUST_LOG=info
   ```

2. **Firewall Rules**
   ```bash
   # Allow only necessary ports
   sudo ufw allow 9000/tcp  # P2P
   sudo ufw allow 8443/tcp  # HTTPS API
   sudo ufw deny 8080/tcp   # Block HTTP
   ```

3. **Process Isolation**
   ```bash
   # Run as non-root user
   sudo useradd -r -s /bin/false aura-node
   sudo chown -R aura-node:aura-node /var/lib/aura
   ```

4. **Resource Limits**
   ```bash
   # /etc/systemd/system/aura-node.service
   [Service]
   LimitNOFILE=65535
   LimitNPROC=4096
   MemoryMax=4G
   CPUQuota=200%
   ```

5. **Monitoring**
   - Set up Prometheus metrics
   - Configure alerting for anomalies
   - Log all API requests
   - Monitor rate limit violations

This implementation guide provides the foundation for securing the Aura network and API. Each component should be thoroughly tested before deployment.