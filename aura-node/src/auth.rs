use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::limit::RequestBodyLimitLayer;

/// JWT secret key - in production, load from secure configuration
const JWT_SECRET: &[u8] = b"aura-secret-key-change-in-production";

/// API rate limiting configuration
pub const RATE_LIMIT_REQUESTS: u32 = 100;
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // Subject (user/node ID)
    pub exp: usize,   // Expiration time
    pub iat: usize,   // Issued at
    pub role: String, // Role (validator, query, admin)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub node_id: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub expires_in: u64,
}

/// Create a new JWT token
pub fn create_token(node_id: &str, role: &str) -> Result<String, AuthError> {
    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::hours(24); // 24 hour expiry
    
    let claims = Claims {
        sub: node_id.to_string(),
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
        role: role.to_string(),
    };
    
    encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET))
        .map_err(|_| AuthError::TokenCreation)
}

/// Verify and decode a JWT token
pub fn verify_token(token: &str) -> Result<TokenData<Claims>, AuthError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::default(),
    )
    .map_err(|_| AuthError::InvalidToken)
}

/// Authentication error types
#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
    TokenCreation,
    MissingToken,
    Unauthorized,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation failed"),
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing authorization header"),
            AuthError::Unauthorized => (StatusCode::FORBIDDEN, "Unauthorized"),
        };
        
        let body = Json(serde_json::json!({
            "error": error_message
        }));
        
        (status, body).into_response()
    }
}

/// JWT authentication extractor
pub struct JwtAuth {
    pub claims: Claims,
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for JwtAuth
where
    S: Send + Sync,
{
    type Rejection = AuthError;
    
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(AuthError::MissingToken)?;
        
        // Check if it's a Bearer token
        if !auth_header.starts_with("Bearer ") {
            return Err(AuthError::InvalidToken);
        }
        
        let token = &auth_header[7..]; // Skip "Bearer "
        
        // Verify the token
        let token_data = verify_token(token)?;
        
        Ok(JwtAuth {
            claims: token_data.claims,
        })
    }
}

/// Create request body size limiter
pub fn create_body_limit_layer() -> RequestBodyLimitLayer {
    RequestBodyLimitLayer::new(1024 * 1024) // 1MB limit
}

/// Validate node credentials (simplified for demo)
pub fn validate_credentials(node_id: &str, password: &str) -> bool {
    // In production, validate against secure storage
    // For now, accept specific test credentials
    match node_id {
        "validator-node-1" => password == "validator-password-1",
        "query-node-1" => password == "query-password-1",
        "admin" => password == "admin-password",
        _ => false,
    }
}

/// Get role for node
pub fn get_node_role(node_id: &str) -> &str {
    match node_id {
        "validator-node-1" => "validator",
        "query-node-1" => "query",
        "admin" => "admin",
        _ => "query",
    }
}