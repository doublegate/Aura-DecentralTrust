use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tower_http::limit::RequestBodyLimitLayer;

/// Global JWT secret storage
static JWT_SECRET: OnceCell<Vec<u8>> = OnceCell::new();

/// Credentials storage
static CREDENTIALS: OnceCell<HashMap<String, Credential>> = OnceCell::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Credential {
    password_hash: String,
    role: String,
}

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

/// Initialize the authentication system with configuration
pub fn initialize_auth(jwt_secret: Vec<u8>, credentials_path: Option<&str>) -> anyhow::Result<()> {
    // Set JWT secret
    JWT_SECRET
        .set(jwt_secret)
        .map_err(|_| anyhow::anyhow!("JWT secret already initialized"))?;

    // Load credentials if path provided
    if let Some(path) = credentials_path {
        if std::path::Path::new(path).exists() {
            let content = std::fs::read_to_string(path)?;
            let creds: HashMap<String, Credential> = serde_json::from_str(&content)?;
            CREDENTIALS
                .set(creds)
                .map_err(|_| anyhow::anyhow!("Credentials already initialized"))?;
        } else {
            // Create default credentials file for development
            let mut default_creds = HashMap::new();
            
            // In production, these should be properly hashed passwords
            // For now, using simple hash for development
            default_creds.insert(
                "validator-node-1".to_string(),
                Credential {
                    password_hash: hash_password("change-me-in-production"),
                    role: "validator".to_string(),
                },
            );
            default_creds.insert(
                "query-node-1".to_string(),
                Credential {
                    password_hash: hash_password("change-me-in-production"),
                    role: "query".to_string(),
                },
            );
            
            // Save default credentials
            if let Some(parent) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, serde_json::to_string_pretty(&default_creds)?)?;
            
            CREDENTIALS
                .set(default_creds)
                .map_err(|_| anyhow::anyhow!("Credentials already initialized"))?;
        }
    } else {
        // No credentials file, initialize empty
        CREDENTIALS
            .set(HashMap::new())
            .map_err(|_| anyhow::anyhow!("Credentials already initialized"))?;
    }

    Ok(())
}

/// Simple password hashing for development (use bcrypt or argon2 in production)
fn hash_password(password: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Create a new JWT token
pub fn create_token(node_id: &str, role: &str, expiry_hours: u64) -> Result<String, AuthError> {
    let secret = JWT_SECRET.get().ok_or(AuthError::NotInitialized)?;
    
    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::hours(expiry_hours as i64);

    let claims = Claims {
        sub: node_id.to_string(),
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
        role: role.to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|_| AuthError::TokenCreation)
}

/// Verify and decode a JWT token
pub fn verify_token(token: &str) -> Result<TokenData<Claims>, AuthError> {
    let secret = JWT_SECRET.get().ok_or(AuthError::NotInitialized)?;
    
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret),
        &Validation::default(),
    )
    .map_err(|_| AuthError::InvalidToken)
}

/// Authentication error types
#[derive(Debug)]
#[allow(dead_code)]
pub enum AuthError {
    InvalidToken,
    TokenCreation,
    MissingToken,
    Unauthorized,
    NotInitialized,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::TokenCreation => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Token creation failed")
            }
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing authorization header"),
            AuthError::Unauthorized => (StatusCode::FORBIDDEN, "Unauthorized"),
            AuthError::NotInitialized => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Authentication system not initialized")
            }
        };

        let body = Json(serde_json::json!({
            "error": error_message
        }));

        (status, body).into_response()
    }
}

// /// JWT authentication extractor
// pub struct JwtAuth {
//     pub claims: Claims,
// }

// #[async_trait::async_trait]
// impl<S> FromRequestParts<S> for JwtAuth
// where
//     S: Send + Sync,
// {
//     type Rejection = AuthError;

//     async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
//         // Extract the token from the authorization header
//         let auth_header = parts
//             .headers
//             .get(header::AUTHORIZATION)
//             .and_then(|value| value.to_str().ok())
//             .ok_or(AuthError::MissingToken)?;

//         // Check if it's a Bearer token
//         if !auth_header.starts_with("Bearer ") {
//             return Err(AuthError::InvalidToken);
//         }

//         let token = &auth_header[7..]; // Skip "Bearer "

//         // Verify the token
//         let token_data = verify_token(token)?;

//         Ok(JwtAuth {
//             claims: token_data.claims,
//         })
//     }
// }

/// Create request body size limiter
pub fn create_body_limit_layer() -> RequestBodyLimitLayer {
    RequestBodyLimitLayer::new(1024 * 1024) // 1MB limit
}

/// Validate node credentials
pub fn validate_credentials(node_id: &str, password: &str) -> bool {
    let credentials = match CREDENTIALS.get() {
        Some(creds) => creds,
        None => return false,
    };

    if let Some(cred) = credentials.get(node_id) {
        // Compare password hash
        let provided_hash = hash_password(password);
        provided_hash == cred.password_hash
    } else {
        false
    }
}

/// Get role for node
pub fn get_node_role(node_id: &str) -> Option<String> {
    let credentials = CREDENTIALS.get()?;
    credentials.get(node_id).map(|cred| cred.role.clone())
}
