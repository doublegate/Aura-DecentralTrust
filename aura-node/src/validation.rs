use aura_common::{AuraError, Result};
use once_cell::sync::Lazy;
use regex::Regex;

// Validation regexes
static DID_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^did:aura:[a-zA-Z0-9\-_]+$").unwrap());

static SCHEMA_ID_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9\-_]{1,64}$").unwrap());

#[allow(dead_code)]
static CHAIN_ID_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9\-]{1,32}$").unwrap());

// Size limits
pub const MAX_TRANSACTION_SIZE: usize = 100 * 1024; // 100KB
#[allow(dead_code)]
pub const MAX_DID_DOCUMENT_SIZE: usize = 10 * 1024; // 10KB
pub const MAX_CREDENTIAL_SIZE: usize = 50 * 1024; // 50KB
pub const MAX_STRING_LENGTH: usize = 1024;
pub const MAX_ARRAY_LENGTH: usize = 100;

/// Validate a DID format
pub fn validate_did(did: &str) -> Result<()> {
    if did.len() > MAX_STRING_LENGTH {
        return Err(AuraError::Validation("DID too long".to_string()));
    }

    if !DID_REGEX.is_match(did) {
        return Err(AuraError::Validation("Invalid DID format".to_string()));
    }

    Ok(())
}

/// Validate a schema ID
pub fn validate_schema_id(schema_id: &str) -> Result<()> {
    if !SCHEMA_ID_REGEX.is_match(schema_id) {
        return Err(AuraError::Validation(
            "Invalid schema ID format".to_string(),
        ));
    }

    Ok(())
}

/// Validate a chain ID
#[allow(dead_code)]
pub fn validate_chain_id(chain_id: &str) -> Result<()> {
    if !CHAIN_ID_REGEX.is_match(chain_id) {
        return Err(AuraError::Validation("Invalid chain ID format".to_string()));
    }

    Ok(())
}

/// Validate URL format and prevent SSRF
#[allow(dead_code)]
pub fn validate_url(url: &str) -> Result<()> {
    if url.len() > MAX_STRING_LENGTH {
        return Err(AuraError::Validation("URL too long".to_string()));
    }

    // Parse URL
    let parsed = url::Url::parse(url)
        .map_err(|_| AuraError::Validation("Invalid URL format".to_string()))?;

    // Check scheme
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err(AuraError::Validation("Invalid URL scheme".to_string())),
    }

    // Prevent localhost/private IPs
    if let Some(host) = parsed.host_str() {
        let blocked_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "::1"];
        if blocked_hosts.contains(&host) {
            return Err(AuraError::Validation("Invalid URL host".to_string()));
        }

        // Check for private IP ranges
        if host.starts_with("10.") || host.starts_with("172.16.") || host.starts_with("192.168.") {
            return Err(AuraError::Validation(
                "Private IP addresses not allowed".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validate transaction size
pub fn validate_transaction_size(data: &[u8]) -> Result<()> {
    if data.len() > MAX_TRANSACTION_SIZE {
        return Err(AuraError::Validation(format!(
            "Transaction too large: {} bytes (max: {})",
            data.len(),
            MAX_TRANSACTION_SIZE
        )));
    }
    Ok(())
}

/// Validate DID document
#[allow(dead_code)]
pub fn validate_did_document(doc: &aura_common::DidDocument) -> Result<()> {
    // Validate DID
    validate_did(&doc.id.to_string())?;

    // Check size when serialized
    let serialized = serde_json::to_vec(doc)
        .map_err(|e| AuraError::Validation(format!("Invalid DID document: {e}")))?;

    if serialized.len() > MAX_DID_DOCUMENT_SIZE {
        return Err(AuraError::Validation(format!(
            "DID document too large: {} bytes (max: {})",
            serialized.len(),
            MAX_DID_DOCUMENT_SIZE
        )));
    }

    // Validate verification methods
    if doc.verification_method.len() > MAX_ARRAY_LENGTH {
        return Err(AuraError::Validation(
            "Too many verification methods".to_string(),
        ));
    }

    // Validate service endpoints
    if doc.service.len() > MAX_ARRAY_LENGTH {
        return Err(AuraError::Validation(
            "Too many service endpoints".to_string(),
        ));
    }

    for service in &doc.service {
        validate_url(&service.service_endpoint)?;
    }

    Ok(())
}

/// Validate credential claims
pub fn validate_credential_claims(claims: &serde_json::Value) -> Result<()> {
    // Check if it's an object
    if !claims.is_object() {
        return Err(AuraError::Validation(
            "Claims must be an object".to_string(),
        ));
    }

    // Check size
    let serialized = serde_json::to_vec(claims)
        .map_err(|e| AuraError::Validation(format!("Invalid claims: {e}")))?;

    if serialized.len() > MAX_CREDENTIAL_SIZE {
        return Err(AuraError::Validation(format!(
            "Claims too large: {} bytes (max: {})",
            serialized.len(),
            MAX_CREDENTIAL_SIZE
        )));
    }

    // Recursively validate claim values
    validate_json_value(claims, 0)?;

    Ok(())
}

/// Recursively validate JSON values to prevent deep nesting attacks
fn validate_json_value(value: &serde_json::Value, depth: usize) -> Result<()> {
    const MAX_DEPTH: usize = 10;

    if depth > MAX_DEPTH {
        return Err(AuraError::Validation("JSON nesting too deep".to_string()));
    }

    match value {
        serde_json::Value::String(s) => {
            if s.len() > MAX_STRING_LENGTH {
                return Err(AuraError::Validation("String value too long".to_string()));
            }
        }
        serde_json::Value::Array(arr) => {
            if arr.len() > MAX_ARRAY_LENGTH {
                return Err(AuraError::Validation("Array too long".to_string()));
            }
            for item in arr {
                validate_json_value(item, depth + 1)?;
            }
        }
        serde_json::Value::Object(map) => {
            if map.len() > MAX_ARRAY_LENGTH {
                return Err(AuraError::Validation(
                    "Object has too many properties".to_string(),
                ));
            }
            for (key, val) in map {
                if key.len() > MAX_STRING_LENGTH {
                    return Err(AuraError::Validation("Object key too long".to_string()));
                }
                validate_json_value(val, depth + 1)?;
            }
        }
        _ => {} // Numbers, booleans, null are fine
    }

    Ok(())
}

/// Sanitize string input to prevent XSS
pub fn sanitize_string(input: &str) -> String {
    // Remove control characters and limit length
    input
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_STRING_LENGTH)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_did() {
        assert!(validate_did("did:aura:abc123").is_ok());
        assert!(validate_did("did:aura:test-node_123").is_ok());
    }

    #[test]
    fn test_invalid_did() {
        assert!(validate_did("did:other:abc123").is_err());
        assert!(validate_did("not-a-did").is_err());
        assert!(validate_did(&("did:aura:".to_string() + &"a".repeat(2000))).is_err());
    }

    #[test]
    fn test_url_validation() {
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("http://example.com/path").is_ok());

        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("https://localhost").is_err());
        assert!(validate_url("https://127.0.0.1").is_err());
        assert!(validate_url("https://192.168.1.1").is_err());
    }
}
