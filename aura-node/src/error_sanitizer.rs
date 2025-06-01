/// Sanitize error messages to prevent information disclosure
pub fn sanitize_error_message(error: &str) -> &'static str {
    // Log the full error internally for debugging
    tracing::error!("Internal error: {}", error);

    // Return generic messages based on error patterns
    if error.contains("parse") || error.contains("deserialize") || error.contains("invalid format")
    {
        return "Invalid request format";
    }

    if error.contains("not found") || error.contains("does not exist") {
        return "Resource not found";
    }

    if error.contains("unauthorized") || error.contains("auth") || error.contains("token") {
        return "Authentication failed";
    }

    if error.contains("permission") || error.contains("forbidden") || error.contains("denied") {
        return "Access denied";
    }

    if error.contains("timeout") || error.contains("timed out") {
        return "Request timeout";
    }

    if error.contains("database") || error.contains("rocksdb") || error.contains("storage") {
        return "Storage error";
    }

    if error.contains("network") || error.contains("connection") || error.contains("peer") {
        return "Network error";
    }

    if error.contains("signature") || error.contains("crypto") || error.contains("verify") {
        return "Cryptographic verification failed";
    }

    if error.contains("size") || error.contains("too large") || error.contains("limit") {
        return "Request size limit exceeded";
    }

    // Default generic error
    "Internal server error"
}

/// Trait for sanitizing errors in Results
pub trait SanitizeError<T> {
    fn sanitize_error(self) -> Result<T, &'static str>;
}

impl<T, E: std::fmt::Display> SanitizeError<T> for Result<T, E> {
    fn sanitize_error(self) -> Result<T, &'static str> {
        self.map_err(|e| sanitize_error_message(&e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_sanitization() {
        assert_eq!(
            sanitize_error_message("Failed to parse JSON"),
            "Invalid request format"
        );
        assert_eq!(
            sanitize_error_message("User not found"),
            "Resource not found"
        );
        assert_eq!(
            sanitize_error_message("Invalid auth token"),
            "Authentication failed"
        );
        assert_eq!(sanitize_error_message("Permission denied"), "Access denied");
        assert_eq!(
            sanitize_error_message("Connection timeout"),
            "Request timeout"
        );
        assert_eq!(
            sanitize_error_message("rocksdb error: corrupted"),
            "Storage error"
        );
        assert_eq!(
            sanitize_error_message("Network peer disconnected"),
            "Network error"
        );
        assert_eq!(
            sanitize_error_message("Invalid signature"),
            "Cryptographic verification failed"
        );
        assert_eq!(
            sanitize_error_message("Payload too large"),
            "Request size limit exceeded"
        );
        assert_eq!(
            sanitize_error_message("Random error"),
            "Internal server error"
        );
    }
}
