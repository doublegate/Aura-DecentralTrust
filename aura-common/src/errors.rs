use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuraError {
    #[error("DID error: {0}")]
    Did(String),

    #[error("Verifiable Credential error: {0}")]
    Vc(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Ledger error: {0}")]
    Ledger(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, AuraError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        // Test each error variant's display implementation
        let errors = vec![
            AuraError::Did("Invalid DID format".to_string()),
            AuraError::Vc("Invalid credential".to_string()),
            AuraError::Crypto("Key generation failed".to_string()),
            AuraError::Ledger("Block not found".to_string()),
            AuraError::Network("Connection timeout".to_string()),
            AuraError::Storage("Database error".to_string()),
            AuraError::Validation("Invalid input".to_string()),
            AuraError::Serialization("JSON parse error".to_string()),
            AuraError::InvalidSignature,
            AuraError::InvalidProof,
            AuraError::NotFound("Resource not found".to_string()),
            AuraError::AlreadyExists("DID already registered".to_string()),
            AuraError::Unauthorized,
            AuraError::Internal("Unexpected error".to_string()),
        ];

        for error in errors {
            let display = format!("{}", error);
            assert!(!display.is_empty());

            // Verify error messages contain expected content
            match &error {
                AuraError::Did(msg) => {
                    assert!(display.contains("DID error") && display.contains(msg))
                }
                AuraError::Vc(msg) => assert!(
                    display.contains("Verifiable Credential error") && display.contains(msg)
                ),
                AuraError::Crypto(msg) => {
                    assert!(display.contains("Cryptographic error") && display.contains(msg))
                }
                AuraError::Ledger(msg) => {
                    assert!(display.contains("Ledger error") && display.contains(msg))
                }
                AuraError::Network(msg) => {
                    assert!(display.contains("Network error") && display.contains(msg))
                }
                AuraError::Storage(msg) => {
                    assert!(display.contains("Storage error") && display.contains(msg))
                }
                AuraError::Validation(msg) => {
                    assert!(display.contains("Validation error") && display.contains(msg))
                }
                AuraError::Serialization(msg) => {
                    assert!(display.contains("Serialization error") && display.contains(msg))
                }
                AuraError::InvalidSignature => assert_eq!(display, "Invalid signature"),
                AuraError::InvalidProof => assert_eq!(display, "Invalid proof"),
                AuraError::NotFound(msg) => {
                    assert!(display.contains("Not found") && display.contains(msg))
                }
                AuraError::AlreadyExists(msg) => {
                    assert!(display.contains("Already exists") && display.contains(msg))
                }
                AuraError::Unauthorized => assert_eq!(display, "Unauthorized"),
                AuraError::Internal(msg) => {
                    assert!(display.contains("Internal error") && display.contains(msg))
                }
            }
        }
    }

    #[test]
    fn test_error_debug() {
        // Test Debug implementation
        let error = AuraError::Did("Debug test".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Did"));
        assert!(debug_str.contains("Debug test"));
    }

    #[test]
    fn test_result_type() {
        // Test the Result type alias
        fn returns_ok() -> Result<String> {
            Ok("Success".to_string())
        }

        fn returns_err() -> Result<String> {
            Err(AuraError::NotFound("Item not found".to_string()))
        }

        assert_eq!(returns_ok().unwrap(), "Success");
        assert!(returns_err().is_err());

        match returns_err() {
            Err(AuraError::NotFound(msg)) => assert_eq!(msg, "Item not found"),
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_error_variants_with_empty_strings() {
        // Test error variants with empty string messages
        let errors = vec![
            AuraError::Did("".to_string()),
            AuraError::Vc("".to_string()),
            AuraError::Crypto("".to_string()),
            AuraError::Ledger("".to_string()),
            AuraError::Network("".to_string()),
            AuraError::Storage("".to_string()),
            AuraError::Validation("".to_string()),
            AuraError::Serialization("".to_string()),
            AuraError::NotFound("".to_string()),
            AuraError::AlreadyExists("".to_string()),
            AuraError::Internal("".to_string()),
        ];

        for error in errors {
            let display = format!("{}", error);
            assert!(!display.is_empty());
            // Even with empty messages, the error type prefix should be present
            assert!(
                display.contains("error:")
                    || display.contains("Not found:")
                    || display.contains("Already exists:")
            );
        }
    }

    #[test]
    fn test_error_source() {
        // Test that errors implement std::error::Error trait
        use std::error::Error;

        let error = AuraError::Did("Test error".to_string());
        // source() should return None for these simple errors
        assert!(error.source().is_none());
    }

    #[test]
    fn test_error_conversion_in_functions() {
        // Test using errors in typical function patterns
        fn may_fail(should_fail: bool) -> Result<i32> {
            if should_fail {
                Err(AuraError::Validation("Invalid parameter".to_string()))
            } else {
                Ok(42)
            }
        }

        // Test successful case
        assert_eq!(may_fail(false).unwrap(), 42);

        // Test error case
        let result = may_fail(true);
        assert!(result.is_err());
        if let Err(AuraError::Validation(msg)) = result {
            assert_eq!(msg, "Invalid parameter");
        } else {
            panic!("Expected Validation error");
        }
    }

    #[test]
    fn test_error_chaining_with_map_err() {
        // Test error conversion patterns commonly used in the codebase
        fn parse_number(s: &str) -> Result<i32> {
            s.parse::<i32>()
                .map_err(|e| AuraError::Validation(format!("Failed to parse number: {}", e)))
        }

        // Test successful parsing
        assert_eq!(parse_number("42").unwrap(), 42);

        // Test failed parsing
        let result = parse_number("not_a_number");
        assert!(result.is_err());
        if let Err(AuraError::Validation(msg)) = result {
            assert!(msg.contains("Failed to parse number"));
        } else {
            panic!("Expected Validation error");
        }
    }

    #[test]
    fn test_error_pattern_matching() {
        // Test comprehensive pattern matching on errors
        let errors: Vec<AuraError> = vec![
            AuraError::InvalidSignature,
            AuraError::InvalidProof,
            AuraError::Unauthorized,
        ];

        for error in errors {
            match error {
                AuraError::InvalidSignature => {
                    assert_eq!(format!("{}", error), "Invalid signature");
                }
                AuraError::InvalidProof => {
                    assert_eq!(format!("{}", error), "Invalid proof");
                }
                AuraError::Unauthorized => {
                    assert_eq!(format!("{}", error), "Unauthorized");
                }
                _ => panic!("Unexpected error variant"),
            }
        }
    }

    #[test]
    fn test_error_equality() {
        // Test that errors can be compared
        let err1 = AuraError::Did("Same message".to_string());
        let err2 = AuraError::Did("Same message".to_string());
        let err3 = AuraError::Did("Different message".to_string());
        let err4 = AuraError::Vc("Same message".to_string());

        // Same variant and message should be equal
        assert_eq!(format!("{}", err1), format!("{}", err2));

        // Different messages should be different
        assert_ne!(format!("{}", err1), format!("{}", err3));

        // Different variants should be different
        assert_ne!(format!("{}", err1), format!("{}", err4));
    }

    #[test]
    fn test_error_in_result_chain() {
        // Test error propagation in Result chains
        fn step1() -> Result<String> {
            Ok("step1".to_string())
        }

        fn step2(input: String) -> Result<String> {
            if input == "step1" {
                Ok(format!("{} -> step2", input))
            } else {
                Err(AuraError::Validation("Invalid input to step2".to_string()))
            }
        }

        fn step3(input: String) -> Result<String> {
            if input.contains("step2") {
                Ok(format!("{} -> step3", input))
            } else {
                Err(AuraError::Internal("Step 3 failed".to_string()))
            }
        }

        // Test successful chain
        let result = step1().and_then(step2).and_then(step3);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "step1 -> step2 -> step3");

        // Test failing chain
        let fail_result = Ok("wrong".to_string()).and_then(step2).and_then(step3);

        assert!(fail_result.is_err());
        match fail_result {
            Err(AuraError::Validation(msg)) => assert!(msg.contains("Invalid input to step2")),
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_error_with_special_characters() {
        // Test error messages with special characters
        let special_messages = vec![
            "Error with newline\n",
            "Error with tab\t",
            "Error with quote\"",
            "Error with emoji 🚨",
            "Error with unicode: ñáéíóú",
            "Error with <html> tags </html>",
            "Error with \\ backslash",
        ];

        for msg in special_messages {
            let error = AuraError::Internal(msg.to_string());
            let display = format!("{}", error);
            assert!(display.contains(msg));
        }
    }
}
