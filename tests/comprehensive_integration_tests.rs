//! Comprehensive integration tests for achieving 100% code coverage

use aura_common::{AuraDid, Timestamp, VerifiableCredential};
use aura_crypto::{EncryptionKey, KeyPair, Signature};
use std::collections::HashMap;

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_full_credential_lifecycle() {
        // Test the complete lifecycle of creating, signing, and verifying a credential
        
        // 1. Create issuer and subject DIDs
        let issuer_did = AuraDid::new("issuer123");
        let subject_did = AuraDid::new("subject456");
        
        // 2. Generate key pairs
        let issuer_keypair = KeyPair::generate();
        let subject_keypair = KeyPair::generate();
        
        // 3. Create claims
        let mut claims = HashMap::new();
        claims.insert("name".to_string(), serde_json::json!("Alice Smith"));
        claims.insert("degree".to_string(), serde_json::json!("Computer Science"));
        claims.insert("graduationDate".to_string(), serde_json::json!("2023-05-15"));
        
        // 4. Create credential
        let mut credential = VerifiableCredential::new(
            issuer_did.clone(),
            subject_did.clone(),
            vec!["UniversityDegreeCredential".to_string()],
            claims,
        );
        
        // 5. Sign the credential
        let credential_json = serde_json::to_string(&credential).unwrap();
        let signature = Signature::sign(&issuer_keypair, credential_json.as_bytes()).unwrap();
        
        // 6. Add proof to credential
        credential.proof = Some(aura_common::vc::Proof {
            proof_type: "Ed25519Signature2020".to_string(),
            created: Timestamp::now(),
            verification_method: format!("{}#key-1", issuer_did),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: hex::encode(signature.to_bytes()),
            challenge: None,
            domain: None,
        });
        
        // 7. Verify the credential signature
        let public_key = issuer_keypair.public_key();
        let sig_bytes = hex::decode(&credential.proof.as_ref().unwrap().proof_value).unwrap();
        let recovered_sig = Signature::from_bytes(&sig_bytes).unwrap();
        
        assert!(recovered_sig.verify(&public_key, credential_json.as_bytes()).is_ok());
        
        // 8. Encrypt the credential for storage
        let encryption_key = EncryptionKey::generate_encryption_key();
        let encrypted = aura_crypto::encrypt(&encryption_key, credential_json.as_bytes()).unwrap();
        
        // 9. Decrypt and verify
        let decrypted = aura_crypto::decrypt(&encryption_key, &encrypted).unwrap();
        let decrypted_str = String::from_utf8(decrypted).unwrap();
        assert_eq!(credential_json, decrypted_str);
    }

    #[test]
    fn test_did_operations() {
        // Test various DID operations
        
        // Valid DID creation
        let did1 = AuraDid::new("test123");
        assert_eq!(did1.0, "did:aura:test123");
        assert_eq!(did1.identifier(), "test123");
        
        // DID from string validation
        let did2 = AuraDid::from_string("did:aura:valid456".to_string()).unwrap();
        assert_eq!(did2.identifier(), "valid456");
        
        // Invalid DID format
        let invalid = AuraDid::from_string("invalid:format".to_string());
        assert!(invalid.is_err());
        
        // Empty DID
        let empty = AuraDid::from_string("".to_string());
        assert!(empty.is_err());
        
        // DID comparison
        let did3 = AuraDid::new("test123");
        assert_eq!(did1, did3);
        
        // DID in collections
        let mut did_set = std::collections::HashSet::new();
        did_set.insert(did1.clone());
        assert!(did_set.contains(&did1));
    }

    #[test]
    fn test_cryptographic_operations() {
        // Test all cryptographic operations
        
        // Key generation
        let key1 = KeyPair::generate();
        let key2 = KeyPair::generate();
        assert_ne!(key1.to_bytes(), key2.to_bytes());
        
        // Key serialization/deserialization
        let key_bytes = key1.to_bytes();
        let recovered_key = KeyPair::from_bytes(&key_bytes).unwrap();
        assert_eq!(key1.to_bytes(), recovered_key.to_bytes());
        
        // Signing and verification
        let message = b"Test message for signing";
        let signature = Signature::sign(&key1, message).unwrap();
        let public_key = key1.public_key();
        
        // Verify with correct key
        assert!(signature.verify(&public_key, message).is_ok());
        
        // Verify with wrong key should fail
        let wrong_key = key2.public_key();
        assert!(signature.verify(&wrong_key, message).is_err());
        
        // Verify with wrong message should fail
        assert!(signature.verify(&public_key, b"Different message").is_err());
        
        // Test hashing
        let hash1 = aura_crypto::sha256(b"test data");
        let hash2 = aura_crypto::sha256(b"test data");
        assert_eq!(hash1, hash2);
        
        let hash3 = aura_crypto::sha256(b"different data");
        assert_ne!(hash1, hash3);
        
        // Test Blake3 hashing
        let blake_hash1 = aura_crypto::blake3(b"test data");
        let blake_hash2 = aura_crypto::blake3(b"test data");
        assert_eq!(blake_hash1, blake_hash2);
    }

    #[test]
    fn test_encryption_decryption() {
        // Test encryption/decryption with various data sizes
        
        let key = EncryptionKey::generate_encryption_key();
        
        // Test small data
        let small_data = b"Small test data";
        let encrypted_small = aura_crypto::encrypt(&key, small_data).unwrap();
        let decrypted_small = aura_crypto::decrypt(&key, &encrypted_small).unwrap();
        assert_eq!(small_data.to_vec(), decrypted_small);
        
        // Test empty data
        let empty_data = b"";
        let encrypted_empty = aura_crypto::encrypt(&key, empty_data).unwrap();
        let decrypted_empty = aura_crypto::decrypt(&key, &encrypted_empty).unwrap();
        assert_eq!(empty_data.to_vec(), decrypted_empty);
        
        // Test large data
        let large_data = vec![0xAB; 1024 * 1024]; // 1MB
        let encrypted_large = aura_crypto::encrypt(&key, &large_data).unwrap();
        let decrypted_large = aura_crypto::decrypt(&key, &encrypted_large).unwrap();
        assert_eq!(large_data, decrypted_large);
        
        // Test JSON encryption
        let json_data = serde_json::json!({
            "name": "Test User",
            "age": 25,
            "active": true
        });
        let encrypted_json = aura_crypto::encrypt_json(&key, &json_data).unwrap();
        let decrypted_json: serde_json::Value = aura_crypto::decrypt_json(&key, &encrypted_json).unwrap();
        assert_eq!(json_data, decrypted_json);
        
        // Test decryption with wrong key
        let wrong_key = EncryptionKey::generate_encryption_key();
        let result = aura_crypto::decrypt(&wrong_key, &encrypted_small);
        assert!(result.is_err());
    }

    #[test]
    fn test_timestamp_operations() {
        use std::thread;
        use std::time::Duration;
        
        // Test timestamp creation
        let ts1 = Timestamp::now();
        thread::sleep(Duration::from_millis(10));
        let ts2 = Timestamp::now();
        
        assert!(ts2 > ts1);
        
        // Test unix timestamp conversion
        let unix_ts = 1609459200; // 2021-01-01 00:00:00 UTC
        let ts3 = Timestamp::from_unix(unix_ts);
        assert_eq!(ts3.as_unix(), unix_ts);
        
        // Test timestamp serialization
        let json = serde_json::to_string(&ts3).unwrap();
        let deserialized: Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(ts3, deserialized);
        
        // Test timestamp comparison
        assert!(ts2 > ts1);
        assert!(ts1 < ts2);
        assert_eq!(ts1, ts1);
        
        // Test with current time
        let now = Timestamp::now();
        let default = Timestamp::default();
        assert!((now.as_unix() - default.as_unix()).abs() < 2);
    }

    #[test]
    fn test_error_handling() {
        use aura_common::AuraError;
        
        // Test all error variants
        let errors = vec![
            AuraError::Did("Invalid DID".to_string()),
            AuraError::Vc("Invalid credential".to_string()),
            AuraError::Crypto("Crypto error".to_string()),
            AuraError::Ledger("Ledger error".to_string()),
            AuraError::Network("Network error".to_string()),
            AuraError::Storage("Storage error".to_string()),
            AuraError::Validation("Validation error".to_string()),
            AuraError::Serialization("Serialization error".to_string()),
            AuraError::InvalidSignature,
            AuraError::InvalidProof,
            AuraError::NotFound("Not found".to_string()),
            AuraError::AlreadyExists("Already exists".to_string()),
            AuraError::Unauthorized,
            AuraError::Internal("Internal error".to_string()),
        ];
        
        // Verify all errors have proper display
        for error in errors {
            let display = format!("{}", error);
            assert!(!display.is_empty());
            
            // Test error in Result type
            let result: Result<(), AuraError> = Err(error);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_verifiable_presentation() {
        // Test creating and manipulating verifiable presentations
        
        let holder_did = AuraDid::new("holder789");
        let issuer_did = AuraDid::new("issuer123");
        let subject_did = holder_did.clone();
        
        // Create multiple credentials
        let mut credentials = Vec::new();
        for i in 0..3 {
            let mut claims = HashMap::new();
            claims.insert("credentialNumber".to_string(), serde_json::json!(i));
            claims.insert("type".to_string(), serde_json::json!(format!("TestCredential{}", i)));
            
            let credential = VerifiableCredential::new(
                issuer_did.clone(),
                subject_did.clone(),
                vec![format!("TestCredential{}", i)],
                claims,
            );
            credentials.push(credential);
        }
        
        // Create presentation
        let presentation = aura_common::vc::VerifiablePresentation::new(
            holder_did.clone(),
            credentials.clone(),
        );
        
        assert_eq!(presentation.holder, holder_did);
        assert_eq!(presentation.verifiable_credential.len(), 3);
        assert_eq!(presentation.presentation_type, vec!["VerifiablePresentation"]);
        
        // Test serialization
        let json = serde_json::to_value(&presentation).unwrap();
        assert_eq!(json["holder"], "did:aura:holder789");
        assert_eq!(json["verifiableCredential"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_service_endpoints() {
        use aura_common::types::ServiceEndpoint;
        
        // Test various service endpoint types
        let endpoints = vec![
            ServiceEndpoint {
                id: "did:aura:test#service-1".to_string(),
                service_type: "MessagingService".to_string(),
                service_endpoint: "https://example.com/messaging".to_string(),
            },
            ServiceEndpoint {
                id: "did:aura:test#service-2".to_string(),
                service_type: "VerifiableCredentialService".to_string(),
                service_endpoint: "https://vc.example.com".to_string(),
            },
            ServiceEndpoint {
                id: "did:aura:test#service-3".to_string(),
                service_type: "LinkedDomains".to_string(),
                service_endpoint: "https://example.com".to_string(),
            },
        ];
        
        for endpoint in endpoints {
            // Test serialization
            let json = serde_json::to_value(&endpoint).unwrap();
            assert_eq!(json["id"], endpoint.id);
            assert_eq!(json["service_type"], endpoint.service_type);
            assert_eq!(json["service_endpoint"], endpoint.service_endpoint);
            
            // Test deserialization
            let deserialized: ServiceEndpoint = serde_json::from_value(json).unwrap();
            assert_eq!(deserialized.id, endpoint.id);
            assert_eq!(deserialized.service_type, endpoint.service_type);
            assert_eq!(deserialized.service_endpoint, endpoint.service_endpoint);
        }
    }

    #[test]
    fn test_complex_did_document() {
        use aura_common::did::{DidDocument, VerificationMethod, VerificationRelationship};
        use aura_common::types::ServiceEndpoint;
        
        let did = AuraDid::new("complex123");
        let mut doc = DidDocument::new(did.clone());
        
        // Add controller
        doc.controller = Some(AuraDid::new("controller456"));
        
        // Add verification methods
        let vm1 = VerificationMethod {
            id: format!("{}#key-1", did),
            controller: did.clone(),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            public_key_multibase: "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_string(),
        };
        
        let vm2 = VerificationMethod {
            id: format!("{}#key-2", did),
            controller: did.clone(),
            verification_type: "X25519KeyAgreementKey2020".to_string(),
            public_key_multibase: "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc".to_string(),
        };
        
        doc.add_verification_method(vm1.clone());
        doc.add_verification_method(vm2.clone());
        
        // Add relationships
        doc.authentication.push(VerificationRelationship::Reference(format!("{}#key-1", did)));
        doc.assertion_method.push(VerificationRelationship::Embedded(vm1.clone()));
        doc.key_agreement.push(VerificationRelationship::Reference(format!("{}#key-2", did)));
        
        // Add services
        let service1 = ServiceEndpoint {
            id: format!("{}#service-1", did),
            service_type: "MessagingService".to_string(),
            service_endpoint: "https://example.com/messaging".to_string(),
        };
        
        let service2 = ServiceEndpoint {
            id: format!("{}#service-2", did),
            service_type: "CredentialService".to_string(),
            service_endpoint: "https://example.com/credentials".to_string(),
        };
        
        doc.add_service(service1);
        doc.add_service(service2);
        
        // Verify document structure
        assert_eq!(doc.id, did);
        assert_eq!(doc.verification_method.len(), 2);
        assert_eq!(doc.service.len(), 2);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1);
        assert_eq!(doc.key_agreement.len(), 1);
        
        // Test JSON serialization
        let json = serde_json::to_value(&doc).unwrap();
        assert!(json["controller"].is_string());
        assert_eq!(json["verificationMethod"].as_array().unwrap().len(), 2);
        assert_eq!(json["service"].as_array().unwrap().len(), 2);
    }
}