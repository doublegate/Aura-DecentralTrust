use crate::storage::Storage;
use aura_common::{AuraDid, AuraError, BlockNumber, CredentialSchema, Result, SchemaRecord};
use aura_crypto::hashing;
use std::sync::Arc;

pub struct VcSchemaRegistry {
    storage: Arc<Storage>,
}

impl VcSchemaRegistry {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    pub fn register_schema(
        &mut self,
        schema: &CredentialSchema,
        issuer_did: &AuraDid,
        block_number: BlockNumber,
    ) -> Result<()> {
        let schema_id = &schema.id;

        // Check if schema already exists
        if self.get_schema(schema_id)?.is_some() {
            return Err(AuraError::AlreadyExists(format!(
                "Schema {schema_id} already exists"
            )));
        }

        // Verify the schema author matches the issuer
        if &schema.author != issuer_did {
            return Err(AuraError::Validation(
                "Schema author must match issuer DID".to_string(),
            ));
        }

        // Create schema record
        let schema_record = SchemaRecord {
            schema_id: schema_id.clone(),
            schema_content_hash: hashing::blake3_json(schema)
                .map_err(|e| AuraError::Crypto(e.to_string()))?
                .to_vec(),
            issuer_did: issuer_did.clone(),
            registered_at_block: block_number.0,
        };

        // Store the record
        self.storage.put_schema(schema_id, &schema_record)?;

        Ok(())
    }

    pub fn get_schema(&self, schema_id: &str) -> Result<Option<SchemaRecord>> {
        self.storage.get_schema(schema_id)
    }

    pub fn validate_schema_exists(&self, schema_id: &str) -> Result<bool> {
        Ok(self.get_schema(schema_id)?.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_common::{AuraDid, CredentialSchema, Timestamp};
    use tempfile::TempDir;

    fn setup_registry() -> (VcSchemaRegistry, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());
        let registry = VcSchemaRegistry::new(storage);
        (registry, temp_dir)
    }

    fn create_test_schema(id: &str, author: &str) -> CredentialSchema {
        CredentialSchema {
            id: id.to_string(),
            schema_type: "https://w3c.github.io/vc-data-model/#schemas".to_string(),
            name: "Test Schema".to_string(),
            version: "1.0.0".to_string(),
            author: AuraDid(format!("did:aura:{}", author)),
            created: Timestamp::now(),
            schema: serde_json::json!({
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "age": {"type": "number"}
                },
                "required": ["name"]
            }),
        }
    }

    #[test]
    fn test_register_schema() {
        let (mut registry, _temp_dir) = setup_registry();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        let schema = create_test_schema("schema123", "issuer123");
        
        let result = registry.register_schema(
            &schema,
            &issuer_did,
            BlockNumber(100),
        );
        
        assert!(result.is_ok());
        
        // Verify schema was registered
        let record = registry.get_schema("schema123").unwrap();
        assert!(record.is_some());
        
        let record = record.unwrap();
        assert_eq!(record.schema_id, "schema123");
        assert_eq!(record.issuer_did, issuer_did);
        assert_eq!(record.registered_at_block, 100);
        assert!(!record.schema_content_hash.is_empty());
    }

    #[test]
    fn test_register_duplicate_schema() {
        let (mut registry, _temp_dir) = setup_registry();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        let schema = create_test_schema("schema123", "issuer123");
        
        // Register first time
        registry.register_schema(
            &schema,
            &issuer_did,
            BlockNumber(100),
        ).unwrap();
        
        // Try to register again
        let result = registry.register_schema(
            &schema,
            &issuer_did,
            BlockNumber(101),
        );
        
        assert!(result.is_err());
        match result {
            Err(AuraError::AlreadyExists(_)) => {},
            _ => panic!("Expected AlreadyExists error"),
        }
    }

    #[test]
    fn test_register_schema_wrong_author() {
        let (mut registry, _temp_dir) = setup_registry();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        let schema = create_test_schema("schema123", "different_author");
        
        let result = registry.register_schema(
            &schema,
            &issuer_did,
            BlockNumber(100),
        );
        
        assert!(result.is_err());
        match result {
            Err(AuraError::Validation(msg)) => {
                assert!(msg.contains("Schema author must match issuer DID"));
            },
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_get_schema_nonexistent() {
        let (registry, _temp_dir) = setup_registry();
        
        let result = registry.get_schema("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_validate_schema_exists() {
        let (mut registry, _temp_dir) = setup_registry();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        let schema = create_test_schema("schema123", "issuer123");
        
        // Check non-existent schema
        assert!(!registry.validate_schema_exists("schema123").unwrap());
        
        // Register schema
        registry.register_schema(
            &schema,
            &issuer_did,
            BlockNumber(100),
        ).unwrap();
        
        // Check existing schema
        assert!(registry.validate_schema_exists("schema123").unwrap());
    }

    #[test]
    fn test_multiple_schemas() {
        let (mut registry, _temp_dir) = setup_registry();
        
        // Register multiple schemas from different issuers
        for i in 1..=5 {
            let issuer_did = AuraDid(format!("did:aura:issuer{}", i));
            let schema = create_test_schema(&format!("schema{}", i), &format!("issuer{}", i));
            
            registry.register_schema(
                &schema,
                &issuer_did,
                BlockNumber(100 + i),
            ).unwrap();
        }
        
        // Verify all schemas exist
        for i in 1..=5 {
            let schema_id = format!("schema{}", i);
            assert!(registry.validate_schema_exists(&schema_id).unwrap());
            
            let record = registry.get_schema(&schema_id).unwrap().unwrap();
            assert_eq!(record.issuer_did.0, format!("did:aura:issuer{}", i));
            assert_eq!(record.registered_at_block, 100 + i);
        }
    }

    #[test]
    fn test_schema_with_complex_structure() {
        let (mut registry, _temp_dir) = setup_registry();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        let mut schema = create_test_schema("complex_schema", "issuer123");
        schema.schema = serde_json::json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "personal": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "age": {"type": "integer", "minimum": 0, "maximum": 150},
                        "email": {"type": "string", "format": "email"}
                    },
                    "required": ["name", "email"]
                },
                "education": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "institution": {"type": "string"},
                            "degree": {"type": "string"},
                            "year": {"type": "integer"}
                        }
                    }
                },
                "skills": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1
                }
            },
            "required": ["personal"]
        });
        
        let result = registry.register_schema(
            &schema,
            &issuer_did,
            BlockNumber(100),
        );
        
        assert!(result.is_ok());
        
        let record = registry.get_schema("complex_schema").unwrap().unwrap();
        assert!(!record.schema_content_hash.is_empty());
    }

    #[test]
    fn test_schema_hash_consistency() {
        let (mut registry, _temp_dir) = setup_registry();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        let schema = create_test_schema("schema123", "issuer123");
        
        // Calculate expected hash
        let expected_hash = hashing::blake3_json(&schema).unwrap().to_vec();
        
        // Register schema
        registry.register_schema(
            &schema,
            &issuer_did,
            BlockNumber(100),
        ).unwrap();
        
        // Verify hash matches
        let record = registry.get_schema("schema123").unwrap().unwrap();
        assert_eq!(record.schema_content_hash, expected_hash);
    }

    #[test]
    fn test_schema_with_special_characters() {
        let (mut registry, _temp_dir) = setup_registry();
        let issuer_did = AuraDid("did:aura:issuer-123_456.789".to_string());
        
        let mut schema = create_test_schema("schema:test/v1.0#fragment", "issuer-123_456.789");
        schema.author = issuer_did.clone();
        
        let result = registry.register_schema(
            &schema,
            &issuer_did,
            BlockNumber(100),
        );
        
        assert!(result.is_ok());
        
        // Verify retrieval with special characters
        let record = registry.get_schema("schema:test/v1.0#fragment").unwrap();
        assert!(record.is_some());
        assert_eq!(record.unwrap().schema_id, "schema:test/v1.0#fragment");
    }

    #[test]
    fn test_schema_registration_at_different_blocks() {
        let (mut registry, _temp_dir) = setup_registry();
        
        let schemas = vec![
            ("schema1", "issuer1", 100),
            ("schema2", "issuer2", 200),
            ("schema3", "issuer3", 300),
        ];
        
        for (schema_id, issuer, block) in schemas {
            let issuer_did = AuraDid(format!("did:aura:{}", issuer));
            let schema = create_test_schema(schema_id, issuer);
            
            registry.register_schema(
                &schema,
                &issuer_did,
                BlockNumber(block),
            ).unwrap();
        }
        
        // Verify block numbers
        assert_eq!(registry.get_schema("schema1").unwrap().unwrap().registered_at_block, 100);
        assert_eq!(registry.get_schema("schema2").unwrap().unwrap().registered_at_block, 200);
        assert_eq!(registry.get_schema("schema3").unwrap().unwrap().registered_at_block, 300);
    }

    #[test]
    fn test_schema_with_empty_properties() {
        let (mut registry, _temp_dir) = setup_registry();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        let mut schema = create_test_schema("empty_schema", "issuer123");
        schema.schema = serde_json::json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {},
            "additionalProperties": false
        });
        
        let result = registry.register_schema(
            &schema,
            &issuer_did,
            BlockNumber(100),
        );
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_schema_persistence() {
        let (mut registry, _temp_dir) = setup_registry();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        let schema = create_test_schema("persist_test", "issuer123");
        
        // Register schema
        registry.register_schema(
            &schema,
            &issuer_did,
            BlockNumber(100),
        ).unwrap();
        
        // Retrieve multiple times to ensure persistence
        for _ in 0..5 {
            let record = registry.get_schema("persist_test").unwrap();
            assert!(record.is_some());
            let record = record.unwrap();
            assert_eq!(record.schema_id, "persist_test");
            assert_eq!(record.issuer_did, issuer_did);
        }
    }
}
