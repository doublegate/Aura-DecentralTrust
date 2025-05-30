use aura_common::{
    AuraError, Result, AuraDid, CredentialSchema, SchemaRecord, BlockNumber,
};
use aura_crypto::hashing;
use crate::storage::Storage;

pub struct VcSchemaRegistry {
    storage: Storage,
}

impl VcSchemaRegistry {
    pub fn new(storage: Storage) -> Self {
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
            return Err(AuraError::AlreadyExists(format!("Schema {} already exists", schema_id)));
        }
        
        // Verify the schema author matches the issuer
        if &schema.author != issuer_did {
            return Err(AuraError::Validation("Schema author must match issuer DID".to_string()));
        }
        
        // Create schema record
        let schema_record = SchemaRecord {
            schema_id: schema_id.clone(),
            schema_content_hash: hashing::blake3_json(schema)?.to_vec(),
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