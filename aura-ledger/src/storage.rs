use std::path::Path;
use rocksdb::{DB, Options, WriteBatch};
use serde::{Deserialize, Serialize};
use aura_common::{AuraError, Result, AuraDid, DidDocument, DidRecord, SchemaRecord};
use crate::{Block, BlockNumber};

const CF_BLOCKS: &str = "blocks";
const CF_DID_RECORDS: &str = "did_records";
const CF_DID_DOCUMENTS: &str = "did_documents";
const CF_SCHEMAS: &str = "schemas";
const CF_REVOCATION: &str = "revocation";
const CF_METADATA: &str = "metadata";

pub struct Storage {
    pub(crate) db: DB,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        
        let cf_names = vec![
            CF_BLOCKS,
            CF_DID_RECORDS,
            CF_DID_DOCUMENTS,
            CF_SCHEMAS,
            CF_REVOCATION,
            CF_METADATA,
        ];
        
        let db = DB::open_cf(&opts, path, cf_names)
            .map_err(|e| AuraError::Storage(e.to_string()))?;
        
        Ok(Self { db })
    }
    
    // Block operations
    pub fn put_block(&self, block: &Block) -> Result<()> {
        let cf = self.db.cf_handle(CF_BLOCKS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;
        
        let key = block.header.block_number.0.to_be_bytes();
        let value = bincode::serialize(block)
            .map_err(|e| AuraError::Serialization(serde_json::Error::custom(e)))?;
        
        self.db.put_cf(cf, key, value)
            .map_err(|e| AuraError::Storage(e.to_string()))?;
        
        Ok(())
    }
    
    pub fn get_block(&self, block_number: &BlockNumber) -> Result<Option<Block>> {
        let cf = self.db.cf_handle(CF_BLOCKS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;
        
        let key = block_number.0.to_be_bytes();
        
        match self.db.get_cf(cf, key) {
            Ok(Some(data)) => {
                let block = bincode::deserialize(&data)
                    .map_err(|e| AuraError::Serialization(serde_json::Error::custom(e)))?;
                Ok(Some(block))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AuraError::Storage(e.to_string())),
        }
    }
    
    pub fn get_latest_block_number(&self) -> Result<Option<BlockNumber>> {
        let cf = self.db.cf_handle(CF_METADATA)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;
        
        match self.db.get_cf(cf, b"latest_block") {
            Ok(Some(data)) => {
                let bytes: [u8; 8] = data.try_into()
                    .map_err(|_| AuraError::Storage("Invalid block number format".to_string()))?;
                Ok(Some(BlockNumber(u64::from_be_bytes(bytes))))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AuraError::Storage(e.to_string())),
        }
    }
    
    pub fn set_latest_block_number(&self, block_number: &BlockNumber) -> Result<()> {
        let cf = self.db.cf_handle(CF_METADATA)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;
        
        self.db.put_cf(cf, b"latest_block", block_number.0.to_be_bytes())
            .map_err(|e| AuraError::Storage(e.to_string()))?;
        
        Ok(())
    }
    
    // DID operations
    pub fn put_did_record(&self, did: &AuraDid, record: &DidRecord) -> Result<()> {
        let cf = self.db.cf_handle(CF_DID_RECORDS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;
        
        let key = did.0.as_bytes();
        let value = bincode::serialize(record)
            .map_err(|e| AuraError::Serialization(serde_json::Error::custom(e)))?;
        
        self.db.put_cf(cf, key, value)
            .map_err(|e| AuraError::Storage(e.to_string()))?;
        
        Ok(())
    }
    
    pub fn get_did_record(&self, did: &AuraDid) -> Result<Option<DidRecord>> {
        let cf = self.db.cf_handle(CF_DID_RECORDS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;
        
        let key = did.0.as_bytes();
        
        match self.db.get_cf(cf, key) {
            Ok(Some(data)) => {
                let record = bincode::deserialize(&data)
                    .map_err(|e| AuraError::Serialization(serde_json::Error::custom(e)))?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AuraError::Storage(e.to_string())),
        }
    }
    
    pub fn put_did_document(&self, did: &AuraDid, document: &DidDocument) -> Result<()> {
        let cf = self.db.cf_handle(CF_DID_DOCUMENTS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;
        
        let key = did.0.as_bytes();
        let value = serde_json::to_vec(document)?;
        
        self.db.put_cf(cf, key, value)
            .map_err(|e| AuraError::Storage(e.to_string()))?;
        
        Ok(())
    }
    
    pub fn get_did_document(&self, did: &AuraDid) -> Result<Option<DidDocument>> {
        let cf = self.db.cf_handle(CF_DID_DOCUMENTS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;
        
        let key = did.0.as_bytes();
        
        match self.db.get_cf(cf, key) {
            Ok(Some(data)) => {
                let document = serde_json::from_slice(&data)?;
                Ok(Some(document))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AuraError::Storage(e.to_string())),
        }
    }
    
    // Schema operations
    pub fn put_schema(&self, schema_id: &str, schema: &SchemaRecord) -> Result<()> {
        let cf = self.db.cf_handle(CF_SCHEMAS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;
        
        let key = schema_id.as_bytes();
        let value = bincode::serialize(schema)
            .map_err(|e| AuraError::Serialization(serde_json::Error::custom(e)))?;
        
        self.db.put_cf(cf, key, value)
            .map_err(|e| AuraError::Storage(e.to_string()))?;
        
        Ok(())
    }
    
    pub fn get_schema(&self, schema_id: &str) -> Result<Option<SchemaRecord>> {
        let cf = self.db.cf_handle(CF_SCHEMAS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;
        
        let key = schema_id.as_bytes();
        
        match self.db.get_cf(cf, key) {
            Ok(Some(data)) => {
                let schema = bincode::deserialize(&data)
                    .map_err(|e| AuraError::Serialization(serde_json::Error::custom(e)))?;
                Ok(Some(schema))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AuraError::Storage(e.to_string())),
        }
    }
}