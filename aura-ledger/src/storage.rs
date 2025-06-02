use crate::Block;
use aura_common::BlockNumber;
use aura_common::{AuraDid, AuraError, DidDocument, DidRecord, Result, SchemaRecord};
use rocksdb::{Options, DB};
use std::path::Path;

const CF_BLOCKS: &str = "blocks";
const CF_DID_RECORDS: &str = "did_records";
const CF_DID_DOCUMENTS: &str = "did_documents";
const CF_SCHEMAS: &str = "schemas";
const CF_REVOCATION: &str = "revocation";
const CF_METADATA: &str = "metadata";
const CF_NONCES: &str = "nonces";
const CF_EXECUTED_TXS: &str = "executed_txs";

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
            CF_NONCES,
            CF_EXECUTED_TXS,
        ];

        let db =
            DB::open_cf(&opts, path, cf_names).map_err(|e| AuraError::Storage(e.to_string()))?;

        Ok(Self { db })
    }

    // Block operations
    pub fn put_block(&self, block: &Block) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_BLOCKS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        let key = block.header.block_number.0.to_be_bytes();
        let value =
            serde_json::to_vec(block).map_err(|e| AuraError::Serialization(e.to_string()))?;

        self.db
            .put_cf(cf, key, value)
            .map_err(|e| AuraError::Storage(e.to_string()))?;

        Ok(())
    }

    pub fn get_block(&self, block_number: &BlockNumber) -> Result<Option<Block>> {
        let cf = self
            .db
            .cf_handle(CF_BLOCKS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        let key = block_number.0.to_be_bytes();

        match self.db.get_cf(cf, key) {
            Ok(Some(data)) => {
                let block = serde_json::from_slice(&data)
                    .map_err(|e| AuraError::Serialization(e.to_string()))?;
                Ok(Some(block))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AuraError::Storage(e.to_string())),
        }
    }

    pub fn get_latest_block_number(&self) -> Result<Option<BlockNumber>> {
        let cf = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        match self.db.get_cf(cf, b"latest_block") {
            Ok(Some(data)) => {
                let bytes: [u8; 8] = data
                    .try_into()
                    .map_err(|_| AuraError::Storage("Invalid block number format".to_string()))?;
                Ok(Some(BlockNumber(u64::from_be_bytes(bytes))))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AuraError::Storage(e.to_string())),
        }
    }

    pub fn set_latest_block_number(&self, block_number: &BlockNumber) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        self.db
            .put_cf(cf, b"latest_block", block_number.0.to_be_bytes())
            .map_err(|e| AuraError::Storage(e.to_string()))?;

        Ok(())
    }

    pub fn store_block(&self, block: &Block) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_BLOCKS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        let key = block.header.block_number.0.to_be_bytes();
        let value =
            serde_json::to_vec(block).map_err(|e| AuraError::Serialization(e.to_string()))?;

        self.db
            .put_cf(cf, key, value)
            .map_err(|e| AuraError::Storage(e.to_string()))?;

        // Update latest block number
        self.set_latest_block_number(&block.header.block_number)?;

        Ok(())
    }

    // DID operations
    pub fn put_did_record(&self, did: &AuraDid, record: &DidRecord) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_DID_RECORDS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        let key = did.0.as_bytes();
        let value = bincode::encode_to_vec(record, bincode::config::standard())
            .map_err(|e| AuraError::Serialization(e.to_string()))?;

        self.db
            .put_cf(cf, key, value)
            .map_err(|e| AuraError::Storage(e.to_string()))?;

        Ok(())
    }

    pub fn get_did_record(&self, did: &AuraDid) -> Result<Option<DidRecord>> {
        let cf = self
            .db
            .cf_handle(CF_DID_RECORDS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        let key = did.0.as_bytes();

        match self.db.get_cf(cf, key) {
            Ok(Some(data)) => {
                let record = bincode::decode_from_slice(&data, bincode::config::standard())
                    .map(|(record, _)| record)
                    .map_err(|e| AuraError::Serialization(e.to_string()))?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AuraError::Storage(e.to_string())),
        }
    }

    pub fn put_did_document(&self, did: &AuraDid, document: &DidDocument) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_DID_DOCUMENTS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        let key = did.0.as_bytes();
        let value =
            serde_json::to_vec(document).map_err(|e| AuraError::Serialization(e.to_string()))?;

        self.db
            .put_cf(cf, key, value)
            .map_err(|e| AuraError::Storage(e.to_string()))?;

        Ok(())
    }

    pub fn get_did_document(&self, did: &AuraDid) -> Result<Option<DidDocument>> {
        let cf = self
            .db
            .cf_handle(CF_DID_DOCUMENTS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        let key = did.0.as_bytes();

        match self.db.get_cf(cf, key) {
            Ok(Some(data)) => {
                let document = serde_json::from_slice(&data)
                    .map_err(|e| AuraError::Serialization(e.to_string()))?;
                Ok(Some(document))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AuraError::Storage(e.to_string())),
        }
    }

    // Schema operations
    pub fn put_schema(&self, schema_id: &str, schema: &SchemaRecord) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_SCHEMAS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        let key = schema_id.as_bytes();
        let value = bincode::encode_to_vec(schema, bincode::config::standard())
            .map_err(|e| AuraError::Serialization(e.to_string()))?;

        self.db
            .put_cf(cf, key, value)
            .map_err(|e| AuraError::Storage(e.to_string()))?;

        Ok(())
    }

    pub fn get_schema(&self, schema_id: &str) -> Result<Option<SchemaRecord>> {
        let cf = self
            .db
            .cf_handle(CF_SCHEMAS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        let key = schema_id.as_bytes();

        match self.db.get_cf(cf, key) {
            Ok(Some(data)) => {
                let schema = bincode::decode_from_slice(&data, bincode::config::standard())
                    .map(|(schema, _)| schema)
                    .map_err(|e| AuraError::Serialization(e.to_string()))?;
                Ok(Some(schema))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AuraError::Storage(e.to_string())),
        }
    }

    // Nonce tracking for replay protection
    pub fn get_nonce(&self, account: &aura_crypto::PublicKey) -> Result<u64> {
        let cf = self
            .db
            .cf_handle(CF_NONCES)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        let key = account.to_bytes();

        match self.db.get_cf(cf, key) {
            Ok(Some(data)) => {
                let nonce = u64::from_be_bytes(
                    data.as_slice()
                        .try_into()
                        .map_err(|_| AuraError::Storage("Invalid nonce data".to_string()))?,
                );
                Ok(nonce)
            }
            Ok(None) => Ok(0), // First transaction for this account
            Err(e) => Err(AuraError::Storage(e.to_string())),
        }
    }

    pub fn increment_nonce(&self, account: &aura_crypto::PublicKey) -> Result<u64> {
        let cf = self
            .db
            .cf_handle(CF_NONCES)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        let key = account.to_bytes();
        let current_nonce = self.get_nonce(account)?;
        let new_nonce = current_nonce + 1;

        self.db
            .put_cf(cf, key, new_nonce.to_be_bytes())
            .map_err(|e| AuraError::Storage(e.to_string()))?;

        Ok(new_nonce)
    }

    // Track executed transactions to prevent replay
    pub fn is_transaction_executed(&self, tx_id: &aura_common::TransactionId) -> Result<bool> {
        let cf = self
            .db
            .cf_handle(CF_EXECUTED_TXS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        let key = tx_id.0.as_bytes();

        match self.db.get_cf(cf, key) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(AuraError::Storage(e.to_string())),
        }
    }

    pub fn mark_transaction_executed(
        &self,
        tx_id: &aura_common::TransactionId,
        block_number: BlockNumber,
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_EXECUTED_TXS)
            .ok_or_else(|| AuraError::Storage("Column family not found".to_string()))?;

        let key = tx_id.0.as_bytes();
        let value = block_number.0.to_be_bytes();

        self.db
            .put_cf(cf, key, value)
            .map_err(|e| AuraError::Storage(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_common::AuraDid;
    use aura_crypto::KeyPair;
    use tempfile::TempDir;

    fn setup_storage() -> (Storage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new(temp_dir.path()).unwrap();
        (storage, temp_dir)
    }

    fn create_test_block(block_number: u64) -> Block {
        let keypair = KeyPair::generate().unwrap();
        Block::new(
            BlockNumber(block_number),
            [0u8; 32],
            vec![],
            keypair.public_key(),
        )
    }

    fn create_test_did_record(did: &str) -> (AuraDid, DidRecord) {
        let did_id = AuraDid(format!("did:aura:{did}"));
        let keypair = KeyPair::generate().unwrap();
        let record = DidRecord {
            did_id: did_id.clone(),
            did_document_hash: vec![1, 2, 3, 4],
            owner_public_key: keypair.public_key().to_bytes().to_vec(),
            last_updated_block: 1,
            active: true,
        };
        (did_id, record)
    }

    fn create_test_did_document(did: &str) -> (AuraDid, DidDocument) {
        let did_id = AuraDid(format!("did:aura:{did}"));
        let document = DidDocument::new(did_id.clone());
        (did_id, document)
    }

    fn create_test_schema_record(schema_id: &str) -> SchemaRecord {
        SchemaRecord {
            schema_id: schema_id.to_string(),
            schema_content_hash: vec![5, 6, 7, 8],
            issuer_did: AuraDid("did:aura:issuer".to_string()),
            registered_at_block: 100,
        }
    }

    #[test]
    fn test_storage_new() {
        let (_storage, _temp_dir) = setup_storage();
        // Storage created successfully
    }

    #[test]
    fn test_put_get_block() {
        let (storage, _temp_dir) = setup_storage();
        let block = create_test_block(42);

        // Put block
        storage.put_block(&block).unwrap();

        // Get block
        let retrieved = storage.get_block(&BlockNumber(42)).unwrap();
        assert!(retrieved.is_some());

        let retrieved_block = retrieved.unwrap();
        assert_eq!(retrieved_block.header.block_number.0, 42);
        assert_eq!(retrieved_block.header.previous_hash, [0u8; 32]);
    }

    #[test]
    fn test_get_nonexistent_block() {
        let (storage, _temp_dir) = setup_storage();

        let result = storage.get_block(&BlockNumber(999)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_latest_block_number() {
        let (storage, _temp_dir) = setup_storage();

        // Initially no latest block
        let latest = storage.get_latest_block_number().unwrap();
        assert!(latest.is_none());

        // Set latest block
        storage.set_latest_block_number(&BlockNumber(100)).unwrap();

        // Get latest block
        let latest = storage.get_latest_block_number().unwrap();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().0, 100);

        // Update latest block
        storage.set_latest_block_number(&BlockNumber(200)).unwrap();
        let latest = storage.get_latest_block_number().unwrap();
        assert_eq!(latest.unwrap().0, 200);
    }

    #[test]
    fn test_put_get_did_record() {
        let (storage, _temp_dir) = setup_storage();
        let (did, record) = create_test_did_record("test123");

        // Put record
        storage.put_did_record(&did, &record).unwrap();

        // Get record
        let retrieved = storage.get_did_record(&did).unwrap();
        assert!(retrieved.is_some());

        let retrieved_record = retrieved.unwrap();
        assert_eq!(retrieved_record.did_id, did);
        assert_eq!(retrieved_record.did_document_hash, vec![1, 2, 3, 4]);
        assert!(retrieved_record.active);
    }

    #[test]
    fn test_get_nonexistent_did_record() {
        let (storage, _temp_dir) = setup_storage();
        let did = AuraDid("did:aura:nonexistent".to_string());

        let result = storage.get_did_record(&did).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_put_get_did_document() {
        let (storage, _temp_dir) = setup_storage();
        let (did, document) = create_test_did_document("test123");

        // Put document
        storage.put_did_document(&did, &document).unwrap();

        // Get document
        let retrieved = storage.get_did_document(&did).unwrap();
        assert!(retrieved.is_some());

        let retrieved_doc = retrieved.unwrap();
        assert_eq!(retrieved_doc.id, did);
    }

    #[test]
    fn test_get_nonexistent_did_document() {
        let (storage, _temp_dir) = setup_storage();
        let did = AuraDid("did:aura:nonexistent".to_string());

        let result = storage.get_did_document(&did).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_put_get_schema() {
        let (storage, _temp_dir) = setup_storage();
        let schema_id = "schema123";
        let schema = create_test_schema_record(schema_id);

        // Put schema
        storage.put_schema(schema_id, &schema).unwrap();

        // Get schema
        let retrieved = storage.get_schema(schema_id).unwrap();
        assert!(retrieved.is_some());

        let retrieved_schema = retrieved.unwrap();
        assert_eq!(retrieved_schema.schema_id, schema_id);
        assert_eq!(retrieved_schema.schema_content_hash, vec![5, 6, 7, 8]);
        assert_eq!(retrieved_schema.registered_at_block, 100);
    }

    #[test]
    fn test_get_nonexistent_schema() {
        let (storage, _temp_dir) = setup_storage();

        let result = storage.get_schema("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_nonce_operations() {
        let (storage, _temp_dir) = setup_storage();
        let keypair = KeyPair::generate().unwrap();
        let account = &keypair.public_key();

        // Initial nonce should be 0
        let nonce = storage.get_nonce(account).unwrap();
        assert_eq!(nonce, 0);

        // Increment nonce
        let new_nonce = storage.increment_nonce(account).unwrap();
        assert_eq!(new_nonce, 1);

        // Get nonce again
        let nonce = storage.get_nonce(account).unwrap();
        assert_eq!(nonce, 1);

        // Increment again
        let new_nonce = storage.increment_nonce(account).unwrap();
        assert_eq!(new_nonce, 2);
    }

    #[test]
    fn test_multiple_account_nonces() {
        let (storage, _temp_dir) = setup_storage();
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();

        // Increment nonce for account1
        storage.increment_nonce(&keypair1.public_key()).unwrap();
        storage.increment_nonce(&keypair1.public_key()).unwrap();

        // Increment nonce for account2
        storage.increment_nonce(&keypair2.public_key()).unwrap();

        // Check nonces are tracked separately
        assert_eq!(storage.get_nonce(&keypair1.public_key()).unwrap(), 2);
        assert_eq!(storage.get_nonce(&keypair2.public_key()).unwrap(), 1);
    }

    #[test]
    fn test_transaction_execution_tracking() {
        let (storage, _temp_dir) = setup_storage();
        let tx_id = aura_common::TransactionId("tx123".to_string());

        // Initially not executed
        assert!(!storage.is_transaction_executed(&tx_id).unwrap());

        // Mark as executed
        storage
            .mark_transaction_executed(&tx_id, BlockNumber(100))
            .unwrap();

        // Now it should be executed
        assert!(storage.is_transaction_executed(&tx_id).unwrap());
    }

    #[test]
    fn test_multiple_transaction_tracking() {
        let (storage, _temp_dir) = setup_storage();
        let tx1 = aura_common::TransactionId("tx1".to_string());
        let tx2 = aura_common::TransactionId("tx2".to_string());
        let tx3 = aura_common::TransactionId("tx3".to_string());

        // Mark tx1 and tx2 as executed
        storage
            .mark_transaction_executed(&tx1, BlockNumber(100))
            .unwrap();
        storage
            .mark_transaction_executed(&tx2, BlockNumber(101))
            .unwrap();

        // Check execution status
        assert!(storage.is_transaction_executed(&tx1).unwrap());
        assert!(storage.is_transaction_executed(&tx2).unwrap());
        assert!(!storage.is_transaction_executed(&tx3).unwrap());
    }

    #[test]
    fn test_block_persistence() {
        let (storage, _temp_dir) = setup_storage();

        // Store multiple blocks
        for i in 0..10 {
            let block = create_test_block(i);
            storage.put_block(&block).unwrap();
        }

        // Retrieve all blocks
        for i in 0..10 {
            let block = storage.get_block(&BlockNumber(i)).unwrap();
            assert!(block.is_some());
            assert_eq!(block.unwrap().header.block_number.0, i);
        }
    }

    #[test]
    fn test_did_update_persistence() {
        let (storage, _temp_dir) = setup_storage();
        let (did, mut record) = create_test_did_record("test123");

        // Store initial record
        storage.put_did_record(&did, &record).unwrap();

        // Update record
        record.last_updated_block = 50;
        record.did_document_hash = vec![9, 10, 11, 12];
        storage.put_did_record(&did, &record).unwrap();

        // Retrieve updated record
        let retrieved = storage.get_did_record(&did).unwrap().unwrap();
        assert_eq!(retrieved.last_updated_block, 50);
        assert_eq!(retrieved.did_document_hash, vec![9, 10, 11, 12]);
    }

    #[test]
    fn test_schema_update() {
        let (storage, _temp_dir) = setup_storage();
        let schema_id = "schema123";
        let mut schema = create_test_schema_record(schema_id);

        // Store initial schema
        storage.put_schema(schema_id, &schema).unwrap();

        // Update schema
        schema.registered_at_block = 200;
        schema.schema_content_hash = vec![13, 14, 15, 16];
        storage.put_schema(schema_id, &schema).unwrap();

        // Retrieve updated schema
        let retrieved = storage.get_schema(schema_id).unwrap().unwrap();
        assert_eq!(retrieved.registered_at_block, 200);
        assert_eq!(retrieved.schema_content_hash, vec![13, 14, 15, 16]);
    }

    #[test]
    fn test_storage_with_special_characters() {
        let (storage, _temp_dir) = setup_storage();

        // Test DID with special characters
        let special_did = AuraDid("did:aura:test-123_456.789".to_string());
        let (_, record) = create_test_did_record("dummy");
        let mut special_record = record;
        special_record.did_id = special_did.clone();

        storage
            .put_did_record(&special_did, &special_record)
            .unwrap();
        let retrieved = storage.get_did_record(&special_did).unwrap();
        assert!(retrieved.is_some());

        // Test schema ID with special characters
        let special_schema_id = "schema:test/v1.0#fragment";
        let schema = create_test_schema_record(special_schema_id);

        storage.put_schema(special_schema_id, &schema).unwrap();
        let retrieved = storage.get_schema(special_schema_id).unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_transaction_id_with_uuid() {
        let (storage, _temp_dir) = setup_storage();
        let tx_id = aura_common::TransactionId(uuid::Uuid::new_v4().to_string());

        assert!(!storage.is_transaction_executed(&tx_id).unwrap());
        storage
            .mark_transaction_executed(&tx_id, BlockNumber(42))
            .unwrap();
        assert!(storage.is_transaction_executed(&tx_id).unwrap());
    }
}
