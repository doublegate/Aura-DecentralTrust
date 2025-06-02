use crate::storage::Storage;
use crate::transaction::Transaction;
use aura_common::{AuraError, BlockNumber, Result, Timestamp};
use aura_crypto::{hashing, PublicKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub block_number: BlockNumber,
    pub previous_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: Timestamp,
    pub validator: PublicKey,
    pub signature: Vec<u8>,
}

impl Block {
    pub fn new(
        block_number: BlockNumber,
        previous_hash: [u8; 32],
        transactions: Vec<Transaction>,
        validator: PublicKey,
    ) -> Self {
        let merkle_root = Self::calculate_merkle_root(&transactions);

        Self {
            header: BlockHeader {
                block_number,
                previous_hash,
                merkle_root,
                timestamp: Timestamp::now(),
                validator,
                signature: Vec::new(),
            },
            transactions,
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        hashing::blake3_json(&self.header).unwrap_or([0u8; 32])
    }

    pub fn calculate_merkle_root(transactions: &[Transaction]) -> [u8; 32] {
        if transactions.is_empty() {
            return [0u8; 32];
        }

        let mut hashes: Vec<[u8; 32]> = transactions
            .iter()
            .map(|tx| hashing::blake3_json(tx).unwrap())
            .collect();

        while hashes.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in hashes.chunks(2) {
                let hash = if chunk.len() == 2 {
                    let mut combined = Vec::new();
                    combined.extend_from_slice(&chunk[0]);
                    combined.extend_from_slice(&chunk[1]);
                    hashing::blake3(&combined)
                } else {
                    chunk[0]
                };
                next_level.push(hash);
            }

            hashes = next_level;
        }

        hashes[0]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisBlock {
    pub timestamp: Timestamp,
    pub validators: Vec<PublicKey>,
    pub chain_config: ChainConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub chain_id: String,
    pub block_time: u64, // in seconds
    pub max_transactions_per_block: usize,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            chain_id: "aura-mainnet".to_string(),
            block_time: 5,
            max_transactions_per_block: 1000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Transaction, TransactionType};
    use aura_common::{AuraDid, DidDocument};
    use aura_crypto::KeyPair;
    use aura_crypto::Signature;

    fn create_test_transaction() -> Transaction {
        let keypair = KeyPair::generate().unwrap();
        let did_doc = DidDocument::new(AuraDid("did:aura:123".to_string()));

        Transaction {
            id: aura_common::TransactionId("test-tx-123".to_string()),
            transaction_type: TransactionType::RegisterDid {
                did_document: did_doc,
            },
            timestamp: Timestamp::now(),
            sender: keypair.public_key(),
            signature: Signature(vec![0; 64]),
            nonce: 1,
            chain_id: "test-chain".to_string(),
            expires_at: None,
        }
    }

    #[test]
    fn test_block_new() {
        let keypair = KeyPair::generate().unwrap();
        let validator = keypair.public_key();
        let previous_hash = [1u8; 32];
        let transactions = vec![create_test_transaction()];

        let block = Block::new(
            BlockNumber(1),
            previous_hash,
            transactions.clone(),
            validator.clone(),
        );

        assert_eq!(block.header.block_number.0, 1);
        assert_eq!(block.header.previous_hash, previous_hash);
        assert_eq!(block.header.validator, validator);
        assert_eq!(block.transactions.len(), 1);
        assert!(block.header.signature.is_empty());
        assert_ne!(block.header.merkle_root, [0u8; 32]);
    }

    #[test]
    fn test_block_hash() {
        let keypair = KeyPair::generate().unwrap();
        let block = Block::new(BlockNumber(1), [0u8; 32], vec![], keypair.public_key());

        let hash1 = block.hash();
        let hash2 = block.hash();

        // Hash should be deterministic
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 32]);
    }

    #[test]
    fn test_calculate_merkle_root_empty() {
        let merkle_root = Block::calculate_merkle_root(&[]);
        assert_eq!(merkle_root, [0u8; 32]);
    }

    #[test]
    fn test_calculate_merkle_root_single_transaction() {
        let tx = create_test_transaction();
        let transactions = vec![tx.clone()];

        let merkle_root = Block::calculate_merkle_root(&transactions);
        let expected = hashing::blake3_json(&tx).unwrap();

        assert_eq!(merkle_root, expected);
    }

    #[test]
    fn test_calculate_merkle_root_multiple_transactions() {
        let transactions = vec![
            create_test_transaction(),
            create_test_transaction(),
            create_test_transaction(),
        ];

        let merkle_root = Block::calculate_merkle_root(&transactions);

        // Should not be empty
        assert_ne!(merkle_root, [0u8; 32]);

        // Should be deterministic
        let merkle_root2 = Block::calculate_merkle_root(&transactions);
        assert_eq!(merkle_root, merkle_root2);
    }

    #[test]
    fn test_calculate_merkle_root_power_of_two() {
        let transactions = vec![
            create_test_transaction(),
            create_test_transaction(),
            create_test_transaction(),
            create_test_transaction(),
        ];

        let merkle_root = Block::calculate_merkle_root(&transactions);
        assert_ne!(merkle_root, [0u8; 32]);
    }

    #[test]
    fn test_calculate_merkle_root_odd_number() {
        let transactions = vec![
            create_test_transaction(),
            create_test_transaction(),
            create_test_transaction(),
            create_test_transaction(),
            create_test_transaction(),
        ];

        let merkle_root = Block::calculate_merkle_root(&transactions);
        assert_ne!(merkle_root, [0u8; 32]);
    }

    #[test]
    fn test_block_header_fields() {
        let keypair = KeyPair::generate().unwrap();
        let validator = keypair.public_key();
        let previous_hash = [42u8; 32];

        let block = Block::new(BlockNumber(100), previous_hash, vec![], validator.clone());

        assert_eq!(block.header.block_number.0, 100);
        assert_eq!(block.header.previous_hash, previous_hash);
        assert_eq!(block.header.validator, validator);
        assert!(block.header.timestamp.as_unix() > 0);
    }

    #[test]
    fn test_genesis_block() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();
        let validators = vec![
            keypair1.public_key().clone(),
            &keypair2.public_key().clone(),
        ];

        let genesis = GenesisBlock {
            timestamp: Timestamp::now(),
            validators: validators.clone(),
            chain_config: ChainConfig::default(),
        };

        assert_eq!(genesis.validators.len(), 2);
        assert_eq!(genesis.validators, validators);
        assert_eq!(genesis.chain_config.chain_id, "aura-mainnet");
    }

    #[test]
    fn test_chain_config_default() {
        let config = ChainConfig::default();

        assert_eq!(config.chain_id, "aura-mainnet");
        assert_eq!(config.block_time, 5);
        assert_eq!(config.max_transactions_per_block, 1000);
    }

    #[test]
    fn test_chain_config_custom() {
        let config = ChainConfig {
            chain_id: "aura-testnet".to_string(),
            block_time: 10,
            max_transactions_per_block: 500,
        };

        assert_eq!(config.chain_id, "aura-testnet");
        assert_eq!(config.block_time, 10);
        assert_eq!(config.max_transactions_per_block, 500);
    }

    #[test]
    fn test_block_serialization() {
        let keypair = KeyPair::generate().unwrap();
        let block = Block::new(
            BlockNumber(1),
            [0u8; 32],
            vec![create_test_transaction()],
            keypair.public_key(),
        );

        // Test JSON serialization
        let json = serde_json::to_string(&block).unwrap();
        let deserialized: Block = serde_json::from_str(&json).unwrap();

        assert_eq!(block.header.block_number, deserialized.header.block_number);
        assert_eq!(
            block.header.previous_hash,
            deserialized.header.previous_hash
        );
        assert_eq!(block.transactions.len(), deserialized.transactions.len());
    }

    #[test]
    fn test_genesis_block_serialization() {
        let keypair = KeyPair::generate().unwrap();
        let genesis = GenesisBlock {
            timestamp: Timestamp::now(),
            validators: vec![keypair.public_key()],
            chain_config: ChainConfig::default(),
        };

        let json = serde_json::to_string(&genesis).unwrap();
        let deserialized: GenesisBlock = serde_json::from_str(&json).unwrap();

        assert_eq!(genesis.validators.len(), deserialized.validators.len());
        assert_eq!(
            genesis.chain_config.chain_id,
            deserialized.chain_config.chain_id
        );
    }

    #[test]
    fn test_block_with_signature() {
        let keypair = KeyPair::generate().unwrap();
        let mut block = Block::new(BlockNumber(1), [0u8; 32], vec![], keypair.public_key());

        // Add a signature
        block.header.signature = vec![1, 2, 3, 4, 5];

        assert_eq!(block.header.signature, vec![1, 2, 3, 4, 5]);

        // Hash should still work
        let hash = block.hash();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_merkle_root_consistency() {
        let tx1 = create_test_transaction();
        let tx2 = create_test_transaction();

        // Same transactions in same order should produce same merkle root
        let root1 = Block::calculate_merkle_root(&vec![tx1.clone(), tx2.clone()]);
        let root2 = Block::calculate_merkle_root(&vec![tx1.clone(), tx2.clone()]);
        assert_eq!(root1, root2);

        // Different order should produce different merkle root
        let root3 = Block::calculate_merkle_root(&vec![tx2.clone(), tx1.clone()]);
        assert_ne!(root1, root3);
    }

    #[test]
    fn test_block_timestamp() {
        let keypair = KeyPair::generate().unwrap();
        let block1 = Block::new(BlockNumber(1), [0u8; 32], vec![], keypair.public_key());

        // Small delay to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(10));

        let block2 = Block::new(BlockNumber(2), [0u8; 32], vec![], keypair.public_key());

        // Timestamps should be different
        assert!(block2.header.timestamp.0 > block1.header.timestamp.0);
    }

    #[test]
    fn test_different_validators_different_blocks() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();

        let block1 = Block::new(
            BlockNumber(1),
            [0u8; 32],
            vec![],
            keypair1.public_key().clone(),
        );
        let block2 = Block::new(
            BlockNumber(1),
            [0u8; 32],
            vec![],
            &keypair2.public_key().clone(),
        );

        // Same block number and previous hash but different validators
        assert_ne!(block1.hash(), block2.hash());
    }

    // Additional edge case tests for enhanced blockchain security

    #[test]
    fn test_block_with_max_transactions() {
        let keypair = KeyPair::generate().unwrap();
        let max_txs = 1000;

        // Create max number of transactions
        let transactions: Vec<Transaction> =
            (0..max_txs).map(|_| create_test_transaction()).collect();

        let block = Block::new(
            BlockNumber(1),
            [0u8; 32],
            transactions.clone(),
            keypair.public_key(),
        );

        assert_eq!(block.transactions.len(), max_txs);
        assert_ne!(block.header.merkle_root, [0u8; 32]);

        // Verify block can be hashed without issues
        let hash = block.hash();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_block_size_limits() {
        let keypair = KeyPair::generate().unwrap();

        // Create a transaction with large data
        let mut large_tx = create_test_transaction();
        if let TransactionType::RegisterDid {
            ref mut did_document,
        } = large_tx.transaction_type
        {
            // Add large metadata to DID document
            for i in 0..100 {
                did_document
                    .authentication
                    .push(aura_common::VerificationRelationship::Embedded(
                        aura_common::VerificationMethod {
                            id: format!("{}#key-{}", did_document.id, i),
                            controller: did_document.id.clone(),
                            verification_type: "Ed25519VerificationKey2020".to_string(),
                            public_key_multibase: Some("z".repeat(1000)), // Large key data
                            public_key_jwk: None,
                            public_key_base58: None,
                        },
                    ));
            }
        }

        let block = Block::new(
            BlockNumber(1),
            [0u8; 32],
            vec![large_tx],
            keypair.public_key(),
        );

        // Should still be able to calculate merkle root and hash
        assert_ne!(block.header.merkle_root, [0u8; 32]);
        assert_ne!(block.hash(), [0u8; 32]);
    }

    #[test]
    fn test_merkle_root_collision_resistance() {
        // Test that different transaction sets produce different merkle roots
        let tx1 = create_test_transaction();
        let tx2 = create_test_transaction();
        let tx3 = create_test_transaction();

        let root1 = Block::calculate_merkle_root(&vec![tx1.clone()]);
        let root2 = Block::calculate_merkle_root(&vec![tx2.clone()]);
        let root3 = Block::calculate_merkle_root(&vec![tx1.clone(), tx2.clone()]);
        let root4 = Block::calculate_merkle_root(&vec![tx2.clone(), tx1.clone()]);
        let root5 = Block::calculate_merkle_root(&vec![tx1.clone(), tx2.clone(), tx3.clone()]);

        // All roots should be different
        assert_ne!(root1, root2);
        assert_ne!(root1, root3);
        assert_ne!(root3, root4); // Order matters
        assert_ne!(root3, root5);
    }

    #[test]
    fn test_genesis_block_validation() {
        // Test various invalid genesis block configurations
        let keypair = KeyPair::generate().unwrap();

        // Empty validators
        let genesis_empty = GenesisBlock {
            timestamp: Timestamp::now(),
            validators: vec![],
            chain_config: ChainConfig::default(),
        };
        assert_eq!(genesis_empty.validators.len(), 0);

        // Many validators
        let many_validators: Vec<PublicKey> = (0..100)
            .map(|_| KeyPair::generate().unwrap().public_key().clone())
            .collect();

        let genesis_many = GenesisBlock {
            timestamp: Timestamp::now(),
            validators: many_validators.clone(),
            chain_config: ChainConfig::default(),
        };
        assert_eq!(genesis_many.validators.len(), 100);

        // Invalid chain config
        let invalid_config = ChainConfig {
            chain_id: "".to_string(),      // Empty chain ID
            block_time: 0,                 // Zero block time
            max_transactions_per_block: 0, // Zero max transactions
        };

        let genesis_invalid = GenesisBlock {
            timestamp: Timestamp::now(),
            validators: vec![keypair.public_key()],
            chain_config: invalid_config,
        };

        // Should still serialize/deserialize
        let json = serde_json::to_string(&genesis_invalid).unwrap();
        let _decoded: GenesisBlock = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_block_hash_stability() {
        let keypair = KeyPair::generate().unwrap();
        let tx = create_test_transaction();
        let block = Block::new(BlockNumber(1), [0u8; 32], vec![tx], keypair.public_key());

        // Hash should be stable across multiple calls
        let hashes: Vec<[u8; 32]> = (0..100).map(|_| block.hash()).collect();

        // All hashes should be identical
        for hash in &hashes[1..] {
            assert_eq!(hash, &hashes[0]);
        }
    }

    #[test]
    fn test_concurrent_merkle_root_calculation() {
        use std::sync::Arc;
        use std::thread;

        let transactions: Vec<Transaction> = (0..100).map(|_| create_test_transaction()).collect();

        let tx_arc = Arc::new(transactions);
        let mut handles = vec![];

        // Calculate merkle root in multiple threads
        for _ in 0..10 {
            let tx_clone = Arc::clone(&tx_arc);
            let handle = thread::spawn(move || Block::calculate_merkle_root(&tx_clone));
            handles.push(handle);
        }

        // Collect all results
        let results: Vec<[u8; 32]> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All results should be identical
        for result in &results[1..] {
            assert_eq!(result, &results[0]);
        }
    }

    #[test]
    fn test_block_with_future_timestamp() {
        let keypair = KeyPair::generate().unwrap();
        let mut block = Block::new(BlockNumber(1), [0u8; 32], vec![], keypair.public_key());

        // Set timestamp to future
        block.header.timestamp = Timestamp(chrono::Utc::now() + chrono::Duration::hours(1));

        // Should still be able to hash
        let hash = block.hash();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_merkle_tree_large_scale() {
        // Test with varying sizes to ensure algorithm works correctly
        for size in [
            1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 512, 1000,
        ] {
            let transactions: Vec<Transaction> =
                (0..size).map(|_| create_test_transaction()).collect();

            let root = Block::calculate_merkle_root(&transactions);
            assert_ne!(
                root, [0u8; 32],
                "Merkle root should not be zero for {size} transactions"
            );

            // Calculate again to ensure determinism
            let root2 = Block::calculate_merkle_root(&transactions);
            assert_eq!(
                root, root2,
                "Merkle root should be deterministic for {size} transactions"
            );
        }
    }

    #[test]
    fn test_block_header_malleability() {
        let keypair = KeyPair::generate().unwrap();
        let block1 = Block::new(BlockNumber(1), [0u8; 32], vec![], keypair.public_key());
        let mut block2 = block1.clone();

        // Modify signature - should change hash
        block2.header.signature = vec![1, 2, 3];
        assert_ne!(block1.hash(), block2.hash());

        // Modify timestamp - should change hash
        block2 = block1.clone();
        block2.header.timestamp =
            Timestamp(block1.header.timestamp.0 + chrono::Duration::seconds(1));
        assert_ne!(block1.hash(), block2.hash());

        // Modify validator - should change hash
        let keypair2 = KeyPair::generate().unwrap();
        block2 = block1.clone();
        block2.header.validator = &keypair2.public_key().clone();
        assert_ne!(block1.hash(), block2.hash());
    }

    #[test]
    fn test_invalid_block_number_sequence() {
        let keypair = KeyPair::generate().unwrap();

        // Create blocks with non-sequential numbers
        let block1 = Block::new(BlockNumber(1), [0u8; 32], vec![], keypair.public_key());
        let block2 = Block::new(BlockNumber(3), block1.hash(), vec![], keypair.public_key()); // Skip block 2
        let block3 = Block::new(BlockNumber(2), block2.hash(), vec![], keypair.public_key()); // Out of order

        // All blocks should have valid hashes regardless of number sequence
        assert_ne!(block1.hash(), [0u8; 32]);
        assert_ne!(block2.hash(), [0u8; 32]);
        assert_ne!(block3.hash(), [0u8; 32]);

        // But they should reference each other correctly
        assert_eq!(block2.header.previous_hash, block1.hash());
        assert_eq!(block3.header.previous_hash, block2.hash());
    }
}

/// The main blockchain structure that manages blocks and state
pub struct Blockchain {
    storage: Arc<Storage>,
}

impl Blockchain {
    /// Create a new blockchain instance
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    /// Get the latest block number
    pub fn get_latest_block_number(&self) -> Result<Option<BlockNumber>> {
        self.storage.get_latest_block_number()
    }

    /// Get a block by its number
    pub fn get_block(&self, block_number: &BlockNumber) -> Result<Option<Block>> {
        self.storage.get_block(block_number)
    }

    /// Add a new block to the blockchain
    pub fn add_block(&self, block: &Block) -> Result<()> {
        // Validate block before adding
        self.validate_block(block)?;

        // Store the block
        self.storage.store_block(block)?;

        Ok(())
    }

    /// Validate a block before adding it to the chain
    fn validate_block(&self, block: &Block) -> Result<()> {
        // Get the latest block number
        let latest_block_num = self.storage.get_latest_block_number()?;

        if let Some(latest_num) = latest_block_num {
            // Check that the new block number is exactly one more than the latest
            if block.header.block_number.0 != latest_num.0 + 1 {
                return Err(AuraError::InvalidBlock(format!(
                    "Invalid block number: expected {}, got {}",
                    latest_num.0 + 1,
                    block.header.block_number.0
                )));
            }

            // Check that the previous hash matches the latest block's hash
            let latest_block = self
                .storage
                .get_block(&latest_num)?
                .ok_or(AuraError::BlockNotFound(latest_num.0))?;

            if block.header.previous_hash != latest_block.hash() {
                return Err(AuraError::InvalidBlock(
                    "Previous hash doesn't match latest block hash".to_string(),
                ));
            }
        } else {
            // This must be the genesis block
            if block.header.block_number.0 != 0 {
                return Err(AuraError::InvalidBlock(
                    "First block must have number 0".to_string(),
                ));
            }

            if block.header.previous_hash != [0u8; 32] {
                return Err(AuraError::InvalidBlock(
                    "Genesis block must have zero previous hash".to_string(),
                ));
            }
        }

        // Validate signature
        if block.header.signature.is_empty() {
            return Err(AuraError::InvalidBlock("Block must be signed".to_string()));
        }

        // TODO: Verify the signature against the validator's public key

        Ok(())
    }

    /// Get the current chain height
    pub fn get_chain_height(&self) -> Result<u64> {
        match self.storage.get_latest_block_number()? {
            Some(num) => Ok(num.0),
            None => Ok(0),
        }
    }
}

#[cfg(test)]
mod blockchain_tests {
    use super::*;
    use crate::storage::Storage;
    use aura_crypto::KeyPair;

    fn create_test_blockchain() -> (Blockchain, tempfile::TempDir) {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());
        (Blockchain::new(storage), temp_dir)
    }

    fn create_signed_block(number: u64, previous_hash: [u8; 32]) -> Block {
        let keypair = KeyPair::generate().unwrap();
        let mut block = Block::new(
            BlockNumber(number),
            previous_hash,
            vec![],
            keypair.public_key(),
        );

        // Add a dummy signature
        block.header.signature = vec![1, 2, 3, 4];
        block
    }

    #[test]
    fn test_blockchain_creation() {
        let (blockchain, _temp_dir) = create_test_blockchain();
        assert_eq!(blockchain.get_chain_height().unwrap(), 0);
        assert!(blockchain.get_latest_block_number().unwrap().is_none());
    }

    #[test]
    fn test_add_genesis_block() {
        let (blockchain, _temp_dir) = create_test_blockchain();
        let genesis = create_signed_block(0, [0u8; 32]);

        blockchain.add_block(&genesis).unwrap();

        assert_eq!(blockchain.get_chain_height().unwrap(), 0);
        let stored_block = blockchain.get_block(&BlockNumber(0)).unwrap().unwrap();
        assert_eq!(stored_block.header.block_number.0, 0);
    }

    #[test]
    fn test_add_block_with_wrong_number() {
        let (blockchain, _temp_dir) = create_test_blockchain();
        let genesis = create_signed_block(0, [0u8; 32]);
        blockchain.add_block(&genesis).unwrap();

        // Try to add block with wrong number
        let wrong_block = create_signed_block(2, genesis.hash());
        let result = blockchain.add_block(&wrong_block);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid block number"));
    }

    #[test]
    fn test_add_block_with_wrong_hash() {
        let (blockchain, _temp_dir) = create_test_blockchain();
        let genesis = create_signed_block(0, [0u8; 32]);
        blockchain.add_block(&genesis).unwrap();

        // Try to add block with wrong previous hash
        let wrong_block = create_signed_block(1, [1u8; 32]);
        let result = blockchain.add_block(&wrong_block);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Previous hash doesn't match"));
    }

    #[test]
    fn test_add_unsigned_block() {
        let (blockchain, _temp_dir) = create_test_blockchain();
        let keypair = KeyPair::generate().unwrap();
        let block = Block::new(BlockNumber(0), [0u8; 32], vec![], keypair.public_key());

        // Don't sign the block
        let result = blockchain.add_block(&block);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be signed"));
    }
}
