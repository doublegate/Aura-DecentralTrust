use crate::transaction::Transaction;
use aura_common::{BlockNumber, Timestamp};
use aura_crypto::{hashing, PublicKey};
use serde::{Deserialize, Serialize};

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
    use aura_crypto::KeyPair;
    use crate::transaction::{Transaction, TransactionType};
    use aura_common::{DidDocument, AuraDid};
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
            sender: keypair.public_key().clone(),
            signature: Signature(vec![0; 64]),
            nonce: 1,
            chain_id: "test-chain".to_string(),
            expires_at: None,
        }
    }

    #[test]
    fn test_block_new() {
        let keypair = KeyPair::generate().unwrap();
        let validator = keypair.public_key().clone();
        let previous_hash = [1u8; 32];
        let transactions = vec![create_test_transaction()];
        
        let block = Block::new(BlockNumber(1), previous_hash, transactions.clone(), validator.clone());
        
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
        let block = Block::new(BlockNumber(1), [0u8; 32], vec![], keypair.public_key().clone());
        
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
        let validator = keypair.public_key().clone();
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
            keypair2.public_key().clone(),
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
        let block = Block::new(BlockNumber(1), [0u8; 32], vec![create_test_transaction()], keypair.public_key().clone());
        
        // Test JSON serialization
        let json = serde_json::to_string(&block).unwrap();
        let deserialized: Block = serde_json::from_str(&json).unwrap();
        
        assert_eq!(block.header.block_number, deserialized.header.block_number);
        assert_eq!(block.header.previous_hash, deserialized.header.previous_hash);
        assert_eq!(block.transactions.len(), deserialized.transactions.len());
    }

    #[test]
    fn test_genesis_block_serialization() {
        let keypair = KeyPair::generate().unwrap();
        let genesis = GenesisBlock {
            timestamp: Timestamp::now(),
            validators: vec![keypair.public_key().clone()],
            chain_config: ChainConfig::default(),
        };
        
        let json = serde_json::to_string(&genesis).unwrap();
        let deserialized: GenesisBlock = serde_json::from_str(&json).unwrap();
        
        assert_eq!(genesis.validators.len(), deserialized.validators.len());
        assert_eq!(genesis.chain_config.chain_id, deserialized.chain_config.chain_id);
    }

    #[test]
    fn test_block_with_signature() {
        let keypair = KeyPair::generate().unwrap();
        let mut block = Block::new(BlockNumber(1), [0u8; 32], vec![], keypair.public_key().clone());
        
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
        let block1 = Block::new(BlockNumber(1), [0u8; 32], vec![], keypair.public_key().clone());
        
        // Small delay to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        let block2 = Block::new(BlockNumber(2), [0u8; 32], vec![], keypair.public_key().clone());
        
        // Timestamps should be different
        assert!(block2.header.timestamp.0 > block1.header.timestamp.0);
    }

    #[test]
    fn test_different_validators_different_blocks() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();
        
        let block1 = Block::new(BlockNumber(1), [0u8; 32], vec![], keypair1.public_key().clone());
        let block2 = Block::new(BlockNumber(1), [0u8; 32], vec![], keypair2.public_key().clone());
        
        // Same block number and previous hash but different validators
        assert_ne!(block1.hash(), block2.hash());
    }
}
