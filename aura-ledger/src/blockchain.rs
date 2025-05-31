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
