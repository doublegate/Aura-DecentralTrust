#[cfg(test)]
mod tests {
    use aura_common::{AuraDid, BlockNumber, DidDocument, Timestamp, TransactionId};
    use aura_crypto::KeyPair;
    use aura_ledger::{Block, Blockchain, Transaction, TransactionType};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn test_blockchain_integration() {
        // Create in-memory storage
        let storage_path =
            std::env::temp_dir().join(format!("aura_test_blockchain_{}", uuid::Uuid::new_v4()));
        let storage = Arc::new(aura_ledger::storage::Storage::new(storage_path).unwrap());

        // Create blockchain instance
        let blockchain = Arc::new(RwLock::new(Blockchain::new(storage)));

        // Create a genesis block
        let keypair = KeyPair::generate().unwrap();
        let mut genesis = Block::new(BlockNumber(0), [0u8; 32], vec![], keypair.public_key());

        // Sign the block
        let block_hash = genesis.hash();
        let signature = aura_crypto::signing::sign(keypair.private_key(), &block_hash)
            .unwrap()
            .to_bytes()
            .to_vec();
        genesis.header.signature = signature;

        // Add genesis block
        {
            let blockchain_guard = blockchain.write().await;
            blockchain_guard.add_block(&genesis).unwrap();
        }

        // Verify block was stored
        {
            let blockchain_guard = blockchain.read().await;
            let stored_block = blockchain_guard
                .get_block(&BlockNumber(0))
                .unwrap()
                .unwrap();

            assert_eq!(stored_block.header.block_number.0, 0);
            assert_eq!(blockchain_guard.get_chain_height().unwrap(), 0);
        }

        // Create a DID document for testing
        let did = AuraDid("did:aura:test123".to_string());
        let did_doc = DidDocument::new(did.clone());

        // Create a transaction
        let tx_data = TransactionType::RegisterDid {
            did_document: did_doc,
        };

        // Sign the transaction data
        let tx_bytes = serde_json::to_vec(&tx_data).unwrap();
        let tx_signature = aura_crypto::signing::sign(keypair.private_key(), &tx_bytes).unwrap();

        let transaction = Transaction {
            id: TransactionId("tx123".to_string()),
            transaction_type: tx_data,
            timestamp: Timestamp::now(),
            sender: keypair.public_key(),
            signature: tx_signature,
            nonce: 1,
            chain_id: "test-chain".to_string(),
            expires_at: None,
        };

        // Add a second block
        let mut block1 = Block::new(
            BlockNumber(1),
            genesis.hash(),
            vec![transaction],
            keypair.public_key(),
        );

        // Sign the second block
        let block1_hash = block1.hash();
        let signature1 = aura_crypto::signing::sign(keypair.private_key(), &block1_hash)
            .unwrap()
            .to_bytes()
            .to_vec();
        block1.header.signature = signature1;

        // Add second block
        {
            let blockchain_guard = blockchain.write().await;
            blockchain_guard.add_block(&block1).unwrap();
        }

        // Verify second block
        {
            let blockchain_guard = blockchain.read().await;
            assert_eq!(blockchain_guard.get_chain_height().unwrap(), 1);

            let stored_block = blockchain_guard
                .get_block(&BlockNumber(1))
                .unwrap()
                .unwrap();

            assert_eq!(stored_block.header.block_number.0, 1);
            assert_eq!(stored_block.header.previous_hash, genesis.hash());
            assert_eq!(stored_block.transactions.len(), 1);
        }
    }

    #[tokio::test]
    async fn test_invalid_block_rejection() {
        let storage_path =
            std::env::temp_dir().join(format!("aura_test_blockchain_{}", uuid::Uuid::new_v4()));
        let storage = Arc::new(aura_ledger::storage::Storage::new(storage_path).unwrap());
        let blockchain = Arc::new(RwLock::new(Blockchain::new(storage)));

        let keypair = KeyPair::generate().unwrap();

        // Try to add block 1 without genesis
        let mut block1 = Block::new(BlockNumber(1), [0u8; 32], vec![], keypair.public_key());
        block1.header.signature = vec![1, 2, 3];

        let blockchain_guard = blockchain.write().await;
        let result = blockchain_guard.add_block(&block1);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("First block must have number 0"));
    }
}
