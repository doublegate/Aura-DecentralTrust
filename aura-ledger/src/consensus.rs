use crate::{storage::Storage, Block};
use aura_common::{AuraError, BlockNumber, Result};
use aura_crypto::{signing, PrivateKey, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfAuthority {
    pub validators: HashSet<PublicKey>,
    pub current_validator_index: usize,
    pub validator_rotation_interval: u64, // blocks
}

impl ProofOfAuthority {
    pub fn new(validators: Vec<PublicKey>) -> Self {
        Self {
            validators: validators.into_iter().collect(),
            current_validator_index: 0,
            validator_rotation_interval: 10,
        }
    }

    pub fn is_validator(&self, public_key: &PublicKey) -> bool {
        self.validators.contains(public_key)
    }

    pub fn add_validator(&mut self, validator: PublicKey) -> Result<()> {
        if self.validators.contains(&validator) {
            return Err(AuraError::AlreadyExists(
                "Validator already exists".to_string(),
            ));
        }
        self.validators.insert(validator);
        Ok(())
    }

    pub fn remove_validator(&mut self, validator: &PublicKey) -> Result<()> {
        if !self.validators.contains(validator) {
            return Err(AuraError::NotFound("Validator not found".to_string()));
        }
        if self.validators.len() <= 1 {
            return Err(AuraError::Validation(
                "Cannot remove last validator".to_string(),
            ));
        }
        self.validators.remove(validator);
        Ok(())
    }

    pub fn get_block_validator(&self, block_number: &BlockNumber) -> Result<&PublicKey> {
        let mut validators: Vec<&PublicKey> = self.validators.iter().collect();
        if validators.is_empty() {
            return Err(AuraError::Internal("No validators available".to_string()));
        }

        // Sort to ensure deterministic ordering
        validators.sort_by_key(|pk| pk.to_bytes());

        let index = (block_number.0 / self.validator_rotation_interval) as usize % validators.len();
        Ok(validators[index])
    }

    pub fn validate_block(&self, block: &Block, previous_block_hash: &[u8; 32]) -> Result<()> {
        // Check if the block validator is authorized
        let expected_validator = self.get_block_validator(&block.header.block_number)?;
        if &block.header.validator != expected_validator {
            return Err(AuraError::Validation("Invalid block validator".to_string()));
        }

        // Verify previous block hash
        if &block.header.previous_hash != previous_block_hash {
            return Err(AuraError::Validation(
                "Invalid previous block hash".to_string(),
            ));
        }

        // Verify block signature
        let header_for_signing = BlockHeaderForSigning {
            block_number: block.header.block_number,
            previous_hash: block.header.previous_hash,
            merkle_root: block.header.merkle_root,
            timestamp: block.header.timestamp,
            validator: block.header.validator.clone(),
        };

        let signature = Signature::from_bytes(block.header.signature.clone())
            .map_err(|e| AuraError::Crypto(e.to_string()))?;

        let valid = signing::verify_json(&block.header.validator, &header_for_signing, &signature)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;

        if !valid {
            return Err(AuraError::InvalidSignature);
        }

        // Verify all transactions
        for tx in &block.transactions {
            tx.verify()?;
        }

        Ok(())
    }

    pub fn validate_transactions(
        &self,
        transactions: &[crate::Transaction],
        storage: &Arc<Storage>,
        chain_id: &str,
    ) -> Result<()> {
        for tx in transactions {
            // Check transaction hasn't been executed
            if storage.is_transaction_executed(&tx.id)? {
                return Err(AuraError::Validation(format!(
                    "Transaction {} already executed",
                    tx.id.0
                )));
            }

            // Verify chain ID
            if tx.chain_id != chain_id {
                return Err(AuraError::Validation(format!(
                    "Invalid chain ID: expected {}, got {}",
                    chain_id, tx.chain_id
                )));
            }

            // Check nonce
            let expected_nonce = storage.get_nonce(&tx.sender)?;
            if tx.nonce != expected_nonce + 1 {
                return Err(AuraError::Validation(format!(
                    "Invalid nonce for {}: expected {}, got {}",
                    hex::encode(tx.sender.to_bytes()),
                    expected_nonce + 1,
                    tx.nonce
                )));
            }

            // Verify signature and expiration
            if !tx.verify()? {
                return Err(AuraError::InvalidSignature);
            }
        }

        Ok(())
    }

    pub fn sign_block(&self, block: &mut Block, validator_key: &PrivateKey) -> Result<()> {
        let header_for_signing = BlockHeaderForSigning {
            block_number: block.header.block_number,
            previous_hash: block.header.previous_hash,
            merkle_root: block.header.merkle_root,
            timestamp: block.header.timestamp,
            validator: block.header.validator.clone(),
        };

        let signature = signing::sign_json(validator_key, &header_for_signing)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;

        block.header.signature = signature.to_bytes().to_vec();
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockHeaderForSigning {
    pub block_number: BlockNumber,
    pub previous_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: aura_common::Timestamp,
    pub validator: PublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::Block;
    use crate::transaction::{Transaction, TransactionType};
    use aura_common::{AuraDid, DidDocument, Timestamp, TransactionId};
    use aura_crypto::{KeyPair, Signature};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn create_test_validators() -> Vec<(KeyPair, PublicKey)> {
        (0..3)
            .map(|_| {
                let keypair = KeyPair::generate().unwrap();
                let public_key = keypair.public_key().clone();
                (keypair, public_key)
            })
            .collect()
    }

    fn create_test_transaction(keypair: &KeyPair, nonce: u64) -> Transaction {
        let did_doc = DidDocument::new(AuraDid("did:aura:test123".to_string()));

        Transaction {
            id: TransactionId(format!("tx-{}", uuid::Uuid::new_v4())),
            transaction_type: TransactionType::RegisterDid {
                did_document: did_doc,
            },
            timestamp: Timestamp::now(),
            sender: keypair.public_key().clone(),
            signature: Signature(vec![0; 64]),
            nonce,
            chain_id: "test-chain".to_string(),
            expires_at: Some(Timestamp::from_unix(Timestamp::now().as_unix() + 3600)),
        }
    }

    #[test]
    fn test_poa_new() {
        let validators = create_test_validators();
        let public_keys: Vec<PublicKey> = validators.iter().map(|(_, pk)| pk.clone()).collect();

        let poa = ProofOfAuthority::new(public_keys.clone());

        assert_eq!(poa.validators.len(), 3);
        assert_eq!(poa.current_validator_index, 0);
        assert_eq!(poa.validator_rotation_interval, 10);
        for pk in &public_keys {
            assert!(poa.validators.contains(pk));
        }
    }

    #[test]
    fn test_is_validator() {
        let validators = create_test_validators();
        let public_keys: Vec<PublicKey> = validators.iter().map(|(_, pk)| pk.clone()).collect();
        let poa = ProofOfAuthority::new(public_keys.clone());

        // Test valid validator
        assert!(poa.is_validator(&public_keys[0]));

        // Test non-validator
        let non_validator = KeyPair::generate().unwrap().public_key().clone();
        assert!(!poa.is_validator(&non_validator));
    }

    #[test]
    fn test_add_validator() {
        let validators = create_test_validators();
        let public_keys: Vec<PublicKey> = validators.iter().map(|(_, pk)| pk.clone()).collect();
        let mut poa = ProofOfAuthority::new(public_keys);

        // Add new validator
        let new_validator = KeyPair::generate().unwrap().public_key().clone();
        poa.add_validator(new_validator.clone()).unwrap();
        assert_eq!(poa.validators.len(), 4);
        assert!(poa.is_validator(&new_validator));

        // Try to add duplicate
        let result = poa.add_validator(new_validator);
        assert!(result.is_err());
        match result {
            Err(AuraError::AlreadyExists(_)) => {}
            _ => panic!("Expected AlreadyExists error"),
        }
    }

    #[test]
    fn test_remove_validator() {
        let validators = create_test_validators();
        let public_keys: Vec<PublicKey> = validators.iter().map(|(_, pk)| pk.clone()).collect();
        let mut poa = ProofOfAuthority::new(public_keys.clone());

        // Remove validator
        poa.remove_validator(&public_keys[0]).unwrap();
        assert_eq!(poa.validators.len(), 2);
        assert!(!poa.is_validator(&public_keys[0]));

        // Try to remove non-existent validator
        let non_validator = KeyPair::generate().unwrap().public_key().clone();
        let result = poa.remove_validator(&non_validator);
        assert!(result.is_err());
        match result {
            Err(AuraError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_remove_last_validator() {
        let validator = KeyPair::generate().unwrap().public_key().clone();
        let mut poa = ProofOfAuthority::new(vec![validator.clone()]);

        // Try to remove last validator
        let result = poa.remove_validator(&validator);
        assert!(result.is_err());
        match result {
            Err(AuraError::Validation(msg)) => {
                assert!(msg.contains("Cannot remove last validator"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_get_block_validator() {
        let validators = create_test_validators();
        let public_keys: Vec<PublicKey> = validators.iter().map(|(_, pk)| pk.clone()).collect();
        let poa = ProofOfAuthority::new(public_keys.clone());

        // Test block validator rotation
        let validator1 = poa.get_block_validator(&BlockNumber(0)).unwrap();
        let validator2 = poa.get_block_validator(&BlockNumber(10)).unwrap();
        let validator3 = poa.get_block_validator(&BlockNumber(20)).unwrap();
        let validator4 = poa.get_block_validator(&BlockNumber(30)).unwrap();

        // Should rotate every 10 blocks
        assert_ne!(validator1, validator2);
        assert_ne!(validator2, validator3);
        assert_eq!(validator1, validator4); // Cycles back
    }

    #[test]
    fn test_get_block_validator_no_validators() {
        let poa = ProofOfAuthority {
            validators: HashSet::new(),
            current_validator_index: 0,
            validator_rotation_interval: 10,
        };

        let result = poa.get_block_validator(&BlockNumber(0));
        assert!(result.is_err());
        match result {
            Err(AuraError::Internal(msg)) => {
                assert!(msg.contains("No validators available"));
            }
            _ => panic!("Expected Internal error"),
        }
    }

    #[test]
    fn test_validate_block_valid() {
        let validators = create_test_validators();
        let public_keys: Vec<PublicKey> = validators.iter().map(|(_, pk)| pk.clone()).collect();
        let poa = ProofOfAuthority::new(public_keys.clone());

        // Get the expected validator for block 0
        let expected_validator = poa.get_block_validator(&BlockNumber(0)).unwrap();

        // Find the corresponding keypair
        let validator_keypair = validators
            .iter()
            .find(|(_, pk)| pk == expected_validator)
            .map(|(kp, _)| kp)
            .unwrap();

        // Create a valid block with the correct validator
        let mut block = Block::new(
            BlockNumber(0),
            [0u8; 32],
            vec![],
            expected_validator.clone(),
        );

        // Sign the block
        poa.sign_block(&mut block, validator_keypair.private_key())
            .unwrap();

        // Validate
        let result = poa.validate_block(&block, &[0u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_block_wrong_validator() {
        let validators = create_test_validators();
        let public_keys: Vec<PublicKey> = validators.iter().map(|(_, pk)| pk.clone()).collect();
        let poa = ProofOfAuthority::new(public_keys.clone());

        // Get the expected validator for block 0
        let expected_validator = poa.get_block_validator(&BlockNumber(0)).unwrap();

        // Find a different validator
        let wrong_validator = validators
            .iter()
            .find(|(_, pk)| pk != expected_validator)
            .map(|(_, pk)| pk.clone())
            .unwrap();

        // Create block with wrong validator
        let block = Block::new(BlockNumber(0), [0u8; 32], vec![], wrong_validator);

        let result = poa.validate_block(&block, &[0u8; 32]);
        assert!(result.is_err());
        match result {
            Err(AuraError::Validation(msg)) => {
                assert!(msg.contains("Invalid block validator"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_validate_block_wrong_previous_hash() {
        let validators = create_test_validators();
        let public_keys: Vec<PublicKey> = validators.iter().map(|(_, pk)| pk.clone()).collect();
        let poa = ProofOfAuthority::new(public_keys.clone());

        // Get the expected validator for block 0
        let expected_validator = poa.get_block_validator(&BlockNumber(0)).unwrap();

        let block = Block::new(
            BlockNumber(0),
            [1u8; 32], // Wrong hash
            vec![],
            expected_validator.clone(),
        );

        let result = poa.validate_block(&block, &[0u8; 32]);
        assert!(result.is_err());
        match result {
            Err(AuraError::Validation(msg)) => {
                assert!(msg.contains("Invalid previous block hash"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_validate_block_invalid_signature() {
        let validators = create_test_validators();
        let public_keys: Vec<PublicKey> = validators.iter().map(|(_, pk)| pk.clone()).collect();
        let poa = ProofOfAuthority::new(public_keys.clone());

        // Get the expected validator for block 0
        let expected_validator = poa.get_block_validator(&BlockNumber(0)).unwrap();

        // Find a different keypair to sign with
        let wrong_keypair = validators
            .iter()
            .find(|(_, pk)| pk != expected_validator)
            .map(|(kp, _)| kp)
            .unwrap();

        let mut block = Block::new(
            BlockNumber(0),
            [0u8; 32],
            vec![],
            expected_validator.clone(),
        );

        // Sign with wrong key
        poa.sign_block(&mut block, wrong_keypair.private_key())
            .unwrap();

        let result = poa.validate_block(&block, &[0u8; 32]);
        assert!(result.is_err());
        match result {
            Err(AuraError::InvalidSignature) => {}
            _ => panic!("Expected InvalidSignature error"),
        }
    }

    #[test]
    fn test_validate_transactions() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());
        let poa = ProofOfAuthority::new(vec![]);

        let keypair = KeyPair::generate().unwrap();
        let mut tx = create_test_transaction(&keypair, 1);

        // Sign transaction properly
        let tx_for_signing = crate::transaction::TransactionForSigning {
            id: tx.id.clone(),
            transaction_type: tx.transaction_type.clone(),
            timestamp: tx.timestamp,
            sender: tx.sender.clone(),
            nonce: tx.nonce,
            chain_id: tx.chain_id.clone(),
            expires_at: tx.expires_at,
        };
        tx.signature = signing::sign_json(keypair.private_key(), &tx_for_signing).unwrap();

        // Validate
        let result = poa.validate_transactions(&[tx], &storage, "test-chain");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_transactions_wrong_chain_id() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());
        let poa = ProofOfAuthority::new(vec![]);

        let keypair = KeyPair::generate().unwrap();
        let tx = create_test_transaction(&keypair, 1);

        let result = poa.validate_transactions(&[tx], &storage, "wrong-chain");
        assert!(result.is_err());
        match result {
            Err(AuraError::Validation(msg)) => {
                assert!(msg.contains("Invalid chain ID"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_sign_block() {
        let keypair = KeyPair::generate().unwrap();
        let poa = ProofOfAuthority::new(vec![keypair.public_key().clone()]);

        let mut block = Block::new(
            BlockNumber(0),
            [0u8; 32],
            vec![],
            keypair.public_key().clone(),
        );

        assert!(block.header.signature.is_empty());

        poa.sign_block(&mut block, keypair.private_key()).unwrap();

        assert_eq!(block.header.signature.len(), 64);
    }

    #[test]
    fn test_validator_rotation() {
        let validators = create_test_validators();
        let public_keys: Vec<PublicKey> = validators.iter().map(|(_, pk)| pk.clone()).collect();
        let poa = ProofOfAuthority::new(public_keys.clone());

        // Test that validators rotate correctly
        let mut validator_sequence = vec![];
        for i in 0..30 {
            let validator = poa.get_block_validator(&BlockNumber(i)).unwrap();
            validator_sequence.push(validator);
        }

        // Every 10 blocks should have same validator
        for i in 0..3 {
            let start = i * 10;
            let end = (i + 1) * 10;
            for j in start + 1..end {
                assert_eq!(validator_sequence[start], validator_sequence[j]);
            }
        }

        // Different rotation periods should have different validators
        assert_ne!(validator_sequence[0], validator_sequence[10]);
        assert_ne!(validator_sequence[10], validator_sequence[20]);
    }
}
