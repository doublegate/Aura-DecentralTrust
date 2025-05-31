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
        let validators: Vec<&PublicKey> = self.validators.iter().collect();
        if validators.is_empty() {
            return Err(AuraError::Internal("No validators available".to_string()));
        }

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
            timestamp: block.header.timestamp.clone(),
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
            timestamp: block.header.timestamp.clone(),
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
