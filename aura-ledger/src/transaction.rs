use aura_common::{
    AuraDid, AuraError, CredentialSchema, DidDocument, Result, Timestamp, TransactionId,
};
use aura_crypto::{PublicKey, Signature};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: TransactionId,
    pub transaction_type: TransactionType,
    pub timestamp: Timestamp,
    pub sender: PublicKey,
    pub signature: Signature,
    pub nonce: u64,                    // Prevents replay attacks
    pub chain_id: String,              // Prevents cross-chain replay
    pub expires_at: Option<Timestamp>, // Optional expiration
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TransactionType {
    // DID Operations
    RegisterDid {
        did_document: DidDocument,
    },
    UpdateDid {
        did: AuraDid,
        did_document: DidDocument,
    },
    DeactivateDid {
        did: AuraDid,
    },

    // VC Schema Operations
    RegisterSchema {
        schema: CredentialSchema,
    },

    // Revocation Operations
    UpdateRevocationList {
        list_id: String,
        revoked_indices: Vec<u32>,
    },
}

impl Transaction {
    pub fn new(
        transaction_type: TransactionType,
        sender: PublicKey,
        signature: Signature,
        nonce: u64,
        chain_id: String,
    ) -> Self {
        Self {
            id: TransactionId(uuid::Uuid::new_v4().to_string()),
            transaction_type,
            timestamp: Timestamp::now(),
            sender,
            signature,
            nonce,
            chain_id,
            expires_at: Some(Timestamp::from_unix(Timestamp::now().as_unix() + 3600)), // 1 hour expiry by default
        }
    }

    pub fn verify(&self) -> Result<bool> {
        // Check if transaction has expired
        if let Some(expires_at) = &self.expires_at {
            if Timestamp::now().as_unix() > expires_at.as_unix() {
                return Ok(false);
            }
        }

        // Verify the signature matches the transaction content
        let tx_without_sig = TransactionForSigning {
            id: self.id.clone(),
            transaction_type: self.transaction_type.clone(),
            timestamp: self.timestamp.clone(),
            sender: self.sender.clone(),
            nonce: self.nonce,
            chain_id: self.chain_id.clone(),
            expires_at: self.expires_at.clone(),
        };

        aura_crypto::verify_json(&self.sender, &tx_without_sig, &self.signature)
            .map_err(|e| AuraError::Crypto(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransactionForSigning {
    pub id: TransactionId,
    pub transaction_type: TransactionType,
    pub timestamp: Timestamp,
    pub sender: PublicKey,
    pub nonce: u64,
    pub chain_id: String,
    pub expires_at: Option<Timestamp>,
}

// Add uuid to workspace dependencies
use uuid;
