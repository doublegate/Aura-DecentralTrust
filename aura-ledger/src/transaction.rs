use serde::{Deserialize, Serialize};
use aura_common::{
    AuraError, Result, Timestamp, TransactionId, AuraDid,
    DidDocument, VerifiableCredential, CredentialSchema,
};
use aura_crypto::{PublicKey, Signature};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: TransactionId,
    pub transaction_type: TransactionType,
    pub timestamp: Timestamp,
    pub sender: PublicKey,
    pub signature: Signature,
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
    ) -> Self {
        Self {
            id: TransactionId(uuid::Uuid::new_v4().to_string()),
            transaction_type,
            timestamp: Timestamp::now(),
            sender,
            signature,
        }
    }
    
    pub fn verify(&self) -> Result<bool> {
        // Verify the signature matches the transaction content
        let tx_without_sig = TransactionForSigning {
            id: self.id.clone(),
            transaction_type: self.transaction_type.clone(),
            timestamp: self.timestamp.clone(),
            sender: self.sender.clone(),
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
}

// Add uuid to workspace dependencies
use uuid;