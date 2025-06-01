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
            timestamp: self.timestamp,
            sender: self.sender.clone(),
            nonce: self.nonce,
            chain_id: self.chain_id.clone(),
            expires_at: self.expires_at,
        };

        aura_crypto::verify_json(&self.sender, &tx_without_sig, &self.signature)
            .map_err(|e| AuraError::Crypto(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionForSigning {
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

#[cfg(test)]
mod tests {
    use super::*;
    use aura_crypto::{sign_json, KeyPair};

    fn create_test_did_document(_keypair: &KeyPair) -> DidDocument {
        DidDocument::new(AuraDid("did:aura:test123".to_string()))
    }

    fn create_test_schema() -> CredentialSchema {
        CredentialSchema {
            id: "https://example.com/schema/1".to_string(),
            schema_type: "CredentialSchema2023".to_string(),
            name: "Test Schema".to_string(),
            version: "1.0.0".to_string(),
            author: AuraDid("did:aura:author123".to_string()),
            created: Timestamp::now(),
            schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string"
                    }
                }
            }),
        }
    }

    fn sign_transaction(tx: &Transaction, keypair: &KeyPair) -> Signature {
        let tx_for_signing = TransactionForSigning {
            id: tx.id.clone(),
            transaction_type: tx.transaction_type.clone(),
            timestamp: tx.timestamp,
            sender: tx.sender.clone(),
            nonce: tx.nonce,
            chain_id: tx.chain_id.clone(),
            expires_at: tx.expires_at,
        };

        sign_json(keypair.private_key(), &tx_for_signing).unwrap()
    }

    #[test]
    fn test_transaction_new() {
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document(&keypair);
        let tx_type = TransactionType::RegisterDid {
            did_document: did_doc,
        };

        let signature = Signature(vec![0; 64]);
        let tx = Transaction::new(
            tx_type.clone(),
            keypair.public_key().clone(),
            signature.clone(),
            1,
            "test-chain".to_string(),
        );

        assert!(!tx.id.0.is_empty());
        assert!(tx.timestamp.as_unix() > 0);
        assert_eq!(tx.nonce, 1);
        assert_eq!(tx.chain_id, "test-chain");
        assert!(tx.expires_at.is_some());

        // Check default expiry is about 1 hour
        let expiry_diff = tx.expires_at.unwrap().as_unix() - tx.timestamp.as_unix();
        assert!(expiry_diff >= 3599 && expiry_diff <= 3601);
    }

    #[test]
    fn test_transaction_verify_valid() {
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document(&keypair);
        let tx_type = TransactionType::RegisterDid {
            did_document: did_doc,
        };

        let mut tx = Transaction::new(
            tx_type,
            keypair.public_key().clone(),
            Signature(vec![]), // Placeholder
            1,
            "test-chain".to_string(),
        );

        // Sign the transaction properly
        tx.signature = sign_transaction(&tx, &keypair);

        let result = tx.verify().unwrap();
        assert!(result);
    }

    #[test]
    fn test_transaction_verify_wrong_signature() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document(&keypair1);
        let tx_type = TransactionType::RegisterDid {
            did_document: did_doc,
        };

        let mut tx = Transaction::new(
            tx_type,
            keypair1.public_key().clone(),
            Signature(vec![]), // Placeholder
            1,
            "test-chain".to_string(),
        );

        // Sign with wrong key
        tx.signature = sign_transaction(&tx, &keypair2);

        let result = tx.verify().unwrap();
        assert!(!result);
    }

    #[test]
    fn test_transaction_verify_expired() {
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document(&keypair);
        let tx_type = TransactionType::RegisterDid {
            did_document: did_doc,
        };

        let mut tx = Transaction::new(
            tx_type,
            keypair.public_key().clone(),
            Signature(vec![]), // Placeholder
            1,
            "test-chain".to_string(),
        );

        // Set expiry to past
        tx.expires_at = Some(Timestamp::from_unix(tx.timestamp.as_unix() - 1000));
        tx.signature = sign_transaction(&tx, &keypair);

        let result = tx.verify().unwrap();
        assert!(!result);
    }

    #[test]
    fn test_transaction_verify_no_expiry() {
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document(&keypair);
        let tx_type = TransactionType::RegisterDid {
            did_document: did_doc,
        };

        let mut tx = Transaction::new(
            tx_type,
            keypair.public_key().clone(),
            Signature(vec![]), // Placeholder
            1,
            "test-chain".to_string(),
        );

        // Remove expiry
        tx.expires_at = None;
        tx.signature = sign_transaction(&tx, &keypair);

        let result = tx.verify().unwrap();
        assert!(result);
    }

    #[test]
    fn test_transaction_types_register_did() {
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document(&keypair);
        let tx_type = TransactionType::RegisterDid {
            did_document: did_doc.clone(),
        };

        if let TransactionType::RegisterDid { did_document } = tx_type {
            assert_eq!(did_document.id, did_doc.id);
        } else {
            panic!("Wrong transaction type");
        }
    }

    #[test]
    fn test_transaction_types_update_did() {
        let keypair = KeyPair::generate().unwrap();
        let did = AuraDid("did:aura:test123".to_string());
        let did_doc = create_test_did_document(&keypair);
        let tx_type = TransactionType::UpdateDid {
            did: did.clone(),
            did_document: did_doc.clone(),
        };

        if let TransactionType::UpdateDid {
            did: tx_did,
            did_document,
        } = tx_type
        {
            assert_eq!(tx_did, did);
            assert_eq!(did_document.id, did_doc.id);
        } else {
            panic!("Wrong transaction type");
        }
    }

    #[test]
    fn test_transaction_types_deactivate_did() {
        let did = AuraDid("did:aura:test123".to_string());
        let tx_type = TransactionType::DeactivateDid { did: did.clone() };

        if let TransactionType::DeactivateDid { did: tx_did } = tx_type {
            assert_eq!(tx_did, did);
        } else {
            panic!("Wrong transaction type");
        }
    }

    #[test]
    fn test_transaction_types_register_schema() {
        let schema = create_test_schema();
        let tx_type = TransactionType::RegisterSchema {
            schema: schema.clone(),
        };

        if let TransactionType::RegisterSchema { schema: tx_schema } = tx_type {
            assert_eq!(tx_schema.id, schema.id);
            assert_eq!(tx_schema.name, schema.name);
        } else {
            panic!("Wrong transaction type");
        }
    }

    #[test]
    fn test_transaction_types_update_revocation_list() {
        let list_id = "revocation-list-1".to_string();
        let indices = vec![1, 5, 10, 15];
        let tx_type = TransactionType::UpdateRevocationList {
            list_id: list_id.clone(),
            revoked_indices: indices.clone(),
        };

        if let TransactionType::UpdateRevocationList {
            list_id: tx_list_id,
            revoked_indices: tx_indices,
        } = tx_type
        {
            assert_eq!(tx_list_id, list_id);
            assert_eq!(tx_indices, indices);
        } else {
            panic!("Wrong transaction type");
        }
    }

    #[test]
    fn test_transaction_serialization() {
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document(&keypair);
        let tx_type = TransactionType::RegisterDid {
            did_document: did_doc,
        };

        let tx = Transaction::new(
            tx_type,
            keypair.public_key().clone(),
            Signature(vec![0; 64]),
            1,
            "test-chain".to_string(),
        );

        // Test JSON serialization
        let json = serde_json::to_string(&tx).unwrap();
        let deserialized: Transaction = serde_json::from_str(&json).unwrap();

        assert_eq!(tx.id, deserialized.id);
        assert_eq!(tx.nonce, deserialized.nonce);
        assert_eq!(tx.chain_id, deserialized.chain_id);
    }

    #[test]
    fn test_transaction_different_chain_ids() {
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document(&keypair);
        let tx_type = TransactionType::RegisterDid {
            did_document: did_doc,
        };

        let tx1 = Transaction::new(
            tx_type.clone(),
            keypair.public_key().clone(),
            Signature(vec![0; 64]),
            1,
            "chain-1".to_string(),
        );

        let tx2 = Transaction::new(
            tx_type,
            keypair.public_key().clone(),
            Signature(vec![0; 64]),
            1,
            "chain-2".to_string(),
        );

        assert_ne!(tx1.chain_id, tx2.chain_id);
    }

    #[test]
    fn test_transaction_nonce_prevents_replay() {
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document(&keypair);
        let tx_type = TransactionType::RegisterDid {
            did_document: did_doc,
        };

        let tx1 = Transaction::new(
            tx_type.clone(),
            keypair.public_key().clone(),
            Signature(vec![0; 64]),
            1,
            "test-chain".to_string(),
        );

        let tx2 = Transaction::new(
            tx_type,
            keypair.public_key().clone(),
            Signature(vec![0; 64]),
            2,
            "test-chain".to_string(),
        );

        assert_ne!(tx1.nonce, tx2.nonce);
    }

    #[test]
    fn test_transaction_for_signing_excludes_signature() {
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document(&keypair);
        let tx_type = TransactionType::RegisterDid {
            did_document: did_doc,
        };

        let tx = Transaction::new(
            tx_type,
            keypair.public_key().clone(),
            Signature(vec![0; 64]),
            1,
            "test-chain".to_string(),
        );

        let tx_for_signing = TransactionForSigning {
            id: tx.id.clone(),
            transaction_type: tx.transaction_type.clone(),
            timestamp: tx.timestamp,
            sender: tx.sender.clone(),
            nonce: tx.nonce,
            chain_id: tx.chain_id.clone(),
            expires_at: tx.expires_at,
        };

        // Should serialize without signature field
        let json = serde_json::to_string(&tx_for_signing).unwrap();
        assert!(!json.contains("signature"));
    }

    #[test]
    fn test_transaction_unique_ids() {
        let keypair = KeyPair::generate().unwrap();
        let did_doc = create_test_did_document(&keypair);
        let tx_type = TransactionType::RegisterDid {
            did_document: did_doc,
        };

        let tx1 = Transaction::new(
            tx_type.clone(),
            keypair.public_key().clone(),
            Signature(vec![0; 64]),
            1,
            "test-chain".to_string(),
        );

        let tx2 = Transaction::new(
            tx_type,
            keypair.public_key().clone(),
            Signature(vec![0; 64]),
            1,
            "test-chain".to_string(),
        );

        // IDs should be unique even for identical transactions
        assert_ne!(tx1.id, tx2.id);
    }

    #[test]
    fn test_complex_schema_transaction() {
        let keypair = KeyPair::generate().unwrap();
        let schema = CredentialSchema {
            id: "https://example.com/schemas/diploma".to_string(),
            schema_type: "CredentialSchema2023".to_string(),
            name: "University Diploma".to_string(),
            version: "2.0.0".to_string(),
            author: AuraDid("did:aura:university".to_string()),
            created: Timestamp::now(),
            schema: serde_json::json!({
                "type": "object",
                "description": "Schema for university diploma credentials",
                "properties": {
                    "degree": {
                        "type": "string",
                        "enum": ["Bachelor", "Master", "PhD"]
                    },
                    "field": {
                        "type": "string"
                    },
                    "university": {
                        "type": "string"
                    },
                    "gpa": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 4.0
                    }
                }
            }),
        };

        let tx_type = TransactionType::RegisterSchema { schema };
        let mut tx = Transaction::new(
            tx_type,
            keypair.public_key().clone(),
            Signature(vec![]),
            1,
            "test-chain".to_string(),
        );

        tx.signature = sign_transaction(&tx, &keypair);
        assert!(tx.verify().unwrap());
    }
}
