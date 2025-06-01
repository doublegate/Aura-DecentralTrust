//! End-to-end integration tests across all Aura crates
//! 
//! These tests verify the complete workflow from key generation through
//! DID creation, credential issuance, and blockchain storage.

use aura_common::{AuraDid, DidDocument, VerificationMethod, VerificationRelationship, Timestamp};
use aura_common::vc::{VerifiableCredential, CredentialSubject, CredentialSchema, Issuer, Proof};
use aura_crypto::{KeyPair, PublicKey, PrivateKey};
use aura_ledger::{
    Blockchain, Storage, DidRegistry, VcSchemaRegistry, RevocationRegistry,
    consensus::ProofOfAuthority,
    transaction::{Transaction, TransactionType},
    BlockNumber,
};
use aura_wallet_core::{Wallet, CredentialStore, KeyManager};
use std::sync::Arc;
use tokio::sync::RwLock;
use tempfile::TempDir;

/// Helper function to create a test blockchain with storage
async fn create_test_blockchain() -> (Arc<RwLock<Blockchain>>, Arc<Storage>, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(Storage::new(temp_dir.path().to_path_buf()).unwrap());
    
    let validator_keys = vec![KeyPair::generate().unwrap()];
    let consensus = ProofOfAuthority::new(
        validator_keys.iter().map(|k| k.public_key().clone()).collect()
    );
    
    let blockchain = Arc::new(RwLock::new(
        Blockchain::new(storage.clone(), Box::new(consensus)).unwrap()
    ));
    
    (blockchain, storage, temp_dir)
}

/// Test complete DID lifecycle: creation, registration, resolution, and updates
#[tokio::test]
async fn test_complete_did_lifecycle() {
    // 1. Generate keys
    let keypair = KeyPair::generate().unwrap();
    let public_key = keypair.public_key();
    let private_key = keypair.private_key();
    
    // 2. Create DID document
    let did = AuraDid::new("test-user");
    let mut did_doc = DidDocument::new(did.clone());
    
    // Add authentication method
    did_doc.authentication.push(VerificationRelationship::Embedded(
        VerificationMethod {
            id: format!("{}#key-1", did.to_string()),
            controller: did.clone(),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            public_key_multibase: aura_crypto::multibase_encode(public_key.as_bytes()),
        }
    ));
    
    // 3. Create blockchain and registries
    let (blockchain, storage, _temp_dir) = create_test_blockchain().await;
    let did_registry = Arc::new(RwLock::new(DidRegistry::new(storage.clone())));
    
    // 4. Create and sign transaction
    let tx_type = TransactionType::RegisterDid {
        did_document: did_doc.clone(),
    };
    
    let tx = Transaction {
        id: aura_common::TransactionId(uuid::Uuid::new_v4().to_string()),
        transaction_type: tx_type,
        timestamp: Timestamp::now(),
        sender: public_key.clone(),
        signature: aura_crypto::Signature(vec![0; 64]), // Will be replaced
        nonce: 1,
        chain_id: "test-chain".to_string(),
        expires_at: Some(Timestamp::from_unix(Timestamp::now().as_unix() + 3600)),
    };
    
    // Sign transaction
    let tx_for_signing = aura_ledger::transaction::TransactionForSigning {
        id: tx.id.clone(),
        transaction_type: tx.transaction_type.clone(),
        timestamp: tx.timestamp,
        sender: tx.sender.clone(),
        nonce: tx.nonce,
        chain_id: tx.chain_id.clone(),
        expires_at: tx.expires_at,
    };
    
    let signature = aura_crypto::sign_json(private_key, &tx_for_signing).unwrap();
    let signed_tx = Transaction { signature, ..tx };
    
    // 5. Process transaction
    {
        let mut registry = did_registry.write().await;
        registry.register_did(did_doc.clone(), BlockNumber(1)).unwrap();
    }
    
    // 6. Add transaction to blockchain
    {
        let mut bc = blockchain.write().await;
        bc.add_transaction(signed_tx.clone()).unwrap();
        bc.produce_block(keypair).unwrap();
    }
    
    // 7. Resolve DID
    {
        let registry = did_registry.read().await;
        let resolved = registry.resolve_did(&did).unwrap();
        assert!(resolved.is_some());
        let resolved_doc = resolved.unwrap();
        assert_eq!(resolved_doc.id, did);
        assert_eq!(resolved_doc.authentication.len(), 1);
    }
    
    // 8. Update DID
    let mut updated_doc = did_doc.clone();
    updated_doc.authentication.push(VerificationRelationship::Embedded(
        VerificationMethod {
            id: format!("{}#key-2", did.to_string()),
            controller: did.clone(),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            public_key_multibase: aura_crypto::multibase_encode(&[1u8; 32]),
        }
    ));
    
    let update_tx_type = TransactionType::UpdateDid {
        did: did.clone(),
        did_document: updated_doc.clone(),
    };
    
    let update_tx = Transaction {
        id: aura_common::TransactionId(uuid::Uuid::new_v4().to_string()),
        transaction_type: update_tx_type,
        timestamp: Timestamp::now(),
        sender: public_key.clone(),
        signature: aura_crypto::Signature(vec![0; 64]),
        nonce: 2,
        chain_id: "test-chain".to_string(),
        expires_at: Some(Timestamp::from_unix(Timestamp::now().as_unix() + 3600)),
    };
    
    // Sign update transaction
    let update_tx_for_signing = aura_ledger::transaction::TransactionForSigning {
        id: update_tx.id.clone(),
        transaction_type: update_tx.transaction_type.clone(),
        timestamp: update_tx.timestamp,
        sender: update_tx.sender.clone(),
        nonce: update_tx.nonce,
        chain_id: update_tx.chain_id.clone(),
        expires_at: update_tx.expires_at,
    };
    
    let update_signature = aura_crypto::sign_json(private_key, &update_tx_for_signing).unwrap();
    let signed_update_tx = Transaction { signature: update_signature, ..update_tx };
    
    // Process update
    {
        let mut registry = did_registry.write().await;
        registry.update_did(&did, updated_doc.clone(), BlockNumber(2)).unwrap();
    }
    
    {
        let mut bc = blockchain.write().await;
        bc.add_transaction(signed_update_tx).unwrap();
        bc.produce_block(keypair).unwrap();
    }
    
    // Verify update
    {
        let registry = did_registry.read().await;
        let resolved = registry.resolve_did(&did).unwrap().unwrap();
        assert_eq!(resolved.authentication.len(), 2);
    }
}

/// Test complete verifiable credential workflow
#[tokio::test]
async fn test_complete_vc_workflow() {
    // 1. Setup issuer and holder
    let issuer_keypair = KeyPair::generate().unwrap();
    let holder_keypair = KeyPair::generate().unwrap();
    
    let issuer_did = AuraDid::new("issuer");
    let holder_did = AuraDid::new("holder");
    
    // 2. Create credential schema
    let schema = CredentialSchema {
        id: "https://example.com/schemas/degree".to_string(),
        schema_type: "CredentialSchema2023".to_string(),
        name: "UniversityDegree".to_string(),
        version: "1.0.0".to_string(),
        author: issuer_did.clone(),
        created: Timestamp::now(),
        schema: serde_json::json!({
            "type": "object",
            "properties": {
                "degree": {"type": "string"},
                "university": {"type": "string"},
                "graduationDate": {"type": "string", "format": "date"}
            },
            "required": ["degree", "university", "graduationDate"]
        }),
    };
    
    // 3. Setup blockchain and registries
    let (blockchain, storage, _temp_dir) = create_test_blockchain().await;
    let schema_registry = Arc::new(RwLock::new(VcSchemaRegistry::new(storage.clone())));
    let revocation_registry = Arc::new(RwLock::new(RevocationRegistry::new(storage.clone())));
    
    // 4. Register schema
    {
        let mut registry = schema_registry.write().await;
        registry.register_schema(schema.clone(), BlockNumber(1)).unwrap();
    }
    
    // 5. Create verifiable credential
    let credential = VerifiableCredential {
        context: vec![
            "https://www.w3.org/2018/credentials/v1".to_string(),
            "https://www.w3.org/2018/credentials/examples/v1".to_string(),
        ],
        id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        credential_type: vec![
            "VerifiableCredential".to_string(),
            "UniversityDegreeCredential".to_string(),
        ],
        issuer: Issuer::Uri(issuer_did.to_string()),
        issuance_date: chrono::Utc::now(),
        expiration_date: Some(chrono::Utc::now() + chrono::Duration::days(365)),
        credential_subject: CredentialSubject {
            id: Some(holder_did.to_string()),
            claims: serde_json::json!({
                "degree": "Bachelor of Science",
                "university": "Example University",
                "graduationDate": "2023-06-15"
            }),
        },
        proof: None,
    };
    
    // 6. Sign credential
    let signed_credential = aura_crypto::sign_verifiable_credential(
        &credential,
        issuer_keypair.private_key(),
        &issuer_did.to_string(),
        "Ed25519Signature2020"
    ).unwrap();
    
    // 7. Verify credential signature
    let is_valid = aura_crypto::verify_verifiable_credential(
        &signed_credential,
        issuer_keypair.public_key()
    ).unwrap();
    assert!(is_valid);
    
    // 8. Store credential in wallet
    let wallet_dir = TempDir::new().unwrap();
    let wallet = Wallet::new(wallet_dir.path().to_path_buf()).unwrap();
    
    // Store credential
    wallet.store_credential(&signed_credential).unwrap();
    
    // 9. Retrieve and verify credential from wallet
    let retrieved = wallet.get_credential(&signed_credential.id).unwrap();
    assert!(retrieved.is_some());
    let retrieved_cred = retrieved.unwrap();
    assert_eq!(retrieved_cred.id, signed_credential.id);
    
    // 10. Check revocation status
    {
        let registry = revocation_registry.read().await;
        let is_revoked = registry.is_credential_revoked(&signed_credential.id).unwrap();
        assert!(!is_revoked);
    }
    
    // 11. Revoke credential
    let revocation_tx = Transaction {
        id: aura_common::TransactionId(uuid::Uuid::new_v4().to_string()),
        transaction_type: TransactionType::UpdateRevocationList {
            list_id: "default-list".to_string(),
            revoked_indices: vec![1], // Assuming credential has index 1
        },
        timestamp: Timestamp::now(),
        sender: issuer_keypair.public_key().clone(),
        signature: aura_crypto::Signature(vec![0; 64]),
        nonce: 1,
        chain_id: "test-chain".to_string(),
        expires_at: None,
    };
    
    // Sign revocation transaction
    let revocation_tx_for_signing = aura_ledger::transaction::TransactionForSigning {
        id: revocation_tx.id.clone(),
        transaction_type: revocation_tx.transaction_type.clone(),
        timestamp: revocation_tx.timestamp,
        sender: revocation_tx.sender.clone(),
        nonce: revocation_tx.nonce,
        chain_id: revocation_tx.chain_id.clone(),
        expires_at: revocation_tx.expires_at,
    };
    
    let revocation_signature = aura_crypto::sign_json(
        issuer_keypair.private_key(),
        &revocation_tx_for_signing
    ).unwrap();
    
    let signed_revocation_tx = Transaction { 
        signature: revocation_signature, 
        ..revocation_tx 
    };
    
    // Process revocation
    {
        let mut bc = blockchain.write().await;
        bc.add_transaction(signed_revocation_tx).unwrap();
        bc.produce_block(issuer_keypair.clone()).unwrap();
    }
    
    // Note: In a real implementation, the revocation registry would be updated
    // based on the blockchain transaction
}

/// Test wallet functionality with multiple identities
#[tokio::test]
async fn test_wallet_multi_identity_management() {
    let wallet_dir = TempDir::new().unwrap();
    let wallet = Wallet::new(wallet_dir.path().to_path_buf()).unwrap();
    
    // Create multiple identities
    let identities = vec![
        ("personal", "Personal Identity"),
        ("work", "Work Identity"),
        ("anonymous", "Anonymous Identity"),
    ];
    
    let mut keypairs = Vec::new();
    let mut dids = Vec::new();
    
    for (id, name) in &identities {
        // Generate keys
        let keypair = wallet.generate_key_pair(id).unwrap();
        keypairs.push(keypair.clone());
        
        // Create DID
        let did = AuraDid::new(id);
        let mut did_doc = DidDocument::new(did.clone());
        
        did_doc.authentication.push(VerificationRelationship::Embedded(
            VerificationMethod {
                id: format!("{}#key-1", did.to_string()),
                controller: did.clone(),
                verification_type: "Ed25519VerificationKey2020".to_string(),
                public_key_multibase: aura_crypto::multibase_encode(
                    keypair.public_key().as_bytes()
                ),
            }
        ));
        
        // Store DID document
        wallet.store_did_document(&did_doc).unwrap();
        dids.push((did, did_doc));
    }
    
    // Verify all identities are stored
    for (did, _) in &dids {
        let retrieved = wallet.get_did_document(did).unwrap();
        assert!(retrieved.is_some());
    }
    
    // Create credentials for different identities
    let issuer_keypair = KeyPair::generate().unwrap();
    let issuer_did = AuraDid::new("issuer");
    
    for ((did, _), keypair) in dids.iter().zip(keypairs.iter()) {
        let credential = VerifiableCredential {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
            id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            credential_type: vec!["VerifiableCredential".to_string()],
            issuer: Issuer::Uri(issuer_did.to_string()),
            issuance_date: chrono::Utc::now(),
            expiration_date: None,
            credential_subject: CredentialSubject {
                id: Some(did.to_string()),
                claims: serde_json::json!({
                    "identity": did.to_string()
                }),
            },
            proof: None,
        };
        
        let signed_credential = aura_crypto::sign_verifiable_credential(
            &credential,
            issuer_keypair.private_key(),
            &issuer_did.to_string(),
            "Ed25519Signature2020"
        ).unwrap();
        
        wallet.store_credential(&signed_credential).unwrap();
    }
    
    // List all credentials
    let all_credentials = wallet.list_credentials().unwrap();
    assert_eq!(all_credentials.len(), identities.len());
    
    // Export and import wallet
    let export_data = wallet.export_wallet("password123").unwrap();
    
    let new_wallet_dir = TempDir::new().unwrap();
    let imported_wallet = Wallet::import_wallet(
        new_wallet_dir.path().to_path_buf(),
        &export_data,
        "password123"
    ).unwrap();
    
    // Verify imported wallet has all data
    let imported_credentials = imported_wallet.list_credentials().unwrap();
    assert_eq!(imported_credentials.len(), identities.len());
}

/// Test blockchain consensus with multiple validators
#[tokio::test]
async fn test_multi_validator_consensus() {
    // Create multiple validators
    let validators: Vec<KeyPair> = (0..3)
        .map(|_| KeyPair::generate().unwrap())
        .collect();
    
    let validator_pubkeys: Vec<PublicKey> = validators
        .iter()
        .map(|kp| kp.public_key().clone())
        .collect();
    
    // Create blockchain with PoA consensus
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(Storage::new(temp_dir.path().to_path_buf()).unwrap());
    let consensus = ProofOfAuthority::new(validator_pubkeys.clone());
    let blockchain = Arc::new(RwLock::new(
        Blockchain::new(storage.clone(), Box::new(consensus)).unwrap()
    ));
    
    // Each validator produces a block
    for (i, validator) in validators.iter().enumerate() {
        // Add some transactions
        for j in 0..3 {
            let did = AuraDid::new(&format!("user-{}-{}", i, j));
            let did_doc = DidDocument::new(did.clone());
            
            let tx = Transaction {
                id: aura_common::TransactionId(uuid::Uuid::new_v4().to_string()),
                transaction_type: TransactionType::RegisterDid { did_document: did_doc },
                timestamp: Timestamp::now(),
                sender: validator.public_key().clone(),
                signature: aura_crypto::Signature(vec![0; 64]),
                nonce: j as u64 + 1,
                chain_id: "test-chain".to_string(),
                expires_at: None,
            };
            
            // Sign transaction
            let tx_for_signing = aura_ledger::transaction::TransactionForSigning {
                id: tx.id.clone(),
                transaction_type: tx.transaction_type.clone(),
                timestamp: tx.timestamp,
                sender: tx.sender.clone(),
                nonce: tx.nonce,
                chain_id: tx.chain_id.clone(),
                expires_at: tx.expires_at,
            };
            
            let signature = aura_crypto::sign_json(
                validator.private_key(),
                &tx_for_signing
            ).unwrap();
            
            let signed_tx = Transaction { signature, ..tx };
            
            let mut bc = blockchain.write().await;
            bc.add_transaction(signed_tx).unwrap();
        }
        
        // Produce block
        {
            let mut bc = blockchain.write().await;
            let block = bc.produce_block(validator.clone()).unwrap();
            assert_eq!(block.transactions.len(), 3);
            assert_eq!(block.header.validator, validator.public_key().clone());
        }
    }
    
    // Verify blockchain state
    {
        let bc = blockchain.read().await;
        let chain_height = bc.get_chain_height();
        assert_eq!(chain_height.0, 3); // 3 blocks produced
        
        // Verify all blocks
        for i in 1..=3 {
            let block = storage.get_block(&BlockNumber(i)).unwrap();
            assert!(block.is_some());
            let block = block.unwrap();
            assert_eq!(block.transactions.len(), 3);
            
            // Verify validator is one of the authorized validators
            assert!(validator_pubkeys.contains(&block.header.validator));
        }
    }
}

/// Test encryption and decryption across wallet and storage
#[tokio::test]
async fn test_cross_crate_encryption() {
    // Generate encryption keys
    let key1 = aura_crypto::generate_encryption_key();
    let key2 = aura_crypto::generate_encryption_key();
    
    // Create sensitive data
    let sensitive_data = serde_json::json!({
        "ssn": "123-45-6789",
        "credit_card": "4111-1111-1111-1111",
        "medical_record": "Patient has condition X"
    });
    
    // Encrypt with first key
    let encrypted1 = aura_crypto::encrypt_json(&key1, &sensitive_data).unwrap();
    
    // Try to decrypt with wrong key (should fail)
    let wrong_decrypt = aura_crypto::decrypt_json::<serde_json::Value>(&key2, &encrypted1);
    assert!(wrong_decrypt.is_err());
    
    // Decrypt with correct key
    let decrypted1: serde_json::Value = aura_crypto::decrypt_json(&key1, &encrypted1).unwrap();
    assert_eq!(decrypted1, sensitive_data);
    
    // Test wallet encryption
    let wallet_dir = TempDir::new().unwrap();
    let wallet = Wallet::new(wallet_dir.path().to_path_buf()).unwrap();
    
    // Generate and encrypt a private key
    let keypair = wallet.generate_key_pair("test").unwrap();
    let private_key_bytes = keypair.private_key().to_bytes();
    
    // Encrypt private key
    let encrypted_key = aura_crypto::encrypt(&key1, &private_key_bytes).unwrap();
    
    // Store encrypted key (simulating storage)
    let storage_dir = TempDir::new().unwrap();
    let storage = Storage::new(storage_dir.path().to_path_buf()).unwrap();
    
    // Store as generic encrypted data
    let key = b"encrypted_private_key";
    storage.put(key, &bincode::encode_to_vec(&encrypted_key, bincode::config::standard()).unwrap()).unwrap();
    
    // Retrieve and decrypt
    let retrieved = storage.get(key).unwrap().unwrap();
    let encrypted_retrieved: aura_crypto::EncryptedData = bincode::decode_from_slice(&retrieved, bincode::config::standard()).unwrap().0;
    
    let decrypted_key = aura_crypto::decrypt(&key1, &encrypted_retrieved).unwrap();
    assert_eq!(&*decrypted_key, &private_key_bytes);
    
    // Verify the key is still valid
    let restored_private = PrivateKey::from_bytes(&decrypted_key).unwrap();
    let restored_public = PublicKey::from(restored_private.clone());
    assert_eq!(restored_public, *keypair.public_key());
}

/// Test complete transaction validation pipeline
#[tokio::test]
async fn test_transaction_validation_pipeline() {
    let keypair = KeyPair::generate().unwrap();
    let did = AuraDid::new("test");
    let did_doc = DidDocument::new(did.clone());
    
    // Create various transaction types
    let tx_types = vec![
        TransactionType::RegisterDid { did_document: did_doc.clone() },
        TransactionType::UpdateDid { 
            did: did.clone(), 
            did_document: did_doc.clone() 
        },
        TransactionType::DeactivateDid { did: did.clone() },
        TransactionType::RegisterSchema {
            schema: CredentialSchema {
                id: "test-schema".to_string(),
                schema_type: "CredentialSchema2023".to_string(),
                name: "Test Schema".to_string(),
                version: "1.0.0".to_string(),
                author: did.clone(),
                created: Timestamp::now(),
                schema: serde_json::json!({}),
            }
        },
        TransactionType::UpdateRevocationList {
            list_id: "test-list".to_string(),
            revoked_indices: vec![1, 2, 3],
        },
    ];
    
    for (nonce, tx_type) in tx_types.into_iter().enumerate() {
        // Create transaction
        let tx = Transaction {
            id: aura_common::TransactionId(uuid::Uuid::new_v4().to_string()),
            transaction_type: tx_type.clone(),
            timestamp: Timestamp::now(),
            sender: keypair.public_key().clone(),
            signature: aura_crypto::Signature(vec![0; 64]),
            nonce: nonce as u64 + 1,
            chain_id: "test-chain".to_string(),
            expires_at: Some(Timestamp::from_unix(Timestamp::now().as_unix() + 3600)),
        };
        
        // Create signing payload
        let tx_for_signing = aura_ledger::transaction::TransactionForSigning {
            id: tx.id.clone(),
            transaction_type: tx.transaction_type.clone(),
            timestamp: tx.timestamp,
            sender: tx.sender.clone(),
            nonce: tx.nonce,
            chain_id: tx.chain_id.clone(),
            expires_at: tx.expires_at,
        };
        
        // Sign transaction
        let signature = aura_crypto::sign_json(keypair.private_key(), &tx_for_signing).unwrap();
        let signed_tx = Transaction { signature: signature.clone(), ..tx };
        
        // Validate transaction
        let validation_result = signed_tx.validate();
        assert!(validation_result.is_ok());
        
        // Verify signature
        let is_valid = aura_crypto::verify_json(
            keypair.public_key(),
            &signature,
            &tx_for_signing
        ).unwrap();
        assert!(is_valid);
        
        // Test expiration
        let mut expired_tx = signed_tx.clone();
        expired_tx.expires_at = Some(Timestamp::from_unix(0)); // Set to past
        assert!(expired_tx.validate().is_err());
        
        // Test invalid chain ID
        let mut wrong_chain_tx = signed_tx.clone();
        wrong_chain_tx.chain_id = "wrong-chain".to_string();
        // Re-verify would fail because signature was for different chain_id
        let wrong_verification = aura_crypto::verify_json(
            keypair.public_key(),
            &wrong_chain_tx.signature,
            &aura_ledger::transaction::TransactionForSigning {
                chain_id: wrong_chain_tx.chain_id.clone(),
                ..tx_for_signing.clone()
            }
        ).unwrap();
        assert!(!wrong_verification);
    }
}