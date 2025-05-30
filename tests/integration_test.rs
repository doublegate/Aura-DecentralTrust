use aura_common::*;
use aura_crypto::*;
use aura_ledger::*;
use aura_wallet_core::*;
use std::collections::HashMap;

#[test]
fn test_did_creation_and_management() {
    // Initialize wallet
    let mut wallet = AuraWallet::new();
    wallet.initialize("test_password").unwrap();
    
    // Create DID
    let (did, did_doc, key_pair) = wallet.create_did().unwrap();
    
    // Verify DID format
    assert!(did.to_string().starts_with("did:aura:"));
    
    // Verify DID document
    assert_eq!(did_doc.id, did);
    assert!(!did_doc.verification_method.is_empty());
    assert!(!did_doc.authentication.is_empty());
}

#[test]
fn test_credential_issuance_and_verification() {
    // Create issuer wallet
    let mut issuer_wallet = AuraWallet::new();
    issuer_wallet.initialize("issuer_password").unwrap();
    let (issuer_did, _, _) = issuer_wallet.create_did().unwrap();
    
    // Create holder wallet
    let mut holder_wallet = AuraWallet::new();
    holder_wallet.initialize("holder_password").unwrap();
    let (holder_did, _, _) = holder_wallet.create_did().unwrap();
    
    // Create credential
    let mut claims = HashMap::new();
    claims.insert("name".to_string(), serde_json::json!("Test User"));
    claims.insert("age".to_string(), serde_json::json!(25));
    
    let credential = VerifiableCredential::new(
        issuer_did.clone(),
        holder_did.clone(),
        vec!["TestCredential".to_string()],
        claims,
    );
    
    // Store in holder's wallet
    let cred_id = holder_wallet.store_credential(
        credential,
        vec!["test".to_string()],
    ).unwrap();
    
    // Verify credential was stored
    let stored_cred = holder_wallet.get_credential(&cred_id).unwrap();
    assert!(stored_cred.is_some());
}

#[test]
fn test_presentation_creation() {
    // Setup wallets and credential
    let mut holder_wallet = AuraWallet::new();
    holder_wallet.initialize("holder_password").unwrap();
    let (holder_did, _, _) = holder_wallet.create_did().unwrap();
    
    let mut issuer_wallet = AuraWallet::new();
    issuer_wallet.initialize("issuer_password").unwrap();
    let (issuer_did, _, _) = issuer_wallet.create_did().unwrap();
    
    // Create and store credential
    let mut claims = HashMap::new();
    claims.insert("test".to_string(), serde_json::json!("value"));
    
    let credential = VerifiableCredential::new(
        issuer_did,
        holder_did.clone(),
        vec!["TestCredential".to_string()],
        claims,
    );
    
    let cred_id = holder_wallet.store_credential(
        credential,
        vec!["test".to_string()],
    ).unwrap();
    
    // Create presentation
    let presentation = holder_wallet.create_presentation(
        &holder_did,
        vec![cred_id],
        Some("challenge".to_string()),
        Some("domain.com".to_string()),
    ).unwrap();
    
    // Verify presentation structure
    assert_eq!(presentation.holder, holder_did);
    assert_eq!(presentation.verifiable_credential.len(), 1);
    assert!(presentation.proof.is_some());
}

#[test]
fn test_blockchain_block_creation() {
    use aura_ledger::{Block, BlockNumber, Transaction};
    
    // Create a genesis block
    let genesis = Block::new(
        BlockNumber(0),
        [0u8; 32],
        vec![],
        PublicKey::from_bytes(&[0u8; 32]).unwrap(),
    );
    
    // Verify block hash
    let hash = genesis.hash();
    assert_ne!(hash, [0u8; 32]);
    
    // Create next block
    let block1 = Block::new(
        BlockNumber(1),
        hash,
        vec![],
        PublicKey::from_bytes(&[1u8; 32]).unwrap(),
    );
    
    assert_eq!(block1.header.block_number.0, 1);
    assert_eq!(block1.header.previous_hash, hash);
}

#[test]
fn test_proof_of_authority_consensus() {
    use aura_ledger::consensus::ProofOfAuthority;
    
    // Create validators
    let key1 = KeyPair::generate().unwrap();
    let key2 = KeyPair::generate().unwrap();
    
    let mut poa = ProofOfAuthority::new(vec![
        key1.public_key().clone(),
        key2.public_key().clone(),
    ]);
    
    // Test validator checking
    assert!(poa.is_validator(key1.public_key()));
    assert!(poa.is_validator(key2.public_key()));
    
    // Test block validator selection
    let validator = poa.get_block_validator(&BlockNumber(0)).unwrap();
    assert!(poa.is_validator(validator));
}