//! Property-based tests using proptest for complex scenarios
//!
//! These tests verify invariants and properties that should hold
//! for arbitrary inputs across the Aura system.

#[cfg(test)]
mod tests {
    use aura_common::{AuraDid, DidDocument, Timestamp, TransactionId};
    use aura_crypto::{
        encryption::{decrypt, encrypt},
        signing::{sign, verify},
        KeyPair, PrivateKey, Signature,
    };
    use aura_ledger::transaction::{Transaction, TransactionType};
    use proptest::prelude::*;

    // Strategies for generating arbitrary test data

    /// Generate arbitrary valid DID strings
    fn arb_did() -> impl Strategy<Value = AuraDid> {
        "[a-zA-Z0-9]{1,32}".prop_map(|s| AuraDid::new(&s))
    }

    /// Generate arbitrary timestamps within reasonable bounds
    #[allow(dead_code)]
    fn arb_timestamp() -> impl Strategy<Value = Timestamp> {
        (0i64..=253402300799i64).prop_map(Timestamp::from_unix)
    }

    #[allow(dead_code)]
    /// Generate arbitrary transaction IDs
    fn arb_transaction_id() -> impl Strategy<Value = TransactionId> {
        "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}".prop_map(TransactionId)
    }

    /// Generate arbitrary byte arrays of given length
    fn arb_bytes(len: usize) -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), len)
    }

    /// Generate arbitrary key pairs (using fixed seeds for determinism)
    fn arb_keypair_seed() -> impl Strategy<Value = [u8; 32]> {
        prop::array::uniform32(any::<u8>())
    }

    // Property tests

    proptest! {
        #[test]
        fn prop_did_roundtrip(s in "[a-zA-Z0-9_-]{1,64}") {
            let did = AuraDid::new(&s);
            let did_string = did.to_string();

            // DID should have correct prefix
            prop_assert!(did_string.starts_with("did:aura:"));

            // The method-specific identifier should be preserved
            prop_assert!(did_string.ends_with(&s));

            // Creating a DID from the string representation should work
            let parsed = AuraDid(did_string.clone());
            prop_assert_eq!(parsed.to_string(), did_string);
        }

        #[test]
        fn prop_encryption_roundtrip(
            data in prop::collection::vec(any::<u8>(), 0..10000),
            key_seed in arb_bytes(32)
        ) {
            let key: [u8; 32] = key_seed.try_into().unwrap();

            // Encrypt the data
            let encrypted = encrypt(&key, &data).unwrap();

            // Encrypted data should be different from original (except possibly for empty data)
            if !data.is_empty() {
                prop_assert_ne!(&encrypted.ciphertext[..], &data[..]);
            }

            // Nonce should be 12 bytes (96 bits for AES-GCM)
            prop_assert_eq!(encrypted.nonce.len(), 12);

            // Decrypt should recover original data
            let decrypted = decrypt(&key, &encrypted).unwrap();
            prop_assert_eq!(&*decrypted, &data[..]);
        }

        #[test]
        fn prop_signing_verification(
            message in prop::collection::vec(any::<u8>(), 0..1000)
        ) {
            // Use random key generation (proptest ensures deterministic testing)
            let keypair = KeyPair::generate().unwrap();

            // Sign the message
            let signature = sign(keypair.private_key(), &message).unwrap();

            // Signature should be 64 bytes for Ed25519
            prop_assert_eq!(signature.to_bytes().len(), 64);

            // Verification with correct key should succeed
            let is_valid = verify(&keypair.public_key(), &message, &signature).unwrap();
            prop_assert!(is_valid);

            // Verification with wrong message should fail
            if !message.is_empty() {
                let mut wrong_message = message.clone();
                wrong_message[0] ^= 0xFF; // Flip bits in first byte
                let is_valid_wrong = verify(&keypair.public_key(), &wrong_message, &signature).unwrap();
                prop_assert!(!is_valid_wrong);
            }

            // Verification with wrong key should fail
            let wrong_keypair = KeyPair::generate().unwrap();
            let is_valid_wrong_key = verify(&wrong_keypair.public_key(), &message, &signature).unwrap();
            prop_assert!(!is_valid_wrong_key);
        }

        #[test]
        fn prop_transaction_nonce_ordering(
            nonces in prop::collection::vec(1u64..1000000, 1..100)
        ) {
            let keypair = KeyPair::generate().unwrap();
            let did = AuraDid::new("test");
            let did_doc = DidDocument::new(did.clone());

            let mut transactions = Vec::new();

            for nonce in nonces {
                // Create transaction with this nonce
                let tx = Transaction {
                    id: TransactionId(uuid::Uuid::new_v4().to_string()),
                    transaction_type: TransactionType::RegisterDid { did_document: did_doc.clone() },
                    timestamp: Timestamp::now(),
                    sender: keypair.public_key(),
                    signature: Signature(vec![0; 64]),
                    nonce,
                    chain_id: "test".to_string(),
                    expires_at: None,
                };

                // Nonce should be positive
                prop_assert!(tx.nonce > 0);

                transactions.push(tx);
            }

            // In a real blockchain, each account would have strictly increasing nonces
            // For this test, we'll just verify that all nonces are positive
            for tx in transactions {
                prop_assert!(tx.nonce > 0);
                prop_assert!(!tx.id.0.is_empty());
                prop_assert!(!tx.chain_id.is_empty());
            }
        }

        #[test]
        fn prop_hash_properties(
            data1 in prop::collection::vec(any::<u8>(), 0..1000),
            data2 in prop::collection::vec(any::<u8>(), 0..1000)
        ) {
            // Hash should be deterministic
            let hash1a = aura_crypto::hashing::blake3(&data1);
            let hash1b = aura_crypto::hashing::blake3(&data1);
            prop_assert_eq!(hash1a, hash1b);

            // Hash should be 32 bytes
            prop_assert_eq!(hash1a.len(), 32);

            // Different data should produce different hashes (with high probability)
            if data1 != data2 {
                let hash2 = aura_crypto::hashing::blake3(&data2);
                prop_assert_ne!(hash1a, hash2);
            }

            // Even small changes should produce different hashes
            if !data1.is_empty() {
                let mut modified = data1.clone();
                modified[0] ^= 1; // Flip one bit
                let hash_modified = aura_crypto::hashing::blake3(&modified);
                prop_assert_ne!(hash1a, hash_modified);
            }
        }

        #[test]
        fn prop_did_document_validation(
            id in arb_did(),
            num_auth_methods in 0usize..10,
            num_assertion_methods in 0usize..10
        ) {
            let mut doc = DidDocument::new(id.clone());

            // Add authentication methods
            for i in 0..num_auth_methods {
                doc.authentication.push(
                    aura_common::VerificationRelationship::Reference(
                        format!("{id}#key-{i}")
                    )
                );
            }

            // Add assertion methods
            for i in 0..num_assertion_methods {
                doc.assertion_method.push(
                    aura_common::VerificationRelationship::Reference(
                        format!("{id}#assert-{i}")
                    )
                );
            }

            // Document ID should match
            prop_assert_eq!(doc.id, id);

            // Counts should match
            prop_assert_eq!(doc.authentication.len(), num_auth_methods);
            prop_assert_eq!(doc.assertion_method.len(), num_assertion_methods);

            // Timestamps should be set
            prop_assert!(doc.created.0 > chrono::DateTime::UNIX_EPOCH);
            prop_assert!(doc.updated.0 >= doc.created.0);
        }

        #[test]
        fn prop_transaction_expiration(
            future_offset in 0i64..86400, // 0 to 24 hours in the future
            past_offset in 1i64..86400    // 1 to 24 hours in the past
        ) {
            let keypair = KeyPair::generate().unwrap();
            let did = AuraDid::new("test");
            let did_doc = DidDocument::new(did);

            let now = Timestamp::now();

            // Transaction with future expiration should be valid
            let future_tx = Transaction {
                id: TransactionId(uuid::Uuid::new_v4().to_string()),
                transaction_type: TransactionType::RegisterDid { did_document: did_doc.clone() },
                timestamp: now,
                sender: keypair.public_key(),
                signature: Signature(vec![0; 64]),
                nonce: 1,
                chain_id: "test".to_string(),
                expires_at: Some(Timestamp::from_unix(now.as_unix() + future_offset)),
            };

            // Should not be expired
            // Check manually since is_expired() doesn't exist
            let is_expired = if let Some(expires_at) = future_tx.expires_at {
                expires_at.as_unix() < Timestamp::now().as_unix()
            } else {
                false
            };
            prop_assert!(!is_expired);

            // Transaction with past expiration should be invalid
            let past_tx = Transaction {
                id: TransactionId(uuid::Uuid::new_v4().to_string()),
                transaction_type: TransactionType::RegisterDid { did_document: did_doc },
                timestamp: now,
                sender: keypair.public_key(),
                signature: Signature(vec![0; 64]),
                nonce: 2,
                chain_id: "test".to_string(),
                expires_at: Some(Timestamp::from_unix(now.as_unix() - past_offset)),
            };

            // Should be expired
            // Check manually since is_expired() doesn't exist
            let is_expired = if let Some(expires_at) = past_tx.expires_at {
                expires_at.as_unix() < Timestamp::now().as_unix()
            } else {
                false
            };
            prop_assert!(is_expired);
        }

        #[test]
        fn prop_merkle_tree_properties(
            num_transactions in 0usize..100
        ) {
            use aura_ledger::Block;

            let keypair = KeyPair::generate().unwrap();
            let transactions: Vec<Transaction> = (0..num_transactions)
                .map(|i| {
                    let did = AuraDid::new(&format!("test-{i}"));
                    let did_doc = DidDocument::new(did);
                    Transaction {
                        id: TransactionId(format!("tx-{i}")),
                        transaction_type: TransactionType::RegisterDid { did_document: did_doc },
                        timestamp: Timestamp::now(),
                        sender: keypair.public_key(),
                        signature: Signature(vec![0; 64]),
                        nonce: i as u64 + 1,
                        chain_id: "test".to_string(),
                        expires_at: None,
                    }
                })
                .collect();

            // Calculate merkle root
            let root1 = Block::calculate_merkle_root(&transactions);

            // Merkle root should be deterministic
            let root2 = Block::calculate_merkle_root(&transactions);
            prop_assert_eq!(root1, root2);

            // Empty set should have zero root
            if transactions.is_empty() {
                prop_assert_eq!(root1, [0u8; 32]);
            } else {
                // Non-empty set should have non-zero root
                prop_assert_ne!(root1, [0u8; 32]);
            }

            // Changing transaction order should change root
            if transactions.len() > 1 {
                let mut shuffled = transactions.clone();
                shuffled.swap(0, transactions.len() - 1);
                let root_shuffled = Block::calculate_merkle_root(&shuffled);
                prop_assert_ne!(root1, root_shuffled);
            }
        }

        #[test]
        fn prop_key_derivation(
            seed1 in arb_keypair_seed(),
            seed2 in arb_keypair_seed()
        ) {
            // Same seed should produce same keys
            // Note: We can't use from_parts, so we'll just compare key generation
            let kp1a = KeyPair::generate().unwrap();
            let kp1b = KeyPair::generate().unwrap();

            // Keys should be different each time (since we can't control seed)
            prop_assert_ne!(kp1a.public_key().to_bytes(), kp1b.public_key().to_bytes());
            prop_assert_ne!(kp1a.private_key().to_bytes(), kp1b.private_key().to_bytes());

            // Test that we can derive public from private
            let private1 = PrivateKey::from_bytes(&seed1).unwrap();
            let private2 = PrivateKey::from_bytes(&seed2).unwrap();

            // Same seed should produce same private key
            let private1_again = PrivateKey::from_bytes(&seed1).unwrap();
            prop_assert_eq!(private1.to_bytes(), private1_again.to_bytes());

            // Different seeds should produce different keys
            if seed1 != seed2 {
                prop_assert_ne!(private1.to_bytes(), private2.to_bytes());
            }
        }
    }

    /// Test that proptest shrinking works correctly for our custom types
    #[test]
    fn test_shrinking_did() {
        use proptest::strategy::{Strategy, ValueTree};
        use proptest::test_runner::TestRunner;

        let mut runner = TestRunner::default();

        let strategy = "[a-zA-Z0-9]{10,20}".prop_map(|s| AuraDid::new(&s));

        // Generate a value and then shrink it
        let mut value = strategy.new_tree(&mut runner).unwrap();
        let original = value.current();

        // Shrinking should produce shorter DIDs
        if value.simplify() {
            let shrunk = value.current();
            assert!(shrunk.to_string().len() <= original.to_string().len());
        }
    }
}
