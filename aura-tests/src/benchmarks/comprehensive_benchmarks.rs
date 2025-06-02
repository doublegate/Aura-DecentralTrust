//! Comprehensive performance benchmarks for the Aura system
//!
//! This module contains all benchmarks previously in aura-benchmarks

use aura_common::{types::BlockNumber, AuraDid, DidDocument, Timestamp, TransactionId};
use aura_crypto::{
    encryption::{decrypt, encrypt, generate_encryption_key},
    keys::KeyPair,
    signing::{sign, sign_json, verify},
};
use aura_ledger::{
    blockchain::Block,
    did_registry::DidRegistry,
    storage::Storage,
    transaction::{Transaction, TransactionType},
};
use aura_wallet_core::wallet::AuraWallet;
use criterion::{BenchmarkId, Criterion};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;

/// Benchmark cryptographic operations with extended coverage
pub fn benchmark_extended_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_extended");

    // Encryption key generation
    group.bench_function("encryption_key_generation", |b| {
        b.iter(generate_encryption_key);
    });

    // Encryption benchmarks for various data sizes
    let key = generate_encryption_key();
    for size in [32, 1024, 10240, 102400, 1048576].iter() {
        let data = vec![0u8; *size];

        group.bench_with_input(
            BenchmarkId::new("encrypt_sizes", format!("{size}B")),
            &data,
            |b, data| {
                b.iter(|| encrypt(&key, black_box(data)).unwrap());
            },
        );

        let encrypted = encrypt(&key, &data).unwrap();
        group.bench_with_input(
            BenchmarkId::new("decrypt_sizes", format!("{size}B")),
            &encrypted,
            |b, encrypted| {
                b.iter(|| decrypt(&key, black_box(encrypted)).unwrap());
            },
        );
    }

    // Extended signing benchmarks
    let keypair = KeyPair::generate().unwrap();
    for msg_size in [32, 256, 1024, 8192].iter() {
        let message = vec![0u8; *msg_size];

        group.bench_with_input(
            BenchmarkId::new("sign_sizes", format!("{msg_size}B")),
            &message,
            |b, message| {
                b.iter(|| sign(keypair.private_key(), black_box(message)).unwrap());
            },
        );

        let signature = sign(keypair.private_key(), &message).unwrap();
        group.bench_with_input(
            BenchmarkId::new("verify_sizes", format!("{msg_size}B")),
            &(&message, &signature),
            |b, (message, signature)| {
                b.iter(|| {
                    verify(
                        keypair.public_key(),
                        black_box(message),
                        black_box(signature),
                    )
                    .unwrap()
                });
            },
        );
    }

    group.finish();
}

/// Benchmark DID operations
pub fn benchmark_did_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("did_operations");

    // DID creation with various identifier lengths
    for len in [8, 16, 32, 64].iter() {
        let identifier = "a".repeat(*len);
        group.bench_with_input(
            BenchmarkId::new("did_creation", format!("{len}_chars")),
            &identifier,
            |b, id| {
                b.iter(|| AuraDid::new(black_box(id)));
            },
        );
    }

    // DID document creation with verification methods
    group.bench_function("did_document_with_keys", |b| {
        let did = AuraDid::new("benchmark-user");
        let keypair = KeyPair::generate().unwrap();
        b.iter(|| {
            let mut doc = DidDocument::new(black_box(did.clone()));
            // Add verification methods
            let vm = aura_common::did::VerificationMethod {
                id: format!("{did}#key-1"),
                controller: did.clone(),
                verification_type: "Ed25519VerificationKey2020".to_string(),
                public_key_multibase: format!(
                    "z{}",
                    bs58::encode(keypair.public_key().to_bytes()).into_string()
                ),
            };
            doc.add_verification_method(vm);
            doc
        });
    });

    // DID registry operations at scale
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());
    let registry = Arc::new(RwLock::new(DidRegistry::new(storage.clone())));

    // Benchmark concurrent DID registrations
    group.bench_function("did_concurrent_registration", |b| {
        let mut counter = 0;
        b.iter(|| {
            counter += 1;
            runtime.block_on(async {
                let handles: Vec<_> = (0..10)
                    .map(|i| {
                        let registry = registry.clone();
                        let id = counter * 10 + i;
                        tokio::spawn(async move {
                            let keypair = KeyPair::generate().unwrap();
                            let did = AuraDid::new(&format!("concurrent-user-{id}"));
                            let doc = DidDocument::new(did);

                            let mut reg = registry.write().await;
                            reg.register_did(
                                &doc,
                                keypair.public_key().clone(),
                                BlockNumber(id as u64),
                            )
                            .unwrap();
                        })
                    })
                    .collect();

                for handle in handles {
                    handle.await.unwrap();
                }
            });
        });
    });

    group.finish();
}

/// Benchmark transaction operations with validation
pub fn benchmark_transactions(c: &mut Criterion) {
    let mut group = c.benchmark_group("transactions_extended");

    let keypair = KeyPair::generate().unwrap();
    let did = AuraDid::new("test-user");
    let did_doc = DidDocument::new(did.clone());

    // Transaction creation for different types
    let tx_types = vec![
        (
            "register_did",
            TransactionType::RegisterDid {
                did_document: did_doc.clone(),
            },
        ),
        (
            "update_did",
            TransactionType::UpdateDid {
                did: did.clone(),
                did_document: did_doc.clone(),
            },
        ),
        (
            "deactivate_did",
            TransactionType::DeactivateDid { did: did.clone() },
        ),
    ];

    for (name, tx_type) in tx_types {
        group.bench_function(format!("transaction_create_{name}"), |b| {
            let mut nonce = 0u64;
            b.iter(|| {
                nonce += 1;
                Transaction {
                    id: TransactionId(uuid::Uuid::new_v4().to_string()),
                    transaction_type: tx_type.clone(),
                    timestamp: Timestamp::now(),
                    sender: keypair.public_key().clone(),
                    signature: aura_crypto::Signature(vec![0; 64]),
                    nonce,
                    chain_id: "benchmark".to_string(),
                    expires_at: Some(Timestamp::from_unix(Timestamp::now().as_unix() + 3600)),
                }
            });
        });
    }

    // Transaction JSON signing benchmark
    let tx = Transaction {
        id: TransactionId(uuid::Uuid::new_v4().to_string()),
        transaction_type: TransactionType::RegisterDid {
            did_document: did_doc.clone(),
        },
        timestamp: Timestamp::now(),
        sender: keypair.public_key().clone(),
        signature: aura_crypto::Signature(vec![0; 64]),
        nonce: 1,
        chain_id: "benchmark".to_string(),
        expires_at: None,
    };

    group.bench_function("transaction_json_signing", |b| {
        b.iter(|| {
            let tx_for_signing = aura_ledger::transaction::TransactionForSigning {
                id: tx.id.clone(),
                transaction_type: tx.transaction_type.clone(),
                timestamp: tx.timestamp,
                sender: tx.sender.clone(),
                nonce: tx.nonce,
                chain_id: tx.chain_id.clone(),
                expires_at: tx.expires_at,
            };

            sign_json(keypair.private_key(), black_box(&tx_for_signing)).unwrap()
        });
    });

    // Batch transaction processing
    let transactions: Vec<Transaction> = (0..100)
        .map(|i| Transaction {
            id: TransactionId(format!("batch-tx-{i}")),
            transaction_type: TransactionType::RegisterDid {
                did_document: DidDocument::new(AuraDid::new(&format!("batch-user-{i}"))),
            },
            timestamp: Timestamp::now(),
            sender: keypair.public_key().clone(),
            signature: aura_crypto::Signature(vec![0; 64]),
            nonce: i as u64 + 1,
            chain_id: "benchmark".to_string(),
            expires_at: None,
        })
        .collect();

    group.bench_function("transaction_batch_validation", |b| {
        b.iter(|| {
            for tx in &transactions {
                // Validate transaction fields
                assert!(!tx.id.0.is_empty());
                assert!(tx.nonce > 0);
                assert!(!tx.chain_id.is_empty());

                // Check expiration
                if let Some(expires_at) = tx.expires_at {
                    let _ = expires_at.as_unix() > Timestamp::now().as_unix();
                }
            }
        });
    });

    group.finish();
}

/// Benchmark blockchain operations
pub fn benchmark_blockchain(c: &mut Criterion) {
    let mut group = c.benchmark_group("blockchain_extended");

    // Merkle tree calculation for various transaction counts
    for tx_count in [1, 10, 100, 1000, 10000].iter() {
        let transactions: Vec<Transaction> = (0..*tx_count)
            .map(|i| {
                let did = AuraDid::new(&format!("user-{i}"));
                let doc = DidDocument::new(did);
                Transaction {
                    id: TransactionId(format!("tx-{i}")),
                    transaction_type: TransactionType::RegisterDid { did_document: doc },
                    timestamp: Timestamp::now(),
                    sender: KeyPair::generate().unwrap().public_key().clone(),
                    signature: aura_crypto::Signature(vec![0; 64]),
                    nonce: i as u64 + 1,
                    chain_id: "benchmark".to_string(),
                    expires_at: None,
                }
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("merkle_root", format!("{tx_count}_txs")),
            &transactions,
            |b, transactions| {
                b.iter(|| Block::calculate_merkle_root(black_box(transactions)));
            },
        );
    }

    // Block creation with different transaction counts
    let validator = KeyPair::generate().unwrap();
    for tx_count in [0, 10, 100, 500].iter() {
        let transactions: Vec<Transaction> = (0..*tx_count)
            .map(|i| Transaction {
                id: TransactionId(format!("block-tx-{i}")),
                transaction_type: TransactionType::RegisterDid {
                    did_document: DidDocument::new(AuraDid::new(&format!("block-user-{i}"))),
                },
                timestamp: Timestamp::now(),
                sender: validator.public_key().clone(),
                signature: aura_crypto::Signature(vec![0; 64]),
                nonce: i as u64 + 1,
                chain_id: "benchmark".to_string(),
                expires_at: None,
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("block_creation", format!("{tx_count}_txs")),
            &transactions,
            |b, transactions| {
                b.iter(|| {
                    Block::new(
                        BlockNumber(1),
                        [0u8; 32],
                        black_box(transactions.clone()),
                        validator.public_key().clone(),
                    )
                });
            },
        );
    }

    // Block serialization/deserialization
    let block = Block::new(
        BlockNumber(1),
        [0u8; 32],
        vec![],
        validator.public_key().clone(),
    );

    group.bench_function("block_serialization", |b| {
        b.iter(|| serde_json::to_vec(black_box(&block)).unwrap());
    });

    let serialized = serde_json::to_vec(&block).unwrap();
    group.bench_function("block_deserialization", |b| {
        b.iter(|| serde_json::from_slice::<Block>(black_box(&serialized)).unwrap());
    });

    group.finish();
}

/// Benchmark wallet operations comprehensively
pub fn benchmark_wallet_extended(c: &mut Criterion) {
    let mut group = c.benchmark_group("wallet_extended");

    let mut wallet = AuraWallet::new();
    wallet.initialize("benchmark_password").unwrap();

    // DID creation through wallet
    group.bench_function("wallet_did_creation", |b| {
        b.iter(|| wallet.create_did().unwrap());
    });

    // Credential operations with different sizes
    let _issuer_keypair = KeyPair::generate().unwrap();
    let issuer_did = AuraDid::new("issuer");

    for claim_count in [1, 5, 10, 20].iter() {
        let mut claims = HashMap::new();
        for i in 0..*claim_count {
            claims.insert(
                format!("claim_{i}"),
                serde_json::json!({
                    "value": format!("test_value_{i}"),
                    "timestamp": Timestamp::now(),
                }),
            );
        }

        let credential = aura_common::vc::VerifiableCredential::new(
            issuer_did.clone(),
            AuraDid::new("subject"),
            vec!["TestCredential".to_string()],
            claims,
        );

        group.bench_with_input(
            BenchmarkId::new("credential_storage", format!("{claim_count}_claims")),
            &credential,
            |b, credential| {
                b.iter(|| {
                    wallet
                        .store_credential(black_box(credential.clone()), vec!["test".to_string()])
                        .unwrap()
                });
            },
        );
    }

    // Store credentials for search benchmarks
    for i in 0..100 {
        let mut claims = HashMap::new();
        claims.insert("index".to_string(), serde_json::json!(i));
        claims.insert(
            "type".to_string(),
            serde_json::json!(if i % 2 == 0 { "even" } else { "odd" }),
        );

        let credential = aura_common::vc::VerifiableCredential::new(
            issuer_did.clone(),
            AuraDid::new(&format!("subject-{i}")),
            vec!["TestCredential".to_string()],
            claims,
        );

        let tags = if i % 2 == 0 {
            vec!["even".to_string(), "number".to_string()]
        } else {
            vec!["odd".to_string(), "number".to_string()]
        };

        wallet.store_credential(credential, tags).unwrap();
    }

    // Credential search benchmarks
    // Note: search_credentials_by_tag not implemented yet
    // group.bench_function("credential_search_by_tag", |b| {
    //     b.iter(|| wallet.search_credentials_by_tag(black_box("even")));
    // });

    group.bench_function("credential_list_all", |b| {
        b.iter(|| wallet.list_credentials());
    });

    // Wallet export/import
    let export_data = wallet.export_wallet().unwrap();

    group.bench_function("wallet_export", |b| {
        b.iter(|| wallet.export_wallet().unwrap());
    });

    group.bench_with_input(
        BenchmarkId::new("wallet_import", "full_wallet"),
        &export_data,
        |b, data| {
            b.iter(|| {
                let mut new_wallet = AuraWallet::new();
                new_wallet
                    .import_wallet(black_box(data.clone()), "benchmark_password")
                    .unwrap()
            });
        },
    );

    group.finish();
}

/// Benchmark storage operations at scale
pub fn benchmark_storage_extended(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_extended");

    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());

    // Concurrent storage operations
    let runtime = tokio::runtime::Runtime::new().unwrap();

    group.bench_function("storage_concurrent_writes", |b| {
        let mut counter = 0;
        b.iter(|| {
            counter += 1;
            runtime.block_on(async {
                let handles: Vec<_> = (0..10)
                    .map(|i| {
                        let storage = storage.clone();
                        let id = counter * 10 + i;
                        tokio::spawn(async move {
                            let block = Block::new(
                                BlockNumber(id as u64),
                                [0u8; 32],
                                vec![],
                                KeyPair::generate().unwrap().public_key().clone(),
                            );
                            storage.put_block(&block).unwrap();
                        })
                    })
                    .collect();

                for handle in handles {
                    handle.await.unwrap();
                }
            });
        });
    });

    // Range queries
    runtime.block_on(async {
        // Pre-populate blocks
        for i in 0..1000 {
            let block = Block::new(
                BlockNumber(i),
                [0u8; 32],
                vec![],
                KeyPair::generate().unwrap().public_key().clone(),
            );
            storage.put_block(&block).unwrap();
        }
    });

    // Note: get_blocks_range not implemented yet
    // group.bench_function("storage_block_range_query", |b| {
    //     b.iter(|| {
    //         runtime.block_on(async {
    //             let blocks = storage
    //                 .get_blocks_range(BlockNumber(100), BlockNumber(200))
    //                 .unwrap();
    //             assert_eq!(blocks.len(), 100);
    //         });
    //     });
    // });

    group.finish();
}
