//! Performance benchmarks for critical paths in the Aura system
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use aura_common::{AuraDid, DidDocument, Timestamp, TransactionId};
use aura_crypto::{KeyPair, generate_encryption_key, encrypt, decrypt, sign, verify};
use aura_ledger::{
    Block, BlockNumber, Storage, Blockchain, DidRegistry,
    consensus::ProofOfAuthority,
    transaction::{Transaction, TransactionType},
};
use aura_wallet_core::Wallet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tempfile::TempDir;

/// Benchmark cryptographic operations
fn crypto_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("cryptography");
    
    // Key generation
    group.bench_function("keypair_generation", |b| {
        b.iter(|| {
            KeyPair::generate().unwrap()
        });
    });
    
    // Encryption key generation
    group.bench_function("encryption_key_generation", |b| {
        b.iter(|| {
            generate_encryption_key()
        });
    });
    
    // Encryption benchmarks for various data sizes
    let key = generate_encryption_key();
    for size in [32, 1024, 10240, 102400, 1048576].iter() {
        let data = vec![0u8; *size];
        
        group.bench_with_input(
            BenchmarkId::new("encrypt", format!("{}B", size)),
            &data,
            |b, data| {
                b.iter(|| {
                    encrypt(&key, black_box(data)).unwrap()
                });
            }
        );
        
        let encrypted = encrypt(&key, &data).unwrap();
        group.bench_with_input(
            BenchmarkId::new("decrypt", format!("{}B", size)),
            &encrypted,
            |b, encrypted| {
                b.iter(|| {
                    decrypt(&key, black_box(encrypted)).unwrap()
                });
            }
        );
    }
    
    // Signing and verification
    let keypair = KeyPair::generate().unwrap();
    let message = b"This is a test message for signing benchmarks";
    
    group.bench_function("sign_message", |b| {
        b.iter(|| {
            sign(keypair.private_key(), black_box(message)).unwrap()
        });
    });
    
    let signature = sign(keypair.private_key(), message).unwrap();
    group.bench_function("verify_signature", |b| {
        b.iter(|| {
            verify(keypair.public_key(), &signature, black_box(message)).unwrap()
        });
    });
    
    group.finish();
}

/// Benchmark DID operations
fn did_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("did_operations");
    
    // DID creation
    group.bench_function("did_creation", |b| {
        let mut counter = 0;
        b.iter(|| {
            counter += 1;
            AuraDid::new(&format!("user{}", counter))
        });
    });
    
    // DID document creation
    group.bench_function("did_document_creation", |b| {
        let did = AuraDid::new("benchmark-user");
        b.iter(|| {
            DidDocument::new(black_box(did.clone()))
        });
    });
    
    // DID registry operations
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(Storage::new(temp_dir.path().to_path_buf()).unwrap());
    let registry = Arc::new(RwLock::new(DidRegistry::new(storage)));
    
    group.bench_function("did_registration", |b| {
        let mut counter = 0;
        b.iter(|| {
            counter += 1;
            let did = AuraDid::new(&format!("bench-user-{}", counter));
            let doc = DidDocument::new(did);
            
            runtime.block_on(async {
                let mut reg = registry.write().await;
                reg.register_did(doc, BlockNumber(counter)).unwrap();
            });
        });
    });
    
    // Pre-register some DIDs for resolution benchmark
    runtime.block_on(async {
        let mut reg = registry.write().await;
        for i in 0..1000 {
            let did = AuraDid::new(&format!("lookup-user-{}", i));
            let doc = DidDocument::new(did);
            reg.register_did(doc, BlockNumber(i)).unwrap();
        }
    });
    
    group.bench_function("did_resolution", |b| {
        let did = AuraDid::new("lookup-user-500");
        b.iter(|| {
            runtime.block_on(async {
                let reg = registry.read().await;
                reg.resolve_did(black_box(&did)).unwrap()
            })
        });
    });
    
    group.finish();
}

/// Benchmark transaction operations
fn transaction_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("transactions");
    
    let keypair = KeyPair::generate().unwrap();
    let did = AuraDid::new("test-user");
    let did_doc = DidDocument::new(did);
    
    // Transaction creation
    group.bench_function("transaction_creation", |b| {
        let mut nonce = 0u64;
        b.iter(|| {
            nonce += 1;
            Transaction {
                id: TransactionId(uuid::Uuid::new_v4().to_string()),
                transaction_type: TransactionType::RegisterDid { 
                    did_document: did_doc.clone() 
                },
                timestamp: Timestamp::now(),
                sender: keypair.public_key().clone(),
                signature: aura_crypto::Signature(vec![0; 64]),
                nonce,
                chain_id: "benchmark".to_string(),
                expires_at: None,
            }
        });
    });
    
    // Transaction signing
    let tx = Transaction {
        id: TransactionId(uuid::Uuid::new_v4().to_string()),
        transaction_type: TransactionType::RegisterDid { 
            did_document: did_doc.clone() 
        },
        timestamp: Timestamp::now(),
        sender: keypair.public_key().clone(),
        signature: aura_crypto::Signature(vec![0; 64]),
        nonce: 1,
        chain_id: "benchmark".to_string(),
        expires_at: None,
    };
    
    group.bench_function("transaction_signing", |b| {
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
            
            aura_crypto::sign_json(keypair.private_key(), black_box(&tx_for_signing)).unwrap()
        });
    });
    
    // Transaction validation
    let signed_tx = {
        let tx_for_signing = aura_ledger::transaction::TransactionForSigning {
            id: tx.id.clone(),
            transaction_type: tx.transaction_type.clone(),
            timestamp: tx.timestamp,
            sender: tx.sender.clone(),
            nonce: tx.nonce,
            chain_id: tx.chain_id.clone(),
            expires_at: tx.expires_at,
        };
        let signature = aura_crypto::sign_json(keypair.private_key(), &tx_for_signing).unwrap();
        Transaction { signature, ..tx }
    };
    
    group.bench_function("transaction_validation", |b| {
        b.iter(|| {
            black_box(&signed_tx).validate().unwrap()
        });
    });
    
    group.finish();
}

/// Benchmark blockchain operations
fn blockchain_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("blockchain");
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    
    // Merkle tree calculation for various transaction counts
    for tx_count in [1, 10, 100, 1000].iter() {
        let transactions: Vec<Transaction> = (0..*tx_count)
            .map(|i| {
                let did = AuraDid::new(&format!("user-{}", i));
                let doc = DidDocument::new(did);
                Transaction {
                    id: TransactionId(format!("tx-{}", i)),
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
            BenchmarkId::new("merkle_root_calculation", tx_count),
            &transactions,
            |b, transactions| {
                b.iter(|| {
                    Block::calculate_merkle_root(black_box(transactions))
                });
            }
        );
    }
    
    // Block production
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(Storage::new(temp_dir.path().to_path_buf()).unwrap());
    let validator = KeyPair::generate().unwrap();
    let consensus = ProofOfAuthority::new(vec![validator.public_key().clone()]);
    let blockchain = Arc::new(RwLock::new(
        Blockchain::new(storage.clone(), Box::new(consensus)).unwrap()
    ));
    
    // Add some transactions
    runtime.block_on(async {
        let mut bc = blockchain.write().await;
        for i in 0..100 {
            let did = AuraDid::new(&format!("bench-user-{}", i));
            let doc = DidDocument::new(did);
            let tx = Transaction {
                id: TransactionId(format!("bench-tx-{}", i)),
                transaction_type: TransactionType::RegisterDid { did_document: doc },
                timestamp: Timestamp::now(),
                sender: validator.public_key().clone(),
                signature: aura_crypto::Signature(vec![0; 64]),
                nonce: i as u64 + 1,
                chain_id: "benchmark".to_string(),
                expires_at: None,
            };
            bc.add_transaction(tx).unwrap();
        }
    });
    
    group.bench_function("block_production_100tx", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let mut bc = blockchain.write().await;
                bc.produce_block(validator.clone()).unwrap()
            })
        });
    });
    
    // Block validation
    let block = runtime.block_on(async {
        let bc = blockchain.read().await;
        bc.get_latest_block().unwrap()
    });
    
    group.bench_function("block_validation", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let bc = blockchain.read().await;
                bc.validate_block(black_box(&block))
            })
        });
    });
    
    group.finish();
}

/// Benchmark wallet operations
fn wallet_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("wallet");
    
    let temp_dir = TempDir::new().unwrap();
    let wallet = Wallet::new(temp_dir.path().to_path_buf()).unwrap();
    
    // Key generation in wallet
    group.bench_function("wallet_key_generation", |b| {
        let mut counter = 0;
        b.iter(|| {
            counter += 1;
            wallet.generate_key_pair(&format!("key-{}", counter)).unwrap()
        });
    });
    
    // Credential storage
    let issuer_keypair = KeyPair::generate().unwrap();
    let issuer_did = AuraDid::new("issuer");
    
    group.bench_function("credential_storage", |b| {
        let mut counter = 0;
        b.iter(|| {
            counter += 1;
            let credential = aura_common::vc::VerifiableCredential {
                context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
                id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                credential_type: vec!["VerifiableCredential".to_string()],
                issuer: aura_common::vc::Issuer::Uri(issuer_did.to_string()),
                issuance_date: chrono::Utc::now(),
                expiration_date: None,
                credential_subject: aura_common::vc::CredentialSubject {
                    id: Some(format!("did:aura:subject-{}", counter)),
                    claims: serde_json::json!({"test": "data"}),
                },
                proof: None,
            };
            
            let signed = aura_crypto::sign_verifiable_credential(
                &credential,
                issuer_keypair.private_key(),
                &issuer_did.to_string(),
                "Ed25519Signature2020"
            ).unwrap();
            
            wallet.store_credential(&signed).unwrap()
        });
    });
    
    // Pre-store some credentials for retrieval benchmark
    for i in 0..100 {
        let credential = aura_common::vc::VerifiableCredential {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
            id: format!("urn:uuid:bench-cred-{}", i),
            credential_type: vec!["VerifiableCredential".to_string()],
            issuer: aura_common::vc::Issuer::Uri(issuer_did.to_string()),
            issuance_date: chrono::Utc::now(),
            expiration_date: None,
            credential_subject: aura_common::vc::CredentialSubject {
                id: Some(format!("did:aura:bench-subject-{}", i)),
                claims: serde_json::json!({"index": i}),
            },
            proof: None,
        };
        
        let signed = aura_crypto::sign_verifiable_credential(
            &credential,
            issuer_keypair.private_key(),
            &issuer_did.to_string(),
            "Ed25519Signature2020"
        ).unwrap();
        
        wallet.store_credential(&signed).unwrap();
    }
    
    group.bench_function("credential_retrieval", |b| {
        let id = "urn:uuid:bench-cred-50";
        b.iter(|| {
            wallet.get_credential(black_box(id)).unwrap()
        });
    });
    
    group.bench_function("credential_listing", |b| {
        b.iter(|| {
            wallet.list_credentials().unwrap()
        });
    });
    
    group.finish();
}

/// Benchmark storage operations
fn storage_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage");
    
    let temp_dir = TempDir::new().unwrap();
    let storage = Storage::new(temp_dir.path().to_path_buf()).unwrap();
    
    // Key-value storage benchmarks
    for size in [32, 1024, 10240, 102400].iter() {
        let key = format!("bench_key_{}", size).into_bytes();
        let value = vec![0u8; *size];
        
        group.bench_with_input(
            BenchmarkId::new("storage_put", format!("{}B", size)),
            &value,
            |b, value| {
                b.iter(|| {
                    storage.put(&key, black_box(value)).unwrap()
                });
            }
        );
        
        // Store the value for get benchmark
        storage.put(&key, &value).unwrap();
        
        group.bench_with_input(
            BenchmarkId::new("storage_get", format!("{}B", size)),
            &key,
            |b, key| {
                b.iter(|| {
                    storage.get(black_box(key)).unwrap()
                });
            }
        );
    }
    
    // Batch operations
    let batch_data: Vec<(Vec<u8>, Vec<u8>)> = (0..100)
        .map(|i| {
            (format!("batch_key_{}", i).into_bytes(), vec![0u8; 1024])
        })
        .collect();
    
    group.bench_function("storage_batch_put_100", |b| {
        b.iter(|| {
            for (key, value) in &batch_data {
                storage.put(key, value).unwrap();
            }
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    crypto_benchmarks,
    did_benchmarks,
    transaction_benchmarks,
    blockchain_benchmarks,
    wallet_benchmarks,
    storage_benchmarks
);

criterion_main!(benches);