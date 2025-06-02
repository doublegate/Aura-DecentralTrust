use aura_common::{types::BlockNumber, AuraDid, DidDocument, Timestamp, TransactionId};
use aura_crypto::{KeyPair, Signature};
use aura_ledger::{
    blockchain::Block,
    did_registry::DidRegistry,
    storage::Storage,
    transaction::{Transaction, TransactionType},
};
use criterion::{BenchmarkId, Criterion};
use std::hint::black_box;
use std::sync::Arc;
use tempfile::TempDir;

pub fn benchmark_ledger(c: &mut Criterion) {
    let mut group = c.benchmark_group("ledger");

    // Storage benchmarks
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());

    // DID registry benchmarks
    let mut did_registry = DidRegistry::new(storage.clone());
    let keypair = KeyPair::generate().unwrap();
    let did = AuraDid::new("test-user");
    let did_doc = DidDocument::new(did.clone());

    group.bench_function("did_register", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let test_did = AuraDid::new(&format!("user-{counter}"));
            let test_doc = DidDocument::new(test_did.clone());
            did_registry
                .register_did(
                    &test_doc,
                    keypair.public_key().clone(),
                    BlockNumber(counter),
                )
                .unwrap();
        })
    });

    // Register a DID for resolution benchmarks
    did_registry
        .register_did(&did_doc, keypair.public_key().clone(), BlockNumber(1))
        .unwrap();

    group.bench_function("did_resolve", |b| {
        b.iter(|| did_registry.resolve_did(black_box(&did)).unwrap())
    });

    // Transaction creation benchmarks
    group.bench_function("transaction_create", |b| {
        b.iter(|| Transaction {
            id: TransactionId(uuid::Uuid::new_v4().to_string()),
            transaction_type: TransactionType::RegisterDid {
                did_document: did_doc.clone(),
            },
            timestamp: Timestamp::now(),
            sender: keypair.public_key().clone(),
            signature: Signature(vec![0; 64]),
            nonce: 1,
            chain_id: "test".to_string(),
            expires_at: None,
        })
    });

    // Block creation benchmarks
    for tx_count in [10, 100, 1000].iter() {
        let transactions: Vec<Transaction> = (0..*tx_count)
            .map(|i| Transaction {
                id: TransactionId(uuid::Uuid::new_v4().to_string()),
                transaction_type: TransactionType::RegisterDid {
                    did_document: DidDocument::new(AuraDid::new(&format!("user-{i}"))),
                },
                timestamp: Timestamp::now(),
                sender: keypair.public_key().clone(),
                signature: Signature(vec![0; 64]),
                nonce: i as u64 + 1,
                chain_id: "test".to_string(),
                expires_at: None,
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("block_create", tx_count),
            &transactions,
            |b, txs| {
                b.iter(|| {
                    Block::new(
                        BlockNumber(1),
                        [0u8; 32],
                        black_box(txs.clone()),
                        keypair.public_key().clone(),
                    )
                })
            },
        );
    }

    // Storage benchmarks
    let block = Block::new(
        BlockNumber(1),
        [0u8; 32],
        vec![],
        keypair.public_key().clone(),
    );

    group.bench_function("storage_put_block", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let test_block = Block::new(
                BlockNumber(counter),
                [0u8; 32],
                vec![],
                keypair.public_key().clone(),
            );
            storage.put_block(black_box(&test_block)).unwrap()
        })
    });

    storage.put_block(&block).unwrap();

    group.bench_function("storage_get_block", |b| {
        b.iter(|| storage.get_block(black_box(&BlockNumber(1))).unwrap())
    });

    group.finish();
}
