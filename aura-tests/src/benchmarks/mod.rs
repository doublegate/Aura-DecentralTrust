//! Performance benchmarks for Aura DecentralTrust
//!
//! These benchmarks measure the performance of critical operations
//! Includes all benchmarks from the former aura-benchmarks crate

use criterion::{criterion_group, criterion_main};

mod comprehensive_benchmarks;
mod crypto_benchmarks;
mod ledger_benchmarks;
mod wallet_benchmarks;

// Original benchmarks
criterion_group!(crypto_benches, crypto_benchmarks::benchmark_crypto);
criterion_group!(ledger_benches, ledger_benchmarks::benchmark_ledger);
criterion_group!(wallet_benches, wallet_benchmarks::benchmark_wallet);

// Extended benchmarks from aura-benchmarks
criterion_group!(
    extended_crypto_benches,
    comprehensive_benchmarks::benchmark_extended_crypto
);
criterion_group!(
    did_benches,
    comprehensive_benchmarks::benchmark_did_operations
);
criterion_group!(
    transaction_benches,
    comprehensive_benchmarks::benchmark_transactions
);
criterion_group!(
    blockchain_benches,
    comprehensive_benchmarks::benchmark_blockchain
);
criterion_group!(
    wallet_extended_benches,
    comprehensive_benchmarks::benchmark_wallet_extended
);
criterion_group!(
    storage_benches,
    comprehensive_benchmarks::benchmark_storage_extended
);

criterion_main!(
    crypto_benches,
    ledger_benches,
    wallet_benches,
    extended_crypto_benches,
    did_benches,
    transaction_benches,
    blockchain_benches,
    wallet_extended_benches,
    storage_benches
);
