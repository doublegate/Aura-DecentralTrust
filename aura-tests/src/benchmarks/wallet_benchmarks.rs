use aura_common::AuraDid;
use aura_wallet_core::wallet::AuraWallet;
use criterion::Criterion;
use std::collections::HashMap;
use std::hint::black_box;

pub fn benchmark_wallet(c: &mut Criterion) {
    let mut group = c.benchmark_group("wallet");

    // Wallet initialization
    group.bench_function("wallet_initialize", |b| {
        b.iter_with_setup(AuraWallet::new, |mut wallet| {
            wallet.initialize(black_box("test_password")).unwrap();
        })
    });

    // Create an initialized wallet for other benchmarks
    let mut wallet = AuraWallet::new();
    wallet.initialize("test_password").unwrap();

    // DID creation
    group.bench_function("wallet_create_did", |b| {
        b.iter(|| wallet.create_did().unwrap())
    });

    // Create some test data
    let (holder_did, _, _) = wallet.create_did().unwrap();
    let issuer_did = AuraDid::new("issuer");

    // Credential storage
    group.bench_function("wallet_store_credential", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let mut claims = HashMap::new();
            claims.insert("id".to_string(), serde_json::json!(counter));
            claims.insert("name".to_string(), serde_json::json!("Test User"));

            let credential = aura_common::VerifiableCredential::new(
                issuer_did.clone(),
                holder_did.clone(),
                vec!["TestCredential".to_string()],
                claims,
            );

            wallet
                .store_credential(credential, vec!["test".to_string()])
                .unwrap();
        })
    });

    // Store some credentials for retrieval benchmarks
    for i in 0..100 {
        let mut claims = HashMap::new();
        claims.insert("id".to_string(), serde_json::json!(i));
        claims.insert("name".to_string(), serde_json::json!("Test User"));

        let mut credential = aura_common::VerifiableCredential::new(
            issuer_did.clone(),
            holder_did.clone(),
            vec!["TestCredential".to_string()],
            claims,
        );
        credential.id = Some(format!("cred-{i}"));

        wallet
            .store_credential(credential, vec!["test".to_string()])
            .unwrap();
    }

    // Credential retrieval
    group.bench_function("wallet_get_credential", |b| {
        b.iter(|| wallet.get_credential(black_box("cred-50")).unwrap())
    });

    // List all credentials
    group.bench_function("wallet_list_credentials", |b| {
        b.iter(|| wallet.list_credentials())
    });

    // Find credentials by type
    group.bench_function("wallet_find_by_type", |b| {
        b.iter(|| wallet.find_credentials_by_type(black_box("TestCredential")))
    });

    // Export wallet
    group.bench_function("wallet_export", |b| {
        b.iter(|| wallet.export_wallet().unwrap())
    });

    group.finish();
}
