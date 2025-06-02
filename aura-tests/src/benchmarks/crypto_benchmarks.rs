use aura_crypto::{
    encryption::{decrypt, encrypt, generate_encryption_key},
    hashing::{blake3, sha256},
    keys::KeyPair,
    signing::{sign, verify},
};
use criterion::{BenchmarkId, Criterion};
use std::hint::black_box;

pub fn benchmark_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto");

    // Key generation
    group.bench_function("keypair_generate", |b| b.iter(KeyPair::generate));

    // Signing benchmarks
    let keypair = KeyPair::generate().unwrap();
    let message = b"Hello, World!";

    group.bench_function("sign_message", |b| {
        b.iter(|| sign(keypair.private_key(), black_box(message)))
    });

    // Verification benchmarks
    let signature = sign(keypair.private_key(), message).unwrap();
    group.bench_function("verify_signature", |b| {
        b.iter(|| {
            verify(
                keypair.public_key(),
                black_box(message),
                black_box(&signature),
            )
        })
    });

    // Encryption benchmarks
    let key = generate_encryption_key();
    for size in [100, 1_000, 10_000, 100_000].iter() {
        let data = vec![0u8; *size];
        group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
            b.iter(|| encrypt(&key, black_box(data)))
        });

        let encrypted = encrypt(&key, &data).unwrap();
        group.bench_with_input(
            BenchmarkId::new("decrypt", size),
            &encrypted,
            |b, encrypted| b.iter(|| decrypt(&key, black_box(encrypted))),
        );
    }

    // Hashing benchmarks
    group.bench_function("sha256_small", |b| {
        b.iter(|| sha256(black_box(b"Hello, World!")))
    });

    group.bench_function("blake3_small", |b| {
        b.iter(|| blake3(black_box(b"Hello, World!")))
    });

    let large_data = vec![0u8; 1_000_000];
    group.bench_function("sha256_1mb", |b| b.iter(|| sha256(black_box(&large_data))));

    group.bench_function("blake3_1mb", |b| b.iter(|| blake3(black_box(&large_data))));

    group.finish();
}
