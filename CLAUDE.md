# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Aura is a decentralized identity and trust network that combines Decentralized Identifiers (DIDs), Verifiable Credentials (VCs), and Zero-Knowledge Proofs (ZKPs) to enable self-sovereign identity and user-controlled data management.

## Architecture

The system consists of four main components:

1. **Aura Ledger** (`aura-ledger`) - A specialized DLT for DIDs and credential metadata (Rust)
2. **Aura Identity Wallets** (`aura-wallet-core`) - User agents for managing identity and credentials (Rust core + JS/TS frontend)
3. **Aura Nodes** (`aura-nodes`) - Network participants maintaining the ledger (Rust)
4. **Off-Chain Storage** - User-controlled encrypted storage for actual credentials and PII

## Development Setup

**Note:** This project is in the initial planning phase. No build infrastructure exists yet.

### To initialize the Rust workspace:

```bash
# Create workspace root
cargo init --name aura-workspace

# Create individual crates
cargo new aura-ledger --lib
cargo new aura-wallet-core --lib
cargo new aura-nodes --bin

# Install WASM tooling for wallet core
cargo install wasm-pack
```

### Expected project structure:

```
aura-workspace/
├── Cargo.toml (workspace root)
├── aura-ledger/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── did_registry/
│       ├── vc_schema_registry/
│       ├── revocation_registry/
│       ├── consensus/
│       └── p2p/
├── aura-wallet-core/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── key_manager/
│       ├── did_manager/
│       ├── vc_store/
│       ├── presentation_generator/
│       └── zkp_handler/
└── aura-nodes/
    ├── Cargo.toml
    └── src/
        └── main.rs
```

## Key Technical Decisions

- **Core Components**: Written in Rust for performance and memory safety
- **Wallet Frontend**: JavaScript/TypeScript with React Native
- **Cross-Platform**: Rust core compiled to WASM for browser/mobile use
- **Cryptography**: Ed25519/ECDSA for signing, AES-GCM for encryption
- **P2P Networking**: libp2p for node communication
- **Standards**: W3C DIDs and Verifiable Credentials

## Important Implementation Notes

- The ledger stores NO personal data - only DIDs, hashes, and metadata
- All PII and credentials are stored off-chain with user-controlled encryption
- Initial consensus will use Proof-of-Authority, later transitioning to Proof-of-Stake
- ZKP integration is planned for Phase 2 using libraries like arkworks-rs or bellman

## Build Commands

```bash
# Build all crates
cargo build

# Build in release mode
cargo build --release

# Run tests
cargo test

# Run specific example
cargo run --example basic_usage

# Run the node
cargo run --bin aura-node

# Check code without building
cargo check

# Format code
cargo fmt

# Run linter
cargo clippy
```

## Current Status

Phase 1 (Foundation & Core Infrastructure) is complete. The project now includes:

- Functional blockchain with PoA consensus
- W3C-compliant DID and VC implementations  
- Identity wallet with key management
- P2P network node with REST API
- Basic examples and integration tests

See `PHASE1_SUMMARY.md` for detailed implementation status.