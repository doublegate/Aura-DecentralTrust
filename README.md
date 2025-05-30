# Aura: Decentralized Trust & Data Oracle

**Your Data, Your Rules, Verifiably.**

## Overview

Aura is a decentralized identity and trust network that combines Decentralized Identifiers (DIDs), Verifiable Credentials (VCs), and Zero-Knowledge Proofs (ZKPs) to enable self-sovereign identity and user-controlled data management.

## Project Status

This is the Phase 1 implementation (Foundation & Core Infrastructure) of the Aura project. The following components have been implemented:

- ✅ **Aura Ledger** - Blockchain with Proof-of-Authority consensus
- ✅ **DID Registry** - W3C-compliant DID management
- ✅ **VC Schema Registry** - Credential schema management
- ✅ **Revocation Registry** - Credential revocation tracking
- ✅ **Aura Wallet Core** - Identity and credential management (Rust/WASM ready)
- ✅ **Aura Node** - Network participation software
- ✅ **Basic Examples** - Credential issuance and verification use cases

## Architecture

```
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│   Aura Wallet       │────▶│    Aura Network     │◀────│   Relying Party     │
│  (Identity Agent)   │     │                     │     │  (Verifier)         │
└─────────────────────┘     │  ┌───────────────┐ │     └─────────────────────┘
                           │  │  Aura Ledger  │ │
                           │  │   (DLT)       │ │
                           │  └───────────────┘ │
                           │                     │
                           │  ┌───────────────┐ │
                           │  │  Aura Nodes   │ │
                           │  │               │ │
                           │  └───────────────┘ │
                           └─────────────────────┘
```

## Getting Started

### Prerequisites

- Rust 1.70+ (install from https://rustup.rs)
- RocksDB dependencies

### Building

```bash
# Clone the repository
git clone https://github.com/aura-decentraltrust/aura
cd aura

# Build all components
cargo build --release
```

### Running a Node

```bash
# Run a query node (default)
cargo run --bin aura-node

# Run a validator node
cargo run --bin aura-node -- --node-type validator

# Specify custom data directory and API port
cargo run --bin aura-node -- --data-dir ./mydata --api-addr 127.0.0.1:8081
```

### Running the Example

```bash
cargo run --example basic_usage
```

## Core Components

### aura-common
Shared types and utilities following W3C standards for DIDs and VCs.

### aura-crypto
Cryptographic primitives including:
- Ed25519 signatures
- AES-256-GCM encryption
- SHA-256 and Blake3 hashing

### aura-ledger
Blockchain implementation with:
- Proof-of-Authority consensus
- DID registry
- VC schema registry
- Revocation registry
- RocksDB storage

### aura-wallet-core
Identity wallet functionality:
- Key management
- DID operations
- Credential storage
- Presentation generation
- WASM compilation support

### aura-node
Network node implementation:
- P2P networking (libp2p)
- Block production (validators)
- REST API
- Transaction processing

## API Endpoints

The Aura node exposes the following REST API endpoints:

- `GET /` - API information
- `GET /node/info` - Node status and information
- `GET /did/{did}` - Resolve a DID
- `GET /schema/{id}` - Get a credential schema
- `POST /transaction` - Submit a transaction
- `GET /revocation/{list_id}/{index}` - Check revocation status

## Development Roadmap

### Phase 1: Foundation & Core Infrastructure ✅ (Complete)
- Core ledger with PoA consensus
- Basic DID and VC functionality
- Identity wallet core
- Network infrastructure

### Phase 2: Ecosystem Growth & Advanced Features (Next)
- Transition to Proof-of-Stake consensus
- Zero-Knowledge Proof integration
- SDKs for multiple languages
- Wallet UI applications
- Decentralized storage integration

### Phase 3: Mainstream Adoption & Governance
- Decentralized governance
- Interoperability bridges
- Enhanced user experience
- Enterprise integrations

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## License

This project is dual-licensed under MIT and Apache 2.0 licenses.

## Security

For security concerns, please email security@aura-network.org

## Learn More

- [Project Outline](proj_outline.md) - Detailed technical specification
- [Documentation](https://docs.aura-network.org) - Coming soon
- [Community Forum](https://forum.aura-network.org) - Coming soon