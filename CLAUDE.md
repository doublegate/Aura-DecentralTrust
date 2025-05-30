# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Aura is a decentralized identity and trust network that combines Decentralized Identifiers (DIDs), Verifiable Credentials (VCs), and Zero-Knowledge Proofs (ZKPs) to enable self-sovereign identity and user-controlled data management.

## Architecture

The system consists of four main components:

1. **Aura Ledger** (`aura-ledger`) - A specialized DLT for DIDs and credential metadata (Rust)
2. **Aura Identity Wallets** (`aura-wallet-core`) - User agents for managing identity and credentials (Rust core + JS/TS frontend)
3. **Aura Nodes** (`aura-node`) - Network participants maintaining the ledger (Rust)
4. **Off-Chain Storage** - User-controlled encrypted storage for actual credentials and PII

## Development Setup

### Prerequisites

- Rust 1.70+ (install from https://rustup.rs)
- C/C++ development tools (gcc, gcc-c++, clang)
- System libraries:
  - rocksdb-devel (RocksDB database) - **REQUIRED for main branch**
  - libzstd-devel (zstd compression)
  - clang/clang-devel (for bindgen)
  - Development headers for C standard library

### Building the Project

```bash
# Clone the repository
git clone https://github.com/doublegate/Aura-DecentralTrust
cd Aura-DecentralTrust

# Install system dependencies first (Fedora/RHEL/Bazzite):
sudo dnf install -y rocksdb-devel libzstd-devel clang-devel

# Standard build (should work with dependencies installed):
cargo build --release

# If you still have bindgen/clang issues:
BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-redhat-linux/15/include" \
ZSTD_SYS_USE_PKG_CONFIG=1 \
cargo build --release

# For Ubuntu/Debian:
sudo apt-get install -y librocksdb-dev libzstd-dev clang
cargo build --release
```

## Key Technical Decisions

- **Core Components**: Written in Rust for performance and memory safety
- **Wallet Frontend**: JavaScript/TypeScript with React Native
- **Cross-Platform**: Rust core compiled to WASM for browser/mobile use
- **Cryptography**: Ed25519/ECDSA for signing, AES-GCM for encryption
- **P2P Networking**: libp2p for node communication
- **Standards**: W3C DIDs and Verifiable Credentials
- **Database**: RocksDB for persistent storage (main branch)

## Important Implementation Notes

- The ledger stores NO personal data - only DIDs, hashes, and metadata
- All PII and credentials are stored off-chain with user-controlled encryption
- Initial consensus will use Proof-of-Authority, later transitioning to Proof-of-Stake
- ZKP integration is planned for Phase 2 using libraries like arkworks-rs or bellman

## Current Status

Phase 1 (Foundation & Core Infrastructure) is complete. The project includes:

- Functional blockchain with PoA consensus
- W3C-compliant DID and VC implementations  
- Identity wallet with key management
- P2P network node with REST API
- Basic examples and integration tests

See `PHASE1_SUMMARY.md` for detailed implementation status.

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

## Recent Updates (2025-05-30)

### Dependency Updates
The project has been updated to work with latest dependencies:
- **bincode**: Updated to 2.0 with new encode/decode API
- **libp2p**: Updated to 0.55.0 with new NetworkBehaviour macro syntax
- **axum**: Updated to 0.8.4 with new serve API
- **All other deps**: Updated to latest versions as of 2025-05-30

### Build Requirements
- **RocksDB**: Requires rocksdb-devel system package on Fedora/RHEL
- **Clang**: Required for bindgen to generate RocksDB bindings
- **Environment**: May need BINDGEN_EXTRA_CLANG_ARGS on some systems

See `CHANGELOG.md` for complete list of changes.