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
  - Development headers for C standard library

### Building the Project

```bash
# Clone the repository
git clone https://github.com/doublegate/Aura-DecentralTrust
cd Aura-DecentralTrust

# With rocksdb-devel installed:
cargo build --release

# If you still have issues on Fedora 42/Bazzite:
BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-redhat-linux/15/include" \
ZSTD_SYS_USE_PKG_CONFIG=1 \
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

Phase 1 (Foundation & Core Infrastructure) is mostly complete. The project includes:

- Functional blockchain with PoA consensus
- W3C-compliant DID and VC implementations  
- Identity wallet with key management
- P2P network node with REST API
- Basic examples and integration tests

Currently updating dependencies and fixing build issues for modern systems.

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

## Session Development Notes

### 2025-05-30 Session Summary

#### Morning Session (build-fixes-sled branch)
- **Branch Status**: Created `build-fixes-sled` branch, pushed to GitHub, marked as deprecated
- **Main Achievement**: Fixed all compilation errors on Fedora 42/Bazzite using sled database
- **Key Changes**: Migrated RocksDB → sled, updated to bincode 2.0, fixed API compatibility
- **Result**: Full compilation success but missing some blockchain features

#### Afternoon Session (main branch)
- **Branch Status**: Switched back to `main` branch to preserve RocksDB implementation
- **Progress**: Fixed most Rust compilation errors, updated all dependencies to latest versions
- **Successfully Building**: aura-common, aura-crypto, aura-wallet-core
- **Blocker**: RocksDB C++ compilation errors (missing headers in bundled code)
- **Next Step**: User installing rocksdb-devel system package, will retry after reboot

#### Key Learnings Documented
- Created `to-dos/ROCKSDB_BUILD_GUIDE.md` for RocksDB build instructions
- Created `to-dos/DEPENDENCY_UPDATE_GUIDE.md` for API migration notes
- Updated build instructions based on compilation attempts

### Important Reminders
- The `main` branch uses RocksDB (requires rocksdb-devel system package)
- The `build-fixes-sled` branch is deprecated and should not be used
- Most Rust code is updated for modern dependencies (bincode 2.0, latest libp2p/axum)
- See session summaries in `to-dos/` for detailed progress tracking

## Known Build Issues

- **RocksDB on Fedora 42**: Bundled RocksDB has C++ compatibility issues
  - Solution: Install rocksdb-devel system package
- **Dependency versions**: All updated to latest as of 2025-05-30
- **bincode 2.0**: API changed from serialize/deserialize to encode/decode