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

# Standard build with system RocksDB:
ROCKSDB_LIB_DIR=/usr/lib64 LIBROCKSDB_SYS_DISABLE_BUNDLED=1 cargo build --release

# If you still have bindgen/clang issues:
BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-redhat-linux/15/include" \
ROCKSDB_LIB_DIR=/usr/lib64 \
LIBROCKSDB_SYS_DISABLE_BUNDLED=1 \
cargo build --release

# For Ubuntu/Debian:
sudo apt-get install -y librocksdb-dev libzstd-dev clang
ROCKSDB_LIB_DIR=/usr/lib LIBROCKSDB_SYS_DISABLE_BUNDLED=1 cargo build --release
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

## Current Status - v0.1.5 Released! 🚀

**Latest Release**: v0.1.5 (June 1, 2025 Evening)
- Download binaries: https://github.com/doublegate/Aura-DecentralTrust/releases/tag/v0.1.5
- Available for: Linux, macOS (Intel/ARM), Windows

**Previous Release**: v0.1.0 (June 1, 2025 Morning)
- Foundation release with security hardening

Phase 1 (Foundation & Core Infrastructure) is 95% complete:

- ✅ Functional blockchain with PoA consensus
- ✅ W3C-compliant DID and VC implementations  
- ✅ Identity wallet with key management
- ✅ P2P network node with REST API
- ✅ JWT authentication and TLS support
- ✅ Comprehensive security hardening
- ✅ **Comprehensive test coverage (95% - 505 tests)** - COMPLETED June 1, 2025
- ⏳ API-blockchain integration (remaining 5%)

See `docs/PHASE1_SUMMARY.md` for detailed implementation status.

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

# Run linter with CI settings (strict)
cargo clippy --all-targets --all-features -- -D warnings
```

## Recent Updates (2025-06-01 Evening)

### v0.1.5 Release (6:45 PM)
Released version 0.1.5 with comprehensive test coverage:
- **Version**: v0.1.5 (tagged and pushed)
- **Release Workflow**: Triggered for multi-platform binary builds
- **Documentation**: Updated README, CHANGELOG, and test coverage reports

### Test Coverage Completion (4:12 PM)
Successfully completed comprehensive test coverage for the entire project:
- **Total Tests**: 505 (ALL PASSING) - up from 452
- **Coverage**: 95% across all crates
- **Test Types**: Unit tests, integration tests, property-based tests, performance benchmarks
- **Key Fixes**: Resolved 17 failing aura-node tests
- **Documentation**: Created TEST_COVERAGE_FINAL_2025-06-01.md and MASTER_PHASE1-REAL_IMP.md
- **Remaining Work**: 5% API-blockchain integration documented (9-15 days)

### Important Development Practice
**Tests should now be written alongside new features** rather than as a separate phase. This ensures better code quality, immediate validation, and continuous integration compliance.

## Recent Updates (2025-06-01 Morning)

### Dependency Updates
The project has been updated to work with latest dependencies:
- **bincode**: Updated to 2.0 with new encode/decode API
- **libp2p**: Updated to 0.55.0 with new NetworkBehaviour macro syntax
- **axum**: Updated to 0.8.4 with new serve API
- **All other deps**: Updated to latest versions as of 2025-05-30

### Build Requirements
- **RocksDB**: Requires rocksdb-devel system package and environment variables
- **Clang**: Required for bindgen to generate RocksDB bindings
- **Environment Variables**:
  - `ROCKSDB_LIB_DIR`: Path to system RocksDB libraries
  - `LIBROCKSDB_SYS_DISABLE_BUNDLED=1`: Use system RocksDB instead of bundled
  - `BINDGEN_EXTRA_CLANG_ARGS`: May be needed for clang headers

### Security Features Implemented
- **JWT Authentication**: All API endpoints protected with Bearer token auth
- **TLS Support**: Self-signed certificate generation with `--enable-tls` flag
- **Input Validation**: Comprehensive validation for DIDs, URLs, and data sizes
- **Key Zeroization**: Cryptographic keys properly cleared from memory
- **Replay Protection**: Transactions include nonces and expiration

### Running the Node
```bash
# Standard run (HTTP)
ROCKSDB_LIB_DIR=/usr/lib64 LIBROCKSDB_SYS_DISABLE_BUNDLED=1 cargo run --bin aura-node

# Run with TLS (generates certificates)
ROCKSDB_LIB_DIR=/usr/lib64 LIBROCKSDB_SYS_DISABLE_BUNDLED=1 cargo run --bin aura-node -- --enable-tls

# Get auth token
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"node_id": "validator-node-1", "password": "validator-password-1"}'
```

### CI/CD Status - FULLY OPERATIONAL ✅ (2025-06-01)
- **GitHub Actions**: CI pipeline working perfectly on Ubuntu and macOS
- **Automated Testing**: All tests passing on PRs and pushes to main
- **Release Automation**: Successfully deployed v0.1.0 with multi-platform binaries
- **Dependency Updates**: Dependabot configured and working
- **Build Status**: 
  - ✅ Test Suite: PASSING (all platforms)
  - ✅ Security Audit: PASSING
  - ✅ Code Coverage: OPERATIONAL
  - ✅ All format/clippy issues: RESOLVED
  - ✅ Release Workflow: OPERATIONAL with auto-generated notes

### Release Workflow Commands
```bash
# Create and push a new tag (triggers release workflow)
git tag -a v0.1.0 -m "Phase 1 Foundation Release"
git push origin v0.1.0

# The release workflow automatically:
# - Builds binaries for Linux, macOS (Intel/ARM), Windows
# - Generates release notes from commit messages
# - Creates GitHub release with all artifacts
# - No manual intervention needed!
```

### Release History
- **v0.1.5** (2025-06-01 Evening): Comprehensive Test Coverage Release
  - 95% test coverage with 505 tests (ALL PASSING)
  - Property-based testing and performance benchmarks
  - Platform-specific test handling
  - Complete test documentation
- **v0.1.0** (2025-06-01 Morning): Phase 1 Foundation Release
  - Core blockchain infrastructure
  - Security hardening complete
  - Multi-platform CI/CD pipeline
  - Binary releases for all major platforms
  - 23 documentation files archived after completion

### Next Milestones
- **v0.2.0**: API-blockchain integration complete
- **v0.3.0**: P2P message handlers implemented
- **v1.0.0**: Desktop wallet MVP included

### Documentation Organization
- **Active docs**: In `to-dos/` directory for current work
- **Archived docs**: In `to-dos/Archive/` with subdirectories:
  - `build-fixes/`: Historical build troubleshooting
  - `completed-features/`: Finished implementations
  - `session-summaries/`: Past work sessions
  - `security-updates/`: Security implementation records
  - See `to-dos/Archive/README.md` for full index

See `CHANGELOG.md` for complete list of changes.