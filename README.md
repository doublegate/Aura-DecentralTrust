# Aura: Decentralized ID Wallet - Trust & Data Management

**Your Data, Your Rules, Verifiably.**

![Aura Logo](images/aura_logo.png)

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
+-----------------------+      +-------------------------+      +-----------------------+
|     Issuers           |----->| Aura Identity Wallet    |<---->|    Relying Parties    |
| (e.g., Gov, Uni, Emp) |      | (User Agent)            |      | (e.g., Websites, Apps)|
+-----------------------+      | - DID Management        |      +-----------------------+
           |                   | - VC Storage (Encrypted)|               |
           | Issues VCs        | - Selective Disclosure  | Presents VPs  | Verifies VPs
           |                   | - ZKP Generation        |               |
           V                   +-------------------------+               |
+------------------------------------------------------------------------+
|                            Aura Network                                |
|                                                                        |
|  +---------------------+   +-------------------------------------+     |
|  | Aura Nodes          |<->| Aura Ledger (DLT)                   |     |
|  | - Validators        |   | - DID Registry                      |     |
|  | - Query Nodes       |   | - VC Schema Registry                |     |
|  | (- Storage Nodes)   |   | - Issuer Key Registry               |     |
|  +---------------------+   | - Revocation Registry               |     |
|                            +-------------------------------------+     |
|                                                                        |
|  User-Controlled Off-Chain Storage (Encrypted VCs & PII)               |
|  (Device, Personal Cloud, Decentralized Storage like IPFS)             |
+------------------------------------------------------------------------+
```

## Getting Started

### Prerequisites

- Rust 1.70+ (install from https://rustup.rs)
- C/C++ development tools (gcc, g++)
- System libraries:
  - rocksdb-devel (RocksDB database)
  - libzstd-devel (zstd compression)
  - clang/llvm (for bindgen)

### Building

```bash
# Clone the repository
git clone https://github.com/doublegate/Aura-DecentralTrust
cd Aura-DecentralTrust

# Install system dependencies (Fedora/RHEL/Bazzite)
sudo dnf install -y rocksdb-devel libzstd-devel clang-devel

# Build all components
cargo build --release

# If you encounter bindgen/clang issues:
BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-redhat-linux/15/include" \
ZSTD_SYS_USE_PKG_CONFIG=1 \
cargo build --release
```

### Special Build Notes

- **Fedora/RHEL/Bazzite**: Install rocksdb-devel and use environment variables if needed
- **Ubuntu/Debian**: Install `librocksdb-dev` and `clang` packages
- **macOS**: Install Xcode Command Line Tools
- **Windows**: Use WSL2 or MSYS2 with mingw-w64

### Running a Node

```bash
# First time setup - copy example config
cp config/config.example.toml config/config.toml

# Run a query node (default)
cargo run --bin aura-node

# Run a validator node
cargo run --bin aura-node -- --node-type validator

# Specify custom data directory and API port
cargo run --bin aura-node -- --data-dir ./mydata --api-addr 127.0.0.1:8081

# Use a custom config file
cargo run --bin aura-node -- --config /path/to/custom/config.toml
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
- RocksDB storage (high-performance embedded database)

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

See [SECURITY_NOTICE.md](SECURITY_NOTICE.md) for important security information and best practices.

For security concerns, please email security@aura-network.org

## Learn More

- [Project Outline](docs/proj_outline.md) - Detailed technical specification
- [Phase 1 Summary](docs/PHASE1_SUMMARY.md) - Implementation details and achievements
- [Phase 1 Completion Report](docs/PHASE1_COMPLETION_REPORT.md) - Functionality and readiness assessment
- [Security Audit](docs/SECURITY_AUDIT_PHASE1.md) - Comprehensive security analysis
- [Documentation Index](docs/README.md) - All project documentation
- [Documentation](https://docs.aura-network.org) - Coming soon
- [Community Forum](https://forum.aura-network.org) - Coming soon

## Metrics

![Alt](https://repobeats.axiom.co/api/embed/b91bd1b950b741e8d35baf666dc9933c5289d418.svg "Repobeats Analytics")
