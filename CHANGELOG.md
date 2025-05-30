# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2025-05-30

### Added
- Build documentation for modern Linux systems (Fedora 42/Bazzite)
- Comprehensive RocksDB build guide (`to-dos/ROCKSDB_BUILD_GUIDE.md`)
- Dependency update guide with API migration notes (`to-dos/DEPENDENCY_UPDATE_GUIDE.md`)
- Environment variable support for clang/bindgen issues
- Logo image for README (`images/aura_logo.png`)
- Enhanced build instructions for multiple platforms
- Session summaries tracking development progress
- `docs` folder for better documentation organization
- Clone implementation for KeyPair type
- Custom bincode implementations for PublicKey and Timestamp

### Changed
- **Documentation**: Moved key docs to `docs/` folder for better organization
  - `DOCUMENTATION_UPDATES.md` → `docs/DOCUMENTATION_UPDATES.md`
  - `PHASE1_SUMMARY.md` → `docs/PHASE1_SUMMARY.md`
  - `proj_outline.md` → `docs/proj_outline.md`
- **Build Process**: Now requires system RocksDB libraries with environment variables
- **Dependencies**: Updated all to latest versions as of 2025-05-30
  - bincode: 1.3.3 → 2.0.1 (major API change)
  - rocksdb: 0.21.0 → 0.23.0
  - libp2p: 0.54.0 → 0.55.0
  - axum: 0.7.0 → 0.8.4
  - tokio: 1.39.0 → 1.45.1
  - ed25519-dalek: 2.1.0 → 2.1.1 (added serde feature)
  - Various other minor updates
- **API Updates**:
  - Migrated from bincode 1.x serialize/deserialize to 2.0 encode/decode API
  - Updated from axum::Server to axum::serve with TcpListener
  - Fixed libp2p 0.55 SwarmBuilder and NetworkBehaviour derive macro usage
  - Added Encode/Decode derives for multiple types
  - Fixed network event handling for new libp2p API
- **Error Handling**:
  - Fixed serde_json::Error conversion (no longer has ::custom method)
  - Improved error messages with proper context
- **Visibility**:
  - Made some internal fields pub(crate) for better module access
  - Fixed private field access issues in wallet components

### Fixed
- Missing serde_json dependency in aura-crypto
- Compilation errors with modern GCC/clang
- Type derivation issues (added Clone, Copy, Debug, Hash, Eq where needed)
- All unused import warnings
- rand version conflicts (using 0.8.5, not 0.9.x)
- multicodec version (0.3 doesn't exist, using 0.1.0)
- Send/Sync issues with NetworkManager (wrapped in Arc<Mutex<>>)
- Block production in static async context
- Connection event pattern matching for libp2p 0.55
- Topic comparison in network message handling

### Removed
- did_url dependency (unused and causing compilation issues)

### Security
- All cryptographic keys properly zeroized on drop
- Encryption keys protected with master key architecture

## [0.1.0] - 2024-01-15

### Added
- Initial Phase 1 implementation
- **Aura Ledger**: Blockchain with Proof-of-Authority consensus
- **DID Registry**: W3C-compliant DID management
- **VC Schema Registry**: Credential schema management  
- **Revocation Registry**: Credential revocation tracking
- **Identity Wallet Core**: Key management, DID operations, credential storage
- **Aura Node**: P2P networking, block production, REST API
- **Cryptography**: Ed25519 signatures, AES-256-GCM encryption, SHA-256/Blake3 hashing
- **Examples**: Basic credential issuance and verification
- **Integration Tests**: Core functionality testing
- Comprehensive project documentation

### Technical Stack
- Rust workspace with 5 core crates
- RocksDB for persistent storage
- libp2p for P2P networking
- axum for REST API
- WASM compilation support for wallet
- W3C standards compliance for DIDs and VCs

[Unreleased]: https://github.com/doublegate/Aura-DecentralTrust/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/doublegate/Aura-DecentralTrust/releases/tag/v0.1.0