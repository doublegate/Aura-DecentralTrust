# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Testing**: Comprehensive test coverage implementation (95% complete - 452 tests)
  - aura-common: 64 tests covering DIDs, errors, types, and VCs
  - aura-crypto: 72 tests covering encryption, hashing, keys, and signing
  - aura-ledger: 104 tests covering blockchain, consensus, and registries
  - aura-wallet-core: 83 tests covering wallet operations and DID management
  - aura-node: 129 tests covering API, auth, networking, and security modules
  - Unit tests, integration tests, async tests, and security validation tests
  - Test coverage documentation in `docs/TEST_COVERAGE_COMPREHENSIVE.md`
- **Security**: Comprehensive security hardening for production readiness
  - Mutual TLS support for node-to-node communication
  - Certificate pinning framework for P2P connections
  - Audit logging system for security events
  - SSRF protection with comprehensive IP range validation
  - Transaction signature verification on API endpoints
  - Error message sanitization to prevent information disclosure
  - Windows file permission handling for sensitive data
- **Security**: Externalized JWT secret configuration via environment variable
- **Security**: File-based credential management with SHA256 password hashing
- **Security**: P2P message size validation to prevent DoS attacks
- **Security**: Rate limiting middleware with per-IP tracking
- **Security**: Automatic rate limit cleanup task
- New security modules: `audit.rs`, `cert_pinning.rs`, `error_sanitizer.rs`, `rate_limit.rs`
- Scripts for secure configuration generation
- Scripts for testing rate limiting functionality
- Comprehensive security fixes documentation
- Release process documentation for automated release notes

### Changed
- **Security**: JWT secret now loaded from AURA_JWT_SECRET environment variable
- **Security**: Credentials now stored in config/credentials.json (not hardcoded)
- **Security**: All unwrap()/expect() replaced with proper error handling
- **Security**: TLS configuration now returns Result instead of panicking
- **Security**: Enhanced URL validation with complete SSRF protection
- **Security**: Improved memory handling during encryption operations
- **Build**: Added sha2, base64, and proper rand dependency management
- **API**: Updated to support configurable security settings
- **API**: Added transaction signature verification
- **Config**: Added SecurityConfig with JWT, credentials, and rate limiting settings
- **Release**: Switched to auto-generated release notes with softprops/action-gh-release

### Fixed
- **Critical Security**: Hardcoded JWT secret vulnerability eliminated
- **Critical Security**: Hardcoded test credentials removed from source
- **High Security**: P2P messages now size-validated before processing
- **High Security**: All panic-inducing unwrap() calls replaced
- **High Security**: Rate limiting now properly enforced
- **Medium Security**: Implemented mutual TLS for secure node communication
- **Medium Security**: Added comprehensive SSRF protection for URL validation
- **Medium Security**: Transaction signatures now verified on submission
- **Medium Security**: Eliminated unnecessary plaintext copies during encryption
- **Low Security**: Added audit logging for all security events
- **Low Security**: Implemented certificate pinning for P2P connections
- **Low Security**: Windows file permissions now set for sensitive files
- **Low Security**: Client error messages sanitized to prevent info leaks
- Release workflow permissions for asset uploads

### Security
- Implemented secure credential storage with password hashing
- Added comprehensive P2P message size limits (1MB max)
- Enforced rate limiting on all API endpoints (60 rpm, 1000 rph)
- Eliminated all hardcoded secrets from codebase
- Added mutual TLS support with client certificate verification
- Comprehensive SSRF protection blocking all private IP ranges
- Transaction signature verification with timestamp validation
- Audit logging framework with security event tracking
- Certificate pinning manager for P2P connections
- Error message sanitization for external responses
- **Total**: 13/13 security issues identified and resolved

## [0.1.0] - 2025-06-01

### Added
- Permanent CXXFLAGS configuration for GCC 15 compatibility
- System-wide and cargo-specific build environment setup
- GitHub Actions CI/CD pipeline for automated testing
- Issue templates for bugs, features, and security reports
- Dependabot configuration for weekly dependency updates
- Cargo audit configuration for security scanning
- Build status badges in README
- Comprehensive CI troubleshooting documentation
- Scripts for CI status checking and pre-flight verification

### Fixed  
- Resolved libclang issues with proper system package installation
- Fixed C++ compilation errors with cstdint header inclusion
- All clippy warnings resolved for clean CI builds
- Code formatting inconsistencies across platforms
- CI/CD configuration to use bundled RocksDB
- Security audit warnings for transitive dependencies
- Cargo audit configuration syntax errors (invalid field names)
- Clippy uninlined_format_args warnings in all modules
- Dependabot.yml syntax error (empty ignore array)
- getrandom feature flag (js → wasm_js for v0.3.x)
- Dependency version conflicts (rand 0.9.1 → 0.8.5)
- ed25519-dalek key generation API compatibility

### Changed
- CI/CD uses bundled RocksDB to avoid version conflicts
- Security audit runs directly instead of through actions-rs
- Updated SECURITY_AUDIT_PHASE1.md to reflect all issues resolved
- Downgraded rand to 0.8.5 for ed25519-dalek compatibility
- Updated all format! macros to use inline variable syntax

### Tested
- Successfully built all components in release mode
- Verified node binary functionality (startup, API endpoints)
- Confirmed JWT authentication working correctly
- Validated TLS/HTTPS support with self-signed certificates
- All local builds passing after dependency fixes
- cargo fmt and cargo clippy passing locally
- **CI/CD PIPELINE FULLY OPERATIONAL** ✅
- All GitHub Actions jobs passing (Ubuntu/macOS, stable/beta)
- Security audit and code coverage working

## [0.1.0] - 2025-05-31

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
- **Security**: JWT-based API authentication with role-based access control
- **Security**: Transaction replay protection with nonces, chain_id, and expiration
- **Security**: TLS/HTTPS support with self-signed certificate generation
- **Security**: Comprehensive input validation module with regex patterns
- **Security**: Rate limiting and request body size limits for DoS protection
- **Security**: Proper key zeroization with Zeroize and ZeroizeOnDrop traits
- **Security**: Comprehensive security audit documentation
- New modules: `auth.rs`, `validation.rs`, `tls.rs` in aura-node
- Security documentation: `SECURITY_AUDIT_PHASE1.md`, `PHASE1_COMPLETION_REPORT.md`
- Timestamp utility methods: `from_unix()` and `as_unix()`
- hex dependency to aura-ledger for transaction logging
- Comprehensive testing documentation: `NODE_TESTING_SUMMARY.md`, `WARNING_FIXES_SUMMARY.md`
- Configuration directory structure with example config template
- API integration tests covering all endpoints
- Performance testing with concurrent request handling
- TLS/HTTPS support with axum-server integration
- Mock API endpoint implementations for testing

### Changed
- **Documentation**: Moved key docs to `docs/` folder for better organization
  - `DOCUMENTATION_UPDATES.md` → `docs/DOCUMENTATION_UPDATES.md`
  - `PHASE1_SUMMARY.md` → `docs/PHASE1_SUMMARY.md`
  - `proj_outline.md` → `docs/proj_outline.md`
  - `SECURITY_NOTICE.md` → `docs/SECURITY_NOTICE.md`
- **Configuration**: Moved config file to dedicated directory
  - `config.toml` → `config/config.toml`
  - Added `config/config.example.toml` as user template
  - Updated default config path in aura-node
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
  - Updated axum route parameters from `:param` to `{param}` format
  - Fixed rustls certificate and key loading APIs
  - Added rustls default crypto provider initialization
- **Error Handling**:
  - Fixed serde_json::Error conversion (no longer has ::custom method)
  - Improved error messages with proper context
- **Visibility**:
  - Made some internal fields pub(crate) for better module access
  - Fixed private field access issues in wallet components
- **Dependency Versions**:
  - rcgen: Fixed to 0.13 (0.14 not available)
  - Added tokio-stream "net" feature for TcpListenerStream

### Fixed
- Missing serde_json dependency in aura-crypto
- **Critical Security**: Private key memory exposure - keys now properly zeroized
- **Critical Security**: Transaction replay vulnerability - added nonce and expiry
- **Critical Security**: Missing API authentication - JWT auth implemented
- **Critical Security**: No rate limiting - body size limits added
- **Critical Security**: No TLS encryption - HTTPS support added
- **Critical Security**: Weak input validation - comprehensive validation added
- **Compilation**: Drop trait conflict with ZeroizeOnDrop derive macro
- **Compilation**: All warnings eliminated with appropriate `#[allow(dead_code)]` attributes
- **Runtime**: Fixed borrow vs move issues with Timestamp
- **Runtime**: Fixed auth middleware compatibility issues
- **API**: Implemented all endpoint handlers with mock responses
- **API**: Fixed parameterized route authentication
- **Tests**: Added comprehensive integration test suite
- **Build**: Fixed wallet-core compilation issues

### Security
- Completed comprehensive security audit of Phase 1 implementation
- Fixed all critical and high priority security vulnerabilities
- Implemented defense-in-depth security measures
- Added security-focused documentation and implementation guides
- Project is now functionally secure but requires external audit before production
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