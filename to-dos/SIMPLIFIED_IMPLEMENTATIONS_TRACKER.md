# Simplified Implementations Tracker

This document tracks all simplified/temporary implementations that were created during Phase 1 development. These need to be replaced with full production versions before the system is ready for deployment.

**Created**: June 2, 2025  
**Purpose**: Track technical debt from rapid prototyping
**Updated**: June 2, 2025 - Phase 1B.1 complete, both high priority items resolved!

## High Priority - Core Functionality

### 1. ~~DID Registry Connection in API~~ ✅ RESOLVED
- **Location**: `aura-node/src/api.rs` lines 164-186
- **Previous Issue**: Created new in-memory registry on each API server start
- **Resolution Implemented** (June 2, 2025):
  - API now accepts `NodeComponents` struct with all registries
  - Node passes components via `get_api_components()` method
  - DID resolution uses actual registry when available
  - Only creates temporary registries for testing/backward compatibility
  - All API operations now affect actual blockchain state
- **Status**: COMPLETE - No longer a simplified implementation

### 2. ~~API State Architecture~~ ✅ RESOLVED
- **Location**: `aura-node/src/api.rs` - `ApiState` struct
- **Previous Issue**: API created its own components without node connection
- **Resolution Implemented** (June 2, 2025):
  - ApiState now includes all registry references:
    - `blockchain: Option<Arc<RwLock<Blockchain>>>`
    - `did_registry: Option<Arc<RwLock<DidRegistry>>>`
    - `schema_registry: Option<Arc<RwLock<VcSchemaRegistry>>>`
    - `revocation_registry: Option<Arc<RwLock<RevocationRegistry>>>`
    - `transaction_pool: Option<Arc<RwLock<Vec<Transaction>>>>`
  - Node passes actual components via NodeComponents struct
  - API properly connected to blockchain state
- **Status**: COMPLETE - Architecture properly implemented

## Medium Priority - Test Infrastructure

### 3. Test Modules with Simplified Mocks
- **Files**:
  - `simple_signature_test.rs` - Basic validation without DID resolution
  - `did_resolver_simple_test.rs` - Tests key extraction without storage
  - `signature_verification_tests.rs` - Uses mock registries
  - `api_nonce_tests.rs` - Not integrated into test suite
- **Issues**:
  - Tests don't use actual storage backends
  - Mock registries don't match production behavior
  - Some tests have compilation errors
- **Required Fix**:
  - Create proper test fixtures with storage
  - Use test utilities from aura-ledger
  - Ensure tests match production scenarios

### 4. DID Resolver Tests
- **Location**: `aura-node/src/did_resolver.rs` test module
- **Current State**: Compilation errors due to:
  - `DidRegistry::new()` requires storage parameter
  - `register_did()` signature mismatch
  - `resolve_did()` returns Result<Option<(doc, record)>>
- **Required Fix**:
  - Update tests to create proper storage instances
  - Match actual API signatures
  - Handle Result types properly

## Low Priority - Documentation

### 5. Inline TODOs
- **Locations**: Throughout codebase marked with "TODO: In production"
- **Required**: Systematic review and resolution of all TODOs

## Implementation Strategy

1. **Phase 1B Integration** - When implementing API-blockchain integration:
   - Fix DID registry connection
   - Update API state architecture
   - Connect all registries properly

2. **Test Refactoring Sprint** - Dedicated effort to:
   - Fix all compilation errors in tests
   - Create shared test utilities
   - Ensure 95% coverage maintained

3. **Production Hardening** - Before v1.0:
   - Remove all simplified implementations
   - Verify no in-memory registries in production code
   - Complete integration testing

## Success Criteria

- [ ] All API operations affect persistent blockchain state
- [ ] No temporary registries created in production code
- [ ] All tests compile and pass with actual storage
- [ ] Integration tests verify end-to-end workflows
- [ ] No TODOs remain in production code paths