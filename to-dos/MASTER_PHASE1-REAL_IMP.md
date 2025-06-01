# Master TODO: Phase 1 Real Implementation Requirements

This document tracks all placeholder implementations, TODOs, and temporary code that must be replaced with real implementations before Phase 1 can be considered complete.

## Priority 1: Security Critical Issues 🚨

### 1.1 Remove Hardcoded Credentials
- **File**: `aura-node/src/auth.rs` (lines 72-87)
- **Issue**: Hardcoded default credentials in production code
- **Current**: 
  ```rust
  ("validator-node-1", "validator-password-1"),
  ("query-node-1", "query-password-1"),
  ("admin", "admin-password")
  ```
- **Required**: Generate secure credentials on first run or require setup wizard

### 1.2 Implement Nonce Tracking
- **File**: `aura-node/src/api.rs` (line 390)
- **Issue**: TODO - Check nonce hasn't been used before
- **Impact**: System vulnerable to replay attacks
- **Required**: Implement persistent nonce storage and validation

## Priority 2: API-Blockchain Integration (The 5% Gap) 🔗

### 2.1 Connect DID Resolution to Registry
- **File**: `aura-node/src/api.rs` (lines 292-293)
- **Current**: Returns hardcoded mock DID documents
- **Required**: 
  ```rust
  // Instead of mock data, use:
  let did_registry = context.did_registry.read().await;
  let did_doc = did_registry.resolve_did(&did)?;
  ```

### 2.2 Connect Schema Retrieval to Registry
- **File**: `aura-node/src/api.rs` (lines 326-327)
- **Current**: Returns hardcoded mock schemas
- **Required**: Query actual schema registry

### 2.3 Implement Transaction Submission
- **File**: `aura-node/src/api.rs` (line 405)
- **Current**: Returns "pending" without submitting
- **Required**: 
  - Submit to transaction pool
  - Broadcast to network
  - Return actual transaction hash

### 2.4 Implement Revocation Checking
- **File**: `aura-node/src/api.rs` (line 429)
- **Current**: Always returns `is_revoked: false`
- **Required**: Query actual revocation registry

### 2.5 Complete Signature Verification
- **File**: `aura-node/src/api.rs` (lines 456-459)
- **Current**: Doesn't resolve DID to get public key
- **Required**: 
  - Resolve DID document
  - Extract verification method
  - Verify signature with actual public key

## Priority 3: Consensus and Block Production 🏗️

### 3.1 Load Validators from Chain State
- **File**: `aura-node/src/node.rs` (lines 61-62)
- **Current**: Creates empty validator list
- **Required**: Load from genesis block or current chain state

### 3.2 Implement Secure Key Management
- **File**: `aura-node/src/node.rs` (lines 76-77)
- **Current**: Generates ephemeral keys
- **Required**: Load from secure key storage (HSM, encrypted file, etc.)

### 3.3 Process Transactions in Blocks
- **File**: `aura-node/src/node.rs` (lines 263-264)
- **Current**: TODO - Transactions included but not processed
- **Required**: 
  - Validate each transaction
  - Update state (DID registry, schema registry, etc.)
  - Track execution results

### 3.4 Revocation List Issuer Resolution
- **File**: `aura-node/src/node.rs` (lines 322-324)
- **Current**: Uses placeholder DID "temp"
- **Required**: Resolve issuer from transaction sender or revocation list metadata

## Priority 4: Network Communication 🌐

### 4.1 Process Received Blocks
- **File**: `aura-node/src/network.rs` (line 327)
- **Current**: TODO - Just logs receipt
- **Required**: 
  - Validate block
  - Add to chain if valid
  - Update local state

### 4.2 Handle Received Transactions
- **File**: `aura-node/src/network.rs` (line 334)
- **Current**: TODO - Just logs receipt
- **Required**: 
  - Validate transaction
  - Add to transaction pool
  - Broadcast to other peers

### 4.3 Process DID Updates
- **File**: `aura-node/src/network.rs` (line 341)
- **Current**: TODO - Just logs receipt
- **Required**: Process DID update notifications

## Priority 5: Infrastructure Improvements 🏛️

### 5.1 Persistent Audit Logging
- **File**: `aura-node/src/audit.rs` (lines 126-129)
- **Current**: In-memory buffer only
- **Required**: 
  - Write to persistent database
  - Integration with SIEM systems
  - Log rotation and archival

### 5.2 Make Hardcoded Values Configurable
- **Various Files**: Multiple hardcoded values
- **Items**:
  - API listen address (127.0.0.1:8080)
  - P2P addresses (/ip4/127.0.0.1/tcp/9000)
  - Chain ID references
  - Message size limits (MAX_BLOCK_SIZE, etc.)
- **Required**: Move to configuration file

## Implementation Plan

### Phase 1A: Security Fixes (1-2 days)
1. Remove hardcoded credentials
2. Implement nonce tracking
3. Complete signature verification

### Phase 1B: API Integration (2-3 days)
1. Connect all API endpoints to actual registries
2. Implement transaction submission
3. Add proper error handling

### Phase 1C: Consensus Implementation (3-5 days)
1. Transaction processing in blocks
2. Validator management
3. State updates

### Phase 1D: Network Handlers (2-3 days)
1. Block synchronization
2. Transaction propagation
3. Peer management

### Phase 1E: Polish (1-2 days)
1. Configuration management
2. Audit logging
3. Documentation updates

## Estimated Total: 9-15 days

## Success Criteria

Phase 1 is complete when:
1. ✅ No hardcoded credentials or test data in production code
2. ✅ All API endpoints connected to real blockchain state
3. ✅ Transactions are processed and state is updated
4. ✅ Network synchronization works between nodes
5. ✅ Security vulnerabilities (replay attacks) are mitigated
6. ✅ All TODOs are resolved or moved to Phase 2

## Notes

- Many of these issues were temporarily bypassed to get tests passing
- The core implementations exist (registries, blockchain, etc.) - they just need to be wired together
- This represents the final 5% of Phase 1 work
- Completing these items will make the system actually functional rather than just architecturally complete

---

*Generated: June 1, 2025*
*Estimated Effort: 9-15 developer days*
*Priority: Complete before v0.2.0 release*