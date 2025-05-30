# Architecture & Design Decisions

## Core Architecture Principles

### 1. Data Privacy Architecture
**Decision**: No PII on blockchain
- ✅ Only store hashes, DIDs, and pointers on-chain
- ✅ All personal data encrypted off-chain
- ✅ User controls encryption keys
- ✅ GDPR compliant by design

### 2. Modular Design
**Decision**: Microservices-like crate architecture
- ✅ Separate crates for each major component
- ✅ Clear interfaces between modules
- ✅ Independent versioning possible
- ✅ Easy to test and maintain

### 3. Standards Compliance
**Decision**: W3C DID and VC standards
- ✅ Ensures interoperability
- ✅ Future-proof design
- ✅ Wide ecosystem compatibility
- ✅ Well-documented specifications

## Cryptographic Decisions

### Current Implementation (Phase 1) ✅
| Component | Algorithm | Rationale |
|-----------|----------|-----------|
| Signatures | Ed25519 | Fast, secure, small signatures |
| Encryption | AES-256-GCM | Industry standard, hardware acceleration |
| Hashing | SHA-256, Blake3 | SHA for compatibility, Blake3 for speed |
| Key Derivation | SHA-256 (temp) | Simple for MVP, upgrade planned |

### Planned Upgrades (Phase 2+) 📋
| Component | Algorithm | Rationale |
|-----------|----------|-----------|
| Key Derivation | Argon2id | Memory-hard, resistant to attacks |
| Aggregated Signatures | BLS12-381 | Signature aggregation for scalability |
| Post-Quantum | Dilithium/Kyber | Quantum resistance |
| ZKP | Groth16/PLONK | Efficient zero-knowledge proofs |

## Consensus Evolution

### Phase 1: Proof of Authority ✅
**Rationale**:
- Quick to implement
- Predictable block times
- No token economics needed yet
- Easy to debug and test

**Implementation**:
```rust
pub struct ProofOfAuthority {
    validators: HashSet<PublicKey>,
    rotation_interval: u64,
}
```

### Phase 2: Proof of Stake 📋
**Design Decisions**:
- Slash for misbehavior
- Delegation support
- Minimum stake requirements
- Reward distribution

**Planned Implementation**:
```rust
pub struct ProofOfStake {
    validators: BTreeMap<PublicKey, Stake>,
    delegations: HashMap<PublicKey, Vec<Delegation>>,
    slashing_conditions: SlashingRules,
    reward_curve: RewardFunction,
}
```

## Storage Architecture

### Current: RocksDB ✅
**Rationale**:
- Embedded database
- High performance
- Good compression
- Battle-tested

### Future Considerations 📋
1. **IPFS Integration**
   - For DID documents
   - Content addressing
   - Decentralized storage

2. **Arweave Integration**
   - Permanent storage
   - For critical schemas
   - Audit trails

3. **Custom DHT**
   - For real-time data
   - Lower latency
   - Better control

## Network Architecture

### P2P Layer: libp2p ✅
**Rationale**:
- Modular protocol stack
- Multiple transport support
- Built-in protocols (Kad, Gossipsub)
- Active development

**Current Usage**:
- Gossipsub for block propagation
- Kademlia for peer discovery
- Noise for encryption

### API Layer Design
**Current**: REST ✅
```
GET  /did/{did}
GET  /schema/{id}
POST /transaction
GET  /revocation/{list}/{index}
```

**Future**: gRPC + GraphQL 📋
- gRPC for node-to-node
- GraphQL for complex queries
- WebSocket for subscriptions

## Wallet Architecture Decisions

### Core Logic: Rust + WASM ✅
**Rationale**:
- Single codebase for all platforms
- Native performance where needed
- Browser compatibility
- Memory safety

### Platform Strategy
1. **Desktop**: Tauri (decided)
   - Native performance
   - Small bundle size
   - Rust integration

2. **Mobile**: React Native + Rust
   - Code reuse from desktop
   - Native modules for crypto
   - Platform-specific features

3. **Browser**: Pure WASM
   - No binary dependencies
   - Sandbox security
   - Easy distribution

## Scalability Architecture

### Vertical Scaling (Phase 1-2)
- Optimize current implementation
- Better indexing
- Caching layers
- Parallel transaction processing

### Horizontal Scaling (Phase 3+)
1. **Sharding**
   ```rust
   pub enum ShardingStrategy {
       ByDID,      // Shard by DID prefix
       ByIssuer,   // Shard by issuer
       Geographic, // Shard by region
   }
   ```

2. **Layer 2 Solutions**
   - State channels for frequent interactions
   - Rollups for batch processing
   - Sidechains for specific use cases

## Security Architecture

### Defense in Depth
1. **Network Level**
   - DDoS protection
   - Rate limiting
   - IP filtering

2. **Protocol Level**
   - Message authentication
   - Replay protection
   - Eclipse attack prevention

3. **Application Level**
   - Input validation
   - SQL injection prevention
   - XSS protection

4. **Cryptographic Level**
   - Key rotation
   - Forward secrecy
   - Side-channel resistance

## Governance Architecture

### Phase 1: Centralized ✅
- Core team decisions
- Community input
- Open source

### Phase 2: Hybrid 📋
- Technical committee
- Community proposals
- Token holder voting

### Phase 3: Decentralized 🎯
- On-chain governance
- Automatic execution
- Upgrade mechanisms
- Emergency procedures

## Performance Targets & Trade-offs

### Optimization Priorities
1. **User Experience** > Raw Performance
2. **Security** > Convenience
3. **Decentralization** > Efficiency (long-term)
4. **Standards Compliance** > Custom Solutions

### Specific Targets
| Metric | Current | Target | Trade-off |
|--------|---------|--------|-----------|
| TPS | ~100 | 1000+ | More complex consensus |
| Finality | 5s | <3s | Reduced decentralization |
| State Size | Linear | Sub-linear | Complex pruning |
| Sync Time | Hours | Minutes | More bandwidth |

## Future Architecture Considerations

### Multi-Chain Strategy
- [ ] EVM compatibility layer
- [ ] Cosmos IBC integration
- [ ] Polkadot parachain
- [ ] Bitcoin anchoring

### Privacy Enhancements
- [ ] Confidential transactions
- [ ] Private smart contracts
- [ ] Encrypted mempools
- [ ] Anonymous credentials

### Compliance Features
- [ ] Regulatory modules
- [ ] Jurisdiction awareness
- [ ] Automated reporting
- [ ] Audit tools

---
*This document captures key architectural decisions and their rationales*
*Updated as new decisions are made or existing ones are revised*