# Dependency Update Guide

This guide documents dependency updates needed for building on modern systems, based on learnings from the build-fixes-sled branch.

## Critical Dependency Versions

### Must Update

These dependencies need updates to compile on modern systems:

```toml
# In aura-ledger/Cargo.toml
[dependencies]
libp2p = "0.55.0"  # Was likely older
axum = "0.8.0"     # API changes from 0.6.x
tower = "0.5.0"    # Match axum's tower version

# In aura-crypto/Cargo.toml
[dependencies]
ed25519-dalek = { version = "2.1.1", features = ["serde"] }  # Add serde feature
serde_json = "1.0"  # Add this dependency

# Workspace-wide
[workspace.dependencies]
rand = "0.8.5"     # NOT 0.9.x - causes compatibility issues
```

### API Migration Required

#### 1. libp2p NetworkBehaviour

Old (pre-0.50):
```rust
#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
struct MyBehaviour {
    // ...
}
```

New (0.55.0):
```rust
#[derive(NetworkBehaviour)]
struct MyBehaviour {
    // ...
}
```

#### 2. axum Server API

Old (0.6.x):
```rust
use axum::Server;

Server::bind(&addr)
    .serve(app.into_make_service())
    .await?;
```

New (0.8.0):
```rust
use axum::serve;
use tokio::net::TcpListener;

let listener = TcpListener::bind(&addr).await?;
axum::serve(listener, app).await?;
```

#### 3. Error Handling

The `serde_json::Error` no longer implements `std::error::Error::custom`. Update error conversions:

```rust
// Don't use #[from] for serde_json::Error
// Instead, implement manually:
impl From<serde_json::Error> for AuraError {
    fn from(err: serde_json::Error) -> Self {
        AuraError::SerializationError(err.to_string())
    }
}
```

## Potential Issues to Watch For

### 1. Trait Bound Issues

Add these derives where needed:
```rust
#[derive(Clone, Copy, Debug)]  // For types used in async contexts
#[derive(Serialize, Deserialize)]  // For network messages
```

### 2. Send + Sync Requirements

Async tasks may require explicit bounds:
```rust
async fn process<T: Send + Sync + 'static>(data: T) {
    // ...
}
```

### 3. Feature Flags

Ensure these features are enabled:
```toml
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
```

## Build Verification Steps

1. **Clean Build**
   ```bash
   cargo clean
   cargo update
   cargo build
   ```

2. **Check Each Crate**
   ```bash
   cargo check -p aura-common
   cargo check -p aura-crypto
   cargo check -p aura-ledger
   cargo check -p aura-wallet-core
   cargo check -p aura-node
   ```

3. **Test Suite**
   ```bash
   cargo test --workspace
   ```

## Dependency Compatibility Matrix

| Package | Old Version | New Version | Breaking Changes |
|---------|-------------|-------------|------------------|
| libp2p | < 0.50 | 0.55.0 | NetworkBehaviour macro |
| axum | 0.6.x | 0.8.0 | Server API |
| bincode | 1.3.3 | Keep 1.3.3 | v2 has different API |
| rand | any | 0.8.5 | Don't use 0.9.x |
| tokio | 1.x | 1.40+ | None expected |

## Rollback Plan

If updates cause issues:

1. **Revert Cargo.toml changes**
2. **Use git to restore**:
   ```bash
   git checkout main -- Cargo.toml
   git checkout main -- */Cargo.toml
   ```
3. **Consider branch strategy**:
   - Keep main with original deps
   - Create update branch for testing

## Future Considerations

- **bincode 2.0**: Major API changes, requires replacing Serialize/Deserialize with Encode/Decode
- **RocksDB alternatives**: sled is simpler but lacks features
- **WASM compatibility**: Check all deps support wasm32-unknown-unknown target

## See Also

- `CHANGELOG.md` - Detailed list of all changes made
- `to-dos/BUILD_FIXES_SUMMARY.md` - Issues encountered and workarounds