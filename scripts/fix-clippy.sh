#!/bin/bash
# Quick fixes for critical clippy warnings

echo "Fixing critical clippy warnings..."

# Fix needless borrows and derefs
sed -i 's/&\*\*master_key/master_key/g' aura-wallet-core/src/key_manager.rs
sed -i 's/&\*private_key_bytes/\&private_key_bytes/g' aura-wallet-core/src/key_manager.rs
sed -i 's/&key_pair\.public_key()/key_pair.public_key()/g' aura-wallet-core/src/did_manager.rs

# Add Default implementations
cat >> aura-wallet-core/src/key_manager.rs << 'EOF'

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}
EOF

cat >> aura-wallet-core/src/vc_store.rs << 'EOF'

impl Default for VcStore {
    fn default() -> Self {
        Self::new()
    }
}
EOF

cat >> aura-wallet-core/src/wallet.rs << 'EOF'

impl Default for AuraWallet {
    fn default() -> Self {
        Self::new()
    }
}
EOF

echo "Done! Run 'cargo fmt' to clean up formatting."