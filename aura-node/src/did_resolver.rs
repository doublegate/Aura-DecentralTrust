use anyhow::{Context, Result};
use aura_common::did::{DidDocument, VerificationMethod};
use aura_common::AuraDid;
use aura_crypto::keys::PublicKey;
use aura_ledger::did_registry::DidRegistry;
use base64::Engine;
use std::sync::Arc;
use tokio::sync::RwLock;

/// DID Resolver that connects to the blockchain registry
pub struct DIDResolver {
    registry: Arc<RwLock<DidRegistry>>,
}

impl DIDResolver {
    /// Create a new DID resolver
    pub fn new(registry: Arc<RwLock<DidRegistry>>) -> Self {
        Self { registry }
    }

    /// Resolve a DID to get its document and public key
    pub async fn resolve_did(&self, did: &str) -> Result<DidDocument> {
        let registry = self.registry.read().await;
        let aura_did = AuraDid(did.to_string());
        match registry.resolve_did(&aura_did)? {
            Some((doc, _record)) => Ok(doc),
            None => Err(anyhow::anyhow!("DID not found: {did}")),
        }
    }

    /// Get the public key for verification from a DID
    pub async fn get_verification_key(&self, did: &str) -> Result<PublicKey> {
        let doc = self.resolve_did(did).await?;

        // Find the first Ed25519 verification method
        let verification_method = doc
            .verification_method
            .iter()
            .find(|vm| vm.verification_type == "Ed25519VerificationKey2020")
            .ok_or_else(|| anyhow::anyhow!("No Ed25519 verification key found for DID"))?;

        // Extract the public key
        self.extract_public_key(verification_method)
    }

    /// Extract public key from verification method
    fn extract_public_key(&self, method: &VerificationMethod) -> Result<PublicKey> {
        // Check for public key JWK
        if let Some(jwk) = &method.public_key_jwk {
            if let Some(x) = jwk.get("x").and_then(|v| v.as_str()) {
                let key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(x)
                    .context("Failed to decode public key from JWK")?;

                if key_bytes.len() != 32 {
                    return Err(anyhow::anyhow!("Invalid public key length"));
                }

                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&key_bytes);

                return PublicKey::from_bytes(&key_array)
                    .context("Failed to create public key from bytes");
            }
        }

        // Check for public key base58
        if let Some(base58) = &method.public_key_base58 {
            let key_bytes = bs58::decode(base58)
                .into_vec()
                .context("Failed to decode public key from base58")?;

            if key_bytes.len() != 32 {
                return Err(anyhow::anyhow!("Invalid public key length"));
            }

            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&key_bytes);

            return PublicKey::from_bytes(&key_array)
                .context("Failed to create public key from bytes");
        }

        // Check for public key multibase
        if let Some(multibase) = &method.public_key_multibase {
            // Multibase format: first char is the base identifier
            if let Some(stripped) = multibase.strip_prefix('z') {
                // 'z' indicates base58btc
                let key_bytes = bs58::decode(stripped)
                    .into_vec()
                    .context("Failed to decode public key from multibase")?;

                // Skip multicodec prefix if present (0xed01 for Ed25519)
                let key_data =
                    if key_bytes.len() == 34 && key_bytes[0] == 0xed && key_bytes[1] == 0x01 {
                        &key_bytes[2..]
                    } else {
                        &key_bytes
                    };

                if key_data.len() != 32 {
                    return Err(anyhow::anyhow!("Invalid public key length"));
                }

                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(key_data);

                return PublicKey::from_bytes(&key_array)
                    .context("Failed to create public key from bytes");
            }
        }

        Err(anyhow::anyhow!("No supported public key format found"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_common::did::{DidDocument, VerificationRelationship};
    use aura_common::{BlockNumber, Timestamp};
    use aura_crypto::keys::PrivateKey;
    use aura_ledger::did_registry::DidRegistry;

    async fn setup_test_registry() -> (Arc<RwLock<DidRegistry>>, tempfile::TempDir) {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = Arc::new(aura_ledger::storage::Storage::new(temp_dir.path()).unwrap());
        let mut registry = DidRegistry::new(storage);

        // Create a test DID document
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key();

        let did = AuraDid("did:aura:test123".to_string());

        // Create multibase encoded public key (z + base58btc)
        let mut key_bytes = vec![0xed, 0x01]; // Ed25519 multicodec prefix
        key_bytes.extend_from_slice(&public_key.to_bytes());
        let multibase_key = format!("z{}", bs58::encode(&key_bytes).into_string());

        let verification_method = VerificationMethod {
            id: format!("{}#key-1", did.0),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            controller: did.clone(),
            public_key_multibase: Some(multibase_key),
            public_key_jwk: None,
            public_key_base58: None,
        };

        let doc = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_string()],
            id: did.clone(),
            controller: None,
            verification_method: vec![verification_method.clone()],
            authentication: vec![VerificationRelationship::Reference(
                verification_method.id.clone(),
            )],
            assertion_method: vec![VerificationRelationship::Reference(
                verification_method.id.clone(),
            )],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
            created: Timestamp::now(),
            updated: Timestamp::now(),
        };

        registry
            .register_did(&doc, public_key, BlockNumber(0))
            .unwrap();
        (Arc::new(RwLock::new(registry)), temp_dir)
    }

    #[tokio::test]
    async fn test_resolve_did() {
        let (registry, _temp_dir) = setup_test_registry().await;
        let resolver = DIDResolver::new(registry);

        // Test successful resolution
        let doc = resolver.resolve_did("did:aura:test123").await.unwrap();
        assert_eq!(doc.id.0, "did:aura:test123");
        assert_eq!(doc.verification_method.len(), 1);

        // Test failed resolution
        let result = resolver.resolve_did("did:aura:nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_verification_key() {
        let (registry, _temp_dir) = setup_test_registry().await;
        let resolver = DIDResolver::new(registry);

        // Test getting verification key
        let public_key = resolver
            .get_verification_key("did:aura:test123")
            .await
            .unwrap();
        assert_eq!(public_key.to_bytes().len(), 32);
    }

    #[tokio::test]
    async fn test_extract_public_key_multibase() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = Arc::new(aura_ledger::storage::Storage::new(temp_dir.path()).unwrap());
        let registry = Arc::new(RwLock::new(DidRegistry::new(storage)));
        let resolver = DIDResolver::new(registry.clone());

        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.public_key();
        let key_bytes = public_key.to_bytes();

        // Test multibase format (base58btc with multicodec)
        let mut multibase_bytes = vec![0xed, 0x01]; // Ed25519 multicodec
        multibase_bytes.extend_from_slice(&key_bytes);

        let method = VerificationMethod {
            id: "did:aura:test#key-1".to_string(),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            controller: AuraDid("did:aura:test".to_string()),
            public_key_multibase: Some(format!(
                "z{}",
                bs58::encode(&multibase_bytes).into_string()
            )),
            public_key_jwk: None,
            public_key_base58: None,
        };

        let extracted = resolver.extract_public_key(&method).unwrap();
        assert_eq!(extracted.to_bytes(), key_bytes);
    }
}
