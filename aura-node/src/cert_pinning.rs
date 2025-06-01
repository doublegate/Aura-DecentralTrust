#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Certificate pinning manager for P2P connections
#[derive(Clone)]
#[allow(dead_code)]
pub struct CertPinningManager {
    /// Set of trusted certificate fingerprints (SHA256 of DER-encoded cert)
    trusted_fingerprints: Arc<RwLock<HashSet<String>>>,
    /// Whether to allow unpinned certificates (for development)
    allow_unpinned: bool,
}

impl CertPinningManager {
    #[allow(dead_code)]
    pub fn new(allow_unpinned: bool) -> Self {
        Self {
            trusted_fingerprints: Arc::new(RwLock::new(HashSet::new())),
            allow_unpinned,
        }
    }

    /// Add a trusted certificate fingerprint
    pub async fn add_trusted_fingerprint(&self, fingerprint: String) {
        let mut trusted = self.trusted_fingerprints.write().await;
        tracing::info!("Added trusted certificate fingerprint: {}", &fingerprint);
        trusted.insert(fingerprint);
    }

    /// Remove a trusted certificate fingerprint
    pub async fn remove_trusted_fingerprint(&self, fingerprint: &str) {
        let mut trusted = self.trusted_fingerprints.write().await;
        if trusted.remove(fingerprint) {
            tracing::info!("Removed trusted certificate fingerprint: {}", fingerprint);
        }
    }

    /// Load trusted fingerprints from a file
    pub async fn load_from_file(&self, path: &str) -> anyhow::Result<()> {
        let content = tokio::fs::read_to_string(path).await?;
        let mut trusted = self.trusted_fingerprints.write().await;

        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                trusted.insert(line.to_string());
            }
        }

        tracing::info!("Loaded {} trusted certificate fingerprints", trusted.len());
        Ok(())
    }

    /// Save trusted fingerprints to a file
    pub async fn save_to_file(&self, path: &str) -> anyhow::Result<()> {
        let trusted = self.trusted_fingerprints.read().await;
        let mut content = String::from("# Trusted P2P Certificate Fingerprints\n");
        content.push_str("# One SHA256 fingerprint per line\n\n");

        for fingerprint in trusted.iter() {
            content.push_str(fingerprint);
            content.push('\n');
        }

        tokio::fs::write(path, content).await?;
        Ok(())
    }

    /// Verify a certificate against pinned fingerprints
    pub async fn verify_certificate(&self, cert_der: &[u8]) -> Result<(), String> {
        // Calculate fingerprint
        let fingerprint = calculate_fingerprint(cert_der);

        // Check if it's trusted
        let trusted = self.trusted_fingerprints.read().await;

        if trusted.contains(&fingerprint) {
            tracing::debug!("Certificate fingerprint {} is trusted", fingerprint);
            Ok(())
        } else if self.allow_unpinned {
            tracing::warn!(
                "Certificate fingerprint {} is not pinned, but unpinned certs are allowed",
                fingerprint
            );
            Ok(())
        } else {
            tracing::error!("Certificate fingerprint {} is not trusted", fingerprint);
            Err("Certificate not pinned".to_string())
        }
    }

    /// Get the fingerprint of a certificate
    pub fn get_fingerprint(cert_der: &[u8]) -> String {
        calculate_fingerprint(cert_der)
    }

    /// Get all trusted fingerprints
    pub async fn get_trusted_fingerprints(&self) -> Vec<String> {
        let trusted = self.trusted_fingerprints.read().await;
        trusted.iter().cloned().collect()
    }
}

/// Calculate SHA256 fingerprint of a DER-encoded certificate
fn calculate_fingerprint(cert_der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Default trusted certificates for the Aura network
pub fn default_trusted_fingerprints() -> Vec<String> {
    vec![
        // In production, these would be the fingerprints of trusted validator certificates
        // For now, empty to allow development
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cert_pinning() {
        let manager = CertPinningManager::new(false);

        // Add a trusted fingerprint
        manager
            .add_trusted_fingerprint("abcd1234".to_string())
            .await;

        // Verify it's trusted
        let trusted = manager.get_trusted_fingerprints().await;
        assert!(trusted.contains(&"abcd1234".to_string()));

        // Remove it
        manager.remove_trusted_fingerprint("abcd1234").await;
        let trusted = manager.get_trusted_fingerprints().await;
        assert!(trusted.is_empty());
    }

    #[test]
    fn test_fingerprint_calculation() {
        let cert_data = b"test certificate data";
        let fingerprint = calculate_fingerprint(cert_data);
        assert_eq!(fingerprint.len(), 64); // SHA256 produces 32 bytes = 64 hex chars
    }
}
