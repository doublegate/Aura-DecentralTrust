use std::path::Path;
use std::sync::Arc;
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use tokio_rustls::TlsAcceptor;

/// TLS configuration for the API server
#[derive(Clone)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

impl TlsConfig {
    /// Create TLS acceptor from certificate and key files
    #[allow(dead_code)]
    pub async fn build_acceptor(&self) -> anyhow::Result<TlsAcceptor> {
        // Install default crypto provider if not already installed
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let certs = load_certs(&self.cert_path)?;
        let key = load_key(&self.key_path)?;

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    /// Convert to rustls ServerConfig for axum-server
    pub fn into_server_config(self) -> anyhow::Result<rustls::ServerConfig> {
        self.into_server_config_with_client_auth(false)
    }
    
    /// Convert to rustls ServerConfig with optional client auth
    pub fn into_server_config_with_client_auth(self, require_client_auth: bool) -> anyhow::Result<rustls::ServerConfig> {
        // Install default crypto provider if not already installed
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let certs = load_certs(&self.cert_path)?;
        let key = load_key(&self.key_path)?;

        let config = if require_client_auth {
            // For mutual TLS, require client certificates
            let mut client_auth_roots = rustls::RootCertStore::empty();
            
            // In production, load trusted client CA certificates
            // For now, accept self-signed certificates
            if let Ok(client_ca_path) = std::env::var("AURA_CLIENT_CA_PATH") {
                let client_ca_certs = load_certs(&client_ca_path)?;
                for cert in client_ca_certs {
                    client_auth_roots.add(cert)?;
                }
            }
            
            let client_auth = if client_auth_roots.is_empty() {
                // If no CA certs, use a verifier that accepts any client cert
                rustls::server::WebPkiClientVerifier::builder(Arc::new(rustls::RootCertStore::empty()))
                    .allow_unauthenticated()
                    .build()?
            } else {
                rustls::server::WebPkiClientVerifier::builder(Arc::new(client_auth_roots))
                    .build()?
            };
            
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(client_auth)
                .with_single_cert(certs, key)?
        } else {
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)?
        };

        Ok(config)
    }

    /// Generate self-signed certificate for development
    pub fn generate_self_signed() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        use rcgen::{generate_simple_self_signed, CertifiedKey};

        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names)?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        Ok((cert_pem.into_bytes(), key_pem.into_bytes()))
    }

    /// Save certificate and key to files
    pub async fn save_cert_and_key(
        cert_data: &[u8],
        key_data: &[u8],
        cert_path: &str,
        key_path: &str,
    ) -> anyhow::Result<()> {
        tokio::fs::write(cert_path, cert_data).await?;
        tokio::fs::write(key_path, key_data).await?;

        // Set appropriate permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tokio::fs::metadata(key_path).await?.permissions();
            perms.set_mode(0o400);
            tokio::fs::set_permissions(key_path, perms).await?;
        }
        
        #[cfg(windows)]
        {
            // Windows permission handling
            // Note: Full ACL control would require windows-acl crate
            // For now, we mark the file as hidden to provide basic protection
            use std::process::Command;
            let _ = Command::new("attrib")
                .arg("+H")
                .arg(key_path)
                .output();
            
            // Also try to restrict permissions using icacls (may fail on some systems)
            let _ = Command::new("icacls")
                .arg(key_path)
                .arg("/inheritance:r")
                .arg("/grant:r")
                .arg(format!("{}:(R)", std::env::var("USERNAME").unwrap_or_else(|_| "SYSTEM".to_string())))
                .output();
        }

        Ok(())
    }
}

/// Load certificates from PEM file
fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let cert_file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut reader)
        .map(|cert| cert.map(|c| c.to_owned()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

/// Load private key from PEM file
fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let key_file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(key_file);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKeyDer::Pkcs1(key)),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::Pkcs8(key)),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(PrivateKeyDer::Sec1(key)),
            None => break,
            _ => {}
        }
    }

    Err(anyhow::anyhow!("No private key found in file"))
}

/// Create or load TLS configuration
pub async fn setup_tls(data_dir: &Path) -> anyhow::Result<TlsConfig> {
    let cert_path = data_dir.join("api-cert.pem");
    let key_path = data_dir.join("api-key.pem");

    // Check if certificates exist
    if !cert_path.exists() || !key_path.exists() {
        tracing::info!("Generating self-signed certificate for HTTPS");
        let (cert, key) = TlsConfig::generate_self_signed()?;
        let cert_path_str = cert_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid certificate path"))?;
        let key_path_str = key_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid key path"))?;
        
        TlsConfig::save_cert_and_key(&cert, &key, cert_path_str, key_path_str).await?;
        tracing::info!("Self-signed certificate saved to {:?}", cert_path);
    }

    Ok(TlsConfig {
        cert_path: cert_path.to_string_lossy().to_string(),
        key_path: key_path.to_string_lossy().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio;
    
    #[test]
    fn test_tls_config_creation() {
        let config = TlsConfig {
            cert_path: "/path/to/cert.pem".to_string(),
            key_path: "/path/to/key.pem".to_string(),
        };
        
        assert_eq!(config.cert_path, "/path/to/cert.pem");
        assert_eq!(config.key_path, "/path/to/key.pem");
    }
    
    #[test]
    fn test_generate_self_signed() {
        let result = TlsConfig::generate_self_signed();
        assert!(result.is_ok());
        
        let (cert, key) = result.unwrap();
        
        // Check that we got PEM data
        assert!(cert.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(cert.ends_with(b"-----END CERTIFICATE-----\n"));
        
        assert!(key.starts_with(b"-----BEGIN PRIVATE KEY-----") || 
                key.starts_with(b"-----BEGIN RSA PRIVATE KEY-----") ||
                key.starts_with(b"-----BEGIN EC PRIVATE KEY-----"));
    }
    
    #[tokio::test]
    async fn test_save_cert_and_key() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("test.crt");
        let key_path = temp_dir.path().join("test.key");
        
        let cert_data = b"-----BEGIN CERTIFICATE-----\ntest cert\n-----END CERTIFICATE-----\n";
        let key_data = b"-----BEGIN PRIVATE KEY-----\ntest key\n-----END PRIVATE KEY-----\n";
        
        let result = TlsConfig::save_cert_and_key(
            cert_data,
            key_data,
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        ).await;
        
        assert!(result.is_ok());
        assert!(cert_path.exists());
        assert!(key_path.exists());
        
        // Verify content
        let saved_cert = tokio::fs::read(&cert_path).await.unwrap();
        let saved_key = tokio::fs::read(&key_path).await.unwrap();
        
        assert_eq!(saved_cert, cert_data);
        assert_eq!(saved_key, key_data);
        
        // Check permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = tokio::fs::metadata(&key_path).await.unwrap();
            let mode = metadata.permissions().mode();
            assert_eq!(mode & 0o777, 0o400); // Read-only for owner
        }
    }
    
    #[tokio::test]
    async fn test_setup_tls_creates_certs() {
        let temp_dir = TempDir::new().unwrap();
        
        let config = setup_tls(temp_dir.path()).await.unwrap();
        
        // Check that certificate files were created
        let cert_path = temp_dir.path().join("api-cert.pem");
        let key_path = temp_dir.path().join("api-key.pem");
        
        assert!(cert_path.exists());
        assert!(key_path.exists());
        
        assert_eq!(config.cert_path, cert_path.to_string_lossy());
        assert_eq!(config.key_path, key_path.to_string_lossy());
    }
    
    #[tokio::test]
    async fn test_setup_tls_uses_existing_certs() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("api-cert.pem");
        let key_path = temp_dir.path().join("api-key.pem");
        
        // Pre-create certificate files
        tokio::fs::write(&cert_path, b"existing cert").await.unwrap();
        tokio::fs::write(&key_path, b"existing key").await.unwrap();
        
        let config = setup_tls(temp_dir.path()).await.unwrap();
        
        // Verify it didn't overwrite existing files
        let cert_content = tokio::fs::read(&cert_path).await.unwrap();
        assert_eq!(cert_content, b"existing cert");
        
        assert_eq!(config.cert_path, cert_path.to_string_lossy());
        assert_eq!(config.key_path, key_path.to_string_lossy());
    }
    
    #[test]
    fn test_load_certs_valid() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("test.crt");
        
        // Generate actual certificate for testing
        let (cert_pem, _) = TlsConfig::generate_self_signed().unwrap();
        std::fs::write(&cert_path, cert_pem).unwrap();
        
        let result = load_certs(cert_path.to_str().unwrap());
        assert!(result.is_ok());
        
        let certs = result.unwrap();
        assert!(!certs.is_empty());
    }
    
    #[test]
    fn test_load_certs_invalid_file() {
        let result = load_certs("/nonexistent/path/cert.pem");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_load_certs_invalid_format() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("invalid.crt");
        
        std::fs::write(&cert_path, b"not a valid certificate").unwrap();
        
        let result = load_certs(cert_path.to_str().unwrap());
        assert!(result.is_ok()); // Returns empty vec for invalid PEM
        assert!(result.unwrap().is_empty());
    }
    
    #[test]
    fn test_load_key_valid() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test.key");
        
        // Generate actual key for testing
        let (_, key_pem) = TlsConfig::generate_self_signed().unwrap();
        std::fs::write(&key_path, key_pem).unwrap();
        
        let result = load_key(key_path.to_str().unwrap());
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_load_key_invalid_file() {
        let result = load_key("/nonexistent/path/key.pem");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_load_key_invalid_format() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("invalid.key");
        
        std::fs::write(&key_path, b"not a valid key").unwrap();
        
        let result = load_key(key_path.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No private key found"));
    }
    
    #[test]
    fn test_into_server_config() {
        let temp_dir = TempDir::new().unwrap();
        
        // Generate and save certificates
        let (cert_pem, key_pem) = TlsConfig::generate_self_signed().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();
        
        let config = TlsConfig {
            cert_path: cert_path.to_string_lossy().to_string(),
            key_path: key_path.to_string_lossy().to_string(),
        };
        
        let result = config.into_server_config();
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_into_server_config_with_client_auth() {
        let temp_dir = TempDir::new().unwrap();
        
        // Generate and save certificates
        let (cert_pem, key_pem) = TlsConfig::generate_self_signed().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();
        
        let config = TlsConfig {
            cert_path: cert_path.to_string_lossy().to_string(),
            key_path: key_path.to_string_lossy().to_string(),
        };
        
        // Test without client auth
        let result = config.clone().into_server_config_with_client_auth(false);
        assert!(result.is_ok());
        
        // Test with client auth (no CA configured)
        let result = config.into_server_config_with_client_auth(true);
        assert!(result.is_ok(), "Failed to create config with client auth: {:?}", result.unwrap_err());
    }
    
    #[test]
    fn test_into_server_config_with_client_ca() {
        let temp_dir = TempDir::new().unwrap();
        
        // Generate and save certificates
        let (cert_pem, key_pem) = TlsConfig::generate_self_signed().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        let ca_path = temp_dir.path().join("ca.pem");
        
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();
        std::fs::write(&ca_path, &cert_pem).unwrap(); // Use same cert as CA for testing
        
        // Set environment variable for client CA
        std::env::set_var("AURA_CLIENT_CA_PATH", ca_path.to_string_lossy().to_string());
        
        let config = TlsConfig {
            cert_path: cert_path.to_string_lossy().to_string(),
            key_path: key_path.to_string_lossy().to_string(),
        };
        
        let result = config.into_server_config_with_client_auth(true);
        assert!(result.is_ok());
        
        // Clean up env var
        std::env::remove_var("AURA_CLIENT_CA_PATH");
    }
    
    #[tokio::test]
    async fn test_build_acceptor() {
        let temp_dir = TempDir::new().unwrap();
        
        // Generate and save certificates
        let (cert_pem, key_pem) = TlsConfig::generate_self_signed().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();
        
        let config = TlsConfig {
            cert_path: cert_path.to_string_lossy().to_string(),
            key_path: key_path.to_string_lossy().to_string(),
        };
        
        let result = config.build_acceptor().await;
        assert!(result.is_ok());
    }
}
