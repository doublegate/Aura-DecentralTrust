use std::path::Path;
use std::sync::Arc;
use tokio_rustls::rustls::{self, Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;

/// TLS configuration for the API server
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

impl TlsConfig {
    /// Create TLS acceptor from certificate and key files
    pub async fn build_acceptor(&self) -> anyhow::Result<TlsAcceptor> {
        let certs = load_certs(&self.cert_path)?;
        let key = load_key(&self.key_path)?;
        
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
            
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
    
    /// Generate self-signed certificate for development
    pub fn generate_self_signed() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        use rcgen::{generate_simple_self_signed, CertifiedKey};
        
        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names)?;
        
        let cert_pem = cert.serialize_pem()?;
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
        
        // Set appropriate permissions (read-only for owner)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tokio::fs::metadata(key_path).await?.permissions();
            perms.set_mode(0o400);
            tokio::fs::set_permissions(key_path, perms).await?;
        }
        
        Ok(())
    }
}

/// Load certificates from PEM file
fn load_certs(path: &str) -> anyhow::Result<Vec<Certificate>> {
    let cert_file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut reader)?
        .into_iter()
        .map(Certificate)
        .collect();
    Ok(certs)
}

/// Load private key from PEM file
fn load_key(path: &str) -> anyhow::Result<PrivateKey> {
    let key_file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(key_file);
    
    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(PrivateKey(key)),
            Some(rustls_pemfile::Item::ECKey(key)) => return Ok(PrivateKey(key)),
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
        TlsConfig::save_cert_and_key(
            &cert,
            &key,
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        ).await?;
        tracing::info!("Self-signed certificate saved to {:?}", cert_path);
    }
    
    Ok(TlsConfig {
        cert_path: cert_path.to_string_lossy().to_string(),
        key_path: key_path.to_string_lossy().to_string(),
    })
}