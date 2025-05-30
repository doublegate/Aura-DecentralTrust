use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use crate::{CryptoError, Result};

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct PrivateKey {
    key: SigningKey,
}

impl PrivateKey {
    pub fn generate() -> Result<Self> {
        let mut csprng = OsRng;
        let key = SigningKey::generate(&mut csprng);
        Ok(Self { key })
    }
    
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey("Invalid private key length".to_string()));
        }
        
        let key = SigningKey::from_bytes(bytes.try_into().unwrap());
        Ok(Self { key })
    }
    
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
    
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            key: self.key.verifying_key(),
        }
    }
    
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    key: VerifyingKey,
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey("Invalid public key length".to_string()));
        }
        
        let key = VerifyingKey::from_bytes(bytes.try_into().unwrap())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        Ok(Self { key })
    }
    
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
    
    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Result<Self> {
        let private_key = PrivateKey::generate()?;
        let public_key = private_key.public_key();
        Ok(Self {
            private_key,
            public_key,
        })
    }
    
    pub fn from_private_key(private_key: PrivateKey) -> Self {
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }
    
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }
    
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}