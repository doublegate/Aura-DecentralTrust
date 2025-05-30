use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use crate::{CryptoError, Result};

pub struct PrivateKey {
    key: SigningKey,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Manually zeroize the key bytes
        let mut bytes = self.key.to_bytes();
        bytes.zeroize();
    }
}

impl PrivateKey {
    pub fn generate() -> Result<Self> {
        let mut csprng = OsRng;
        let key = SigningKey::from_bytes(&rand::Rng::gen::<[u8; 32]>(&mut csprng));
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PublicKey {
    key: VerifyingKey,
}

impl bincode::Encode for PublicKey {
    fn encode<E: bincode::enc::Encoder>(&self, encoder: &mut E) -> std::result::Result<(), bincode::error::EncodeError> {
        self.key.to_bytes().encode(encoder)
    }
}

impl bincode::Decode<()> for PublicKey {
    fn decode<D: bincode::de::Decoder>(decoder: &mut D) -> std::result::Result<Self, bincode::error::DecodeError> {
        let bytes = <[u8; 32]>::decode(decoder)?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| bincode::error::DecodeError::Other("Invalid public key"))?;
        Ok(Self { key })
    }
}

impl<'de> bincode::BorrowDecode<'de, ()> for PublicKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(decoder: &mut D) -> std::result::Result<Self, bincode::error::DecodeError> {
        let bytes = <[u8; 32]>::borrow_decode(decoder)?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| bincode::error::DecodeError::Other("Invalid public key"))?;
        Ok(Self { key })
    }
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

#[derive(Debug)]
pub struct KeyPair {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl Clone for KeyPair {
    fn clone(&self) -> Self {
        let private_key = PrivateKey::from_bytes(&self.private_key.to_bytes()).unwrap();
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }
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