use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use bincode::{Encode, Decode};
use crate::{CryptoError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

pub fn generate_encryption_key() -> [u8; 32] {
    let key = Aes256Gcm::generate_key(OsRng);
    key.into()
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedData> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
    
    Ok(EncryptedData {
        ciphertext,
        nonce: nonce.to_vec(),
    })
}

pub fn decrypt(key: &[u8; 32], encrypted: &EncryptedData) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&encrypted.nonce);
    
    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    
    Ok(plaintext)
}

pub fn encrypt_json<T: Serialize>(key: &[u8; 32], data: &T) -> Result<EncryptedData> {
    let json = serde_json::to_vec(data)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
    encrypt(key, &json)
}

pub fn decrypt_json<T: for<'a> Deserialize<'a>>(
    key: &[u8; 32],
    encrypted: &EncryptedData,
) -> Result<T> {
    let plaintext = decrypt(key, encrypted)?;
    let data = serde_json::from_slice(&plaintext)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    Ok(data)
}