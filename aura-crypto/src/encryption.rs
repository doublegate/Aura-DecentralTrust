use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use bincode::{Encode, Decode};
use zeroize::{Zeroize, Zeroizing};
use crate::{CryptoError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Generate a new encryption key wrapped in Zeroizing for automatic cleanup
pub fn generate_encryption_key() -> Zeroizing<[u8; 32]> {
    let key = Aes256Gcm::generate_key(OsRng);
    Zeroizing::new(key.into())
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedData> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    // Clear plaintext from memory after encryption
    let mut plaintext_copy = plaintext.to_vec();
    let ciphertext = cipher
        .encrypt(&nonce, plaintext_copy.as_slice())
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
    plaintext_copy.zeroize();
    
    Ok(EncryptedData {
        ciphertext,
        nonce: nonce.to_vec(),
    })
}

/// Decrypt data and return it wrapped in Zeroizing for automatic cleanup
pub fn decrypt(key: &[u8; 32], encrypted: &EncryptedData) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&encrypted.nonce);
    
    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    
    Ok(Zeroizing::new(plaintext))
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
    let data = serde_json::from_slice(&*plaintext)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    Ok(data)
}