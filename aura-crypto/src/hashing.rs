use crate::Result;
use blake3::Hasher as Blake3Hasher;
use serde::Serialize;
use sha2::{Digest as Sha2Digest, Sha256};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

pub fn sha256_json<T: Serialize>(data: &T) -> Result<[u8; 32]> {
    let json =
        serde_json::to_vec(data).map_err(|e| crate::CryptoError::InvalidKey(e.to_string()))?;
    Ok(sha256(&json))
}

pub fn blake3_json<T: Serialize>(data: &T) -> Result<[u8; 32]> {
    let json =
        serde_json::to_vec(data).map_err(|e| crate::CryptoError::InvalidKey(e.to_string()))?;
    Ok(blake3(&json))
}
