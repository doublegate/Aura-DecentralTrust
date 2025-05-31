use crate::{CryptoError, PrivateKey, PublicKey, Result};
use bincode::{Decode, Encode};
use ed25519_dalek::{Signature as Ed25519Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Signature(pub Vec<u8>);

impl Signature {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidKey(
                "Invalid signature length".to_string(),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub fn sign(private_key: &PrivateKey, message: &[u8]) -> Result<Signature> {
    let signature = private_key.signing_key().sign(message);
    Ok(Signature(signature.to_vec()))
}

pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool> {
    if signature.0.len() != 64 {
        return Ok(false);
    }

    let sig = Ed25519Signature::from_slice(&signature.0)
        .map_err(|e| CryptoError::VerificationError(e.to_string()))?;

    match public_key.verifying_key().verify(message, &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn sign_json<T: Serialize>(private_key: &PrivateKey, data: &T) -> Result<Signature> {
    let json = serde_json::to_vec(data).map_err(|e| CryptoError::SigningError(e.to_string()))?;
    sign(private_key, &json)
}

pub fn verify_json<T: Serialize>(
    public_key: &PublicKey,
    data: &T,
    signature: &Signature,
) -> Result<bool> {
    let json =
        serde_json::to_vec(data).map_err(|e| CryptoError::VerificationError(e.to_string()))?;
    verify(public_key, &json, signature)
}
