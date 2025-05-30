pub mod signing;
pub mod encryption;
pub mod hashing;
pub mod keys;

pub use signing::*;
pub use encryption::*;
pub use hashing::*;
pub use keys::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    
    #[error("Signing error: {0}")]
    SigningError(String),
    
    #[error("Verification error: {0}")]
    VerificationError(String),
    
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;