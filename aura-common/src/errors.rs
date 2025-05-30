use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuraError {
    #[error("DID error: {0}")]
    Did(String),
    
    #[error("Verifiable Credential error: {0}")]
    Vc(String),
    
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    #[error("Ledger error: {0}")]
    Ledger(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Storage error: {0}")]
    Storage(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Invalid proof")]
    InvalidProof,
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Already exists: {0}")]
    AlreadyExists(String),
    
    #[error("Unauthorized")]
    Unauthorized,
    
    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, AuraError>;