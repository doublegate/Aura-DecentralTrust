use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuraDid(pub String);

impl AuraDid {
    pub fn new(identifier: &str) -> Self {
        Self(format!("did:aura:{}", identifier))
    }
    
    pub fn from_string(did: String) -> crate::Result<Self> {
        if !did.starts_with("did:aura:") {
            return Err(crate::AuraError::Did("Invalid DID format".to_string()));
        }
        Ok(Self(did))
    }
    
    pub fn identifier(&self) -> &str {
        self.0.strip_prefix("did:aura:").unwrap_or(&self.0)
    }
}

impl std::fmt::Display for AuraDid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timestamp(pub DateTime<Utc>);

impl Default for Timestamp {
    fn default() -> Self {
        Self(Utc::now())
    }
}

impl Timestamp {
    pub fn now() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockNumber(pub u64);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub id: String,
    pub controller: AuraDid,
    pub public_key_multibase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    pub service_type: String,
    pub service_endpoint: String,
}