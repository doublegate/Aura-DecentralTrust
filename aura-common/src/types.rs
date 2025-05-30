use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use bincode::{Encode, Decode};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode)]
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

impl bincode::Encode for Timestamp {
    fn encode<E: bincode::enc::Encoder>(&self, encoder: &mut E) -> Result<(), bincode::error::EncodeError> {
        self.0.timestamp().encode(encoder)
    }
}

impl bincode::Decode<()> for Timestamp {
    fn decode<D: bincode::de::Decoder>(decoder: &mut D) -> Result<Self, bincode::error::DecodeError> {
        let timestamp = i64::decode(decoder)?;
        let dt = DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| bincode::error::DecodeError::Other("Invalid timestamp"))?;
        Ok(Self(dt))
    }
}

impl<'de> bincode::BorrowDecode<'de, ()> for Timestamp {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(decoder: &mut D) -> Result<Self, bincode::error::DecodeError> {
        let timestamp = i64::borrow_decode(decoder)?;
        let dt = DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| bincode::error::DecodeError::Other("Invalid timestamp"))?;
        Ok(Self(dt))
    }
}

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode)]
pub struct BlockNumber(pub u64);

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct TransactionId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct PublicKey {
    pub id: String,
    pub controller: AuraDid,
    pub public_key_multibase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct ServiceEndpoint {
    pub id: String,
    pub service_type: String,
    pub service_endpoint: String,
}