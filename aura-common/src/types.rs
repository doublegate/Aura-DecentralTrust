use bincode::{Decode, Encode};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode)]
pub struct AuraDid(pub String);

impl AuraDid {
    pub fn new(identifier: &str) -> Self {
        Self(format!("did:aura:{identifier}"))
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub DateTime<Utc>);

impl bincode::Encode for Timestamp {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.0.timestamp().encode(encoder)
    }
}

impl bincode::Decode<()> for Timestamp {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let timestamp = i64::decode(decoder)?;
        let dt = DateTime::from_timestamp(timestamp, 0)
            .ok_or(bincode::error::DecodeError::Other("Invalid timestamp"))?;
        Ok(Self(dt))
    }
}

impl<'de> bincode::BorrowDecode<'de, ()> for Timestamp {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let timestamp = i64::borrow_decode(decoder)?;
        let dt = DateTime::from_timestamp(timestamp, 0)
            .ok_or(bincode::error::DecodeError::Other("Invalid timestamp"))?;
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

    pub fn from_unix(timestamp: i64) -> Self {
        let dt = DateTime::from_timestamp(timestamp, 0).unwrap_or_else(Utc::now);
        Self(dt)
    }

    pub fn as_unix(&self) -> i64 {
        self.0.timestamp()
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

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::{decode_from_slice, encode_to_vec};

    #[test]
    fn test_aura_did_new() {
        let did = AuraDid::new("test123");
        assert_eq!(did.0, "did:aura:test123");
        assert_eq!(did.identifier(), "test123");
    }

    #[test]
    fn test_aura_did_from_string_valid() {
        let did = AuraDid::from_string("did:aura:test456".to_string()).unwrap();
        assert_eq!(did.0, "did:aura:test456");
        assert_eq!(did.identifier(), "test456");
    }

    #[test]
    fn test_aura_did_from_string_invalid() {
        let result = AuraDid::from_string("invalid:did".to_string());
        assert!(result.is_err());
        match result {
            Err(crate::AuraError::Did(msg)) => assert_eq!(msg, "Invalid DID format"),
            _ => panic!("Expected Did error"),
        }
    }

    #[test]
    fn test_aura_did_from_string_empty() {
        let result = AuraDid::from_string("".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_aura_did_display() {
        let did = AuraDid::new("display_test");
        assert_eq!(format!("{}", did), "did:aura:display_test");
    }

    #[test]
    fn test_aura_did_clone_and_eq() {
        let did1 = AuraDid::new("test");
        let did2 = did1.clone();
        assert_eq!(did1, did2);
    }

    #[test]
    fn test_aura_did_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        let did = AuraDid::new("hashtest");
        set.insert(did.clone());
        assert!(set.contains(&did));
    }

    #[test]
    fn test_aura_did_serialization() {
        let did = AuraDid::new("serde_test");
        let json = serde_json::to_string(&did).unwrap();
        let deserialized: AuraDid = serde_json::from_str(&json).unwrap();
        assert_eq!(did, deserialized);
    }

    #[test]
    fn test_aura_did_bincode() {
        let did = AuraDid::new("bincode_test");
        let encoded = encode_to_vec(&did, bincode::config::standard()).unwrap();
        let (decoded, _): (AuraDid, _) = decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(did, decoded);
    }

    #[test]
    fn test_timestamp_now() {
        let before = Utc::now();
        let timestamp = Timestamp::now();
        let after = Utc::now();
        
        assert!(timestamp.0 >= before);
        assert!(timestamp.0 <= after);
    }

    #[test]
    fn test_timestamp_default() {
        let before = Utc::now();
        let timestamp = Timestamp::default();
        let after = Utc::now();
        
        assert!(timestamp.0 >= before);
        assert!(timestamp.0 <= after);
    }

    #[test]
    fn test_timestamp_from_unix() {
        let unix_time = 1704067200; // 2024-01-01 00:00:00 UTC
        let timestamp = Timestamp::from_unix(unix_time);
        assert_eq!(timestamp.as_unix(), unix_time);
    }

    #[test]
    fn test_timestamp_from_unix_negative() {
        let unix_time = -100; // Before epoch
        let timestamp = Timestamp::from_unix(unix_time);
        assert_eq!(timestamp.as_unix(), unix_time);
    }

    #[test]
    fn test_timestamp_from_unix_invalid() {
        // Test with an invalid timestamp that would overflow
        let unix_time = i64::MAX;
        let timestamp = Timestamp::from_unix(unix_time);
        // Should fall back to current time
        assert!(timestamp.as_unix() > 0);
    }

    #[test]
    fn test_timestamp_serialization() {
        let timestamp = Timestamp::from_unix(1704067200);
        let json = serde_json::to_string(&timestamp).unwrap();
        let deserialized: Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(timestamp.as_unix(), deserialized.as_unix());
    }

    #[test]
    fn test_timestamp_bincode() {
        let timestamp = Timestamp::from_unix(1704067200);
        let encoded = encode_to_vec(&timestamp, bincode::config::standard()).unwrap();
        let (decoded, _): (Timestamp, _) = decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(timestamp.as_unix(), decoded.as_unix());
    }

    #[test]
    fn test_timestamp_bincode_edge_cases() {
        // Test with edge case timestamps
        let timestamps = vec![
            Timestamp::from_unix(0),            // Epoch
            Timestamp::from_unix(-1),           // Before epoch
            Timestamp::from_unix(i32::MAX as i64), // Large positive
            Timestamp::from_unix(i32::MIN as i64), // Large negative
        ];

        for timestamp in timestamps {
            let encoded = encode_to_vec(&timestamp, bincode::config::standard()).unwrap();
            let (decoded, _): (Timestamp, _) = decode_from_slice(&encoded, bincode::config::standard()).unwrap();
            assert_eq!(timestamp.as_unix(), decoded.as_unix());
        }
    }

    #[test]
    fn test_block_number() {
        let block = BlockNumber(42);
        assert_eq!(block.0, 42);

        // Test serialization
        let json = serde_json::to_string(&block).unwrap();
        let deserialized: BlockNumber = serde_json::from_str(&json).unwrap();
        assert_eq!(block.0, deserialized.0);

        // Test bincode
        let encoded = encode_to_vec(&block, bincode::config::standard()).unwrap();
        let (decoded, _): (BlockNumber, _) = decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(block.0, decoded.0);
    }

    #[test]
    fn test_block_number_edge_cases() {
        let blocks = vec![
            BlockNumber(0),
            BlockNumber(1),
            BlockNumber(u64::MAX),
        ];

        for block in blocks {
            let encoded = encode_to_vec(&block, bincode::config::standard()).unwrap();
            let (decoded, _): (BlockNumber, _) = decode_from_slice(&encoded, bincode::config::standard()).unwrap();
            assert_eq!(block.0, decoded.0);
        }
    }

    #[test]
    fn test_transaction_id() {
        let tx_id = TransactionId("tx123".to_string());
        assert_eq!(tx_id.0, "tx123");

        // Test with empty string
        let empty_tx = TransactionId("".to_string());
        assert_eq!(empty_tx.0, "");

        // Test serialization
        let json = serde_json::to_string(&tx_id).unwrap();
        let deserialized: TransactionId = serde_json::from_str(&json).unwrap();
        assert_eq!(tx_id.0, deserialized.0);

        // Test bincode
        let encoded = encode_to_vec(&tx_id, bincode::config::standard()).unwrap();
        let (decoded, _): (TransactionId, _) = decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(tx_id.0, decoded.0);
    }

    #[test]
    fn test_transaction_id_special_chars() {
        let special_chars = "tx-123_ABC.xyz~!@#$%^&*()";
        let tx_id = TransactionId(special_chars.to_string());
        
        let encoded = encode_to_vec(&tx_id, bincode::config::standard()).unwrap();
        let (decoded, _): (TransactionId, _) = decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(tx_id.0, decoded.0);
    }

    #[test]
    fn test_public_key() {
        let did = AuraDid::new("controller");
        let key = PublicKey {
            id: "key1".to_string(),
            controller: did.clone(),
            public_key_multibase: "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_string(),
        };

        assert_eq!(key.id, "key1");
        assert_eq!(key.controller, did);

        // Test serialization
        let json = serde_json::to_string(&key).unwrap();
        let deserialized: PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key.id, deserialized.id);
        assert_eq!(key.controller, deserialized.controller);
        assert_eq!(key.public_key_multibase, deserialized.public_key_multibase);

        // Test bincode
        let encoded = encode_to_vec(&key, bincode::config::standard()).unwrap();
        let (decoded, _): (PublicKey, _) = decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(key.id, decoded.id);
        assert_eq!(key.controller, decoded.controller);
        assert_eq!(key.public_key_multibase, decoded.public_key_multibase);
    }

    #[test]
    fn test_public_key_empty_fields() {
        let did = AuraDid::new("empty_controller");
        let key = PublicKey {
            id: "".to_string(),
            controller: did,
            public_key_multibase: "".to_string(),
        };

        let encoded = encode_to_vec(&key, bincode::config::standard()).unwrap();
        let (decoded, _): (PublicKey, _) = decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(key.id, decoded.id);
        assert_eq!(key.public_key_multibase, decoded.public_key_multibase);
    }

    #[test]
    fn test_service_endpoint() {
        let endpoint = ServiceEndpoint {
            id: "service1".to_string(),
            service_type: "VerifiableCredentialService".to_string(),
            service_endpoint: "https://example.com/vc".to_string(),
        };

        assert_eq!(endpoint.id, "service1");
        assert_eq!(endpoint.service_type, "VerifiableCredentialService");
        assert_eq!(endpoint.service_endpoint, "https://example.com/vc");

        // Test serialization
        let json = serde_json::to_string(&endpoint).unwrap();
        let deserialized: ServiceEndpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(endpoint.id, deserialized.id);
        assert_eq!(endpoint.service_type, deserialized.service_type);
        assert_eq!(endpoint.service_endpoint, deserialized.service_endpoint);

        // Test bincode
        let encoded = encode_to_vec(&endpoint, bincode::config::standard()).unwrap();
        let (decoded, _): (ServiceEndpoint, _) = decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(endpoint.id, decoded.id);
        assert_eq!(endpoint.service_type, decoded.service_type);
        assert_eq!(endpoint.service_endpoint, decoded.service_endpoint);
    }

    #[test]
    fn test_service_endpoint_various_urls() {
        let endpoints = vec![
            ("http://localhost:8080", "HTTP local"),
            ("https://example.com:443/path", "HTTPS with port"),
            ("did:web:example.com", "DID URL"),
            ("ipfs://QmHash", "IPFS URL"),
            ("", "Empty URL"),
        ];

        for (url, desc) in endpoints {
            let endpoint = ServiceEndpoint {
                id: desc.to_string(),
                service_type: "TestService".to_string(),
                service_endpoint: url.to_string(),
            };

            let encoded = encode_to_vec(&endpoint, bincode::config::standard()).unwrap();
            let (decoded, _): (ServiceEndpoint, _) = decode_from_slice(&encoded, bincode::config::standard()).unwrap();
            assert_eq!(endpoint.service_endpoint, decoded.service_endpoint);
        }
    }

    #[test]
    fn test_debug_implementations() {
        // Test that all types implement Debug
        let did = AuraDid::new("debug_test");
        let timestamp = Timestamp::now();
        let block = BlockNumber(100);
        let tx_id = TransactionId("tx_debug".to_string());
        let key = PublicKey {
            id: "key_debug".to_string(),
            controller: did.clone(),
            public_key_multibase: "z6Mk...".to_string(),
        };
        let endpoint = ServiceEndpoint {
            id: "service_debug".to_string(),
            service_type: "DebugService".to_string(),
            service_endpoint: "https://debug.example.com".to_string(),
        };

        // Just ensure Debug formatting doesn't panic
        assert!(!format!("{:?}", did).is_empty());
        assert!(!format!("{:?}", timestamp).is_empty());
        assert!(!format!("{:?}", block).is_empty());
        assert!(!format!("{:?}", tx_id).is_empty());
        assert!(!format!("{:?}", key).is_empty());
        assert!(!format!("{:?}", endpoint).is_empty());
    }

    #[test]
    fn test_clone_implementations() {
        // Test that all types implement Clone correctly
        let did = AuraDid::new("clone_test");
        let did_clone = did.clone();
        assert_eq!(did, did_clone);

        let timestamp = Timestamp::now();
        let timestamp_clone = timestamp.clone();
        assert_eq!(timestamp.as_unix(), timestamp_clone.as_unix());

        let block = BlockNumber(42);
        let block_clone = block.clone();
        assert_eq!(block.0, block_clone.0);

        let tx_id = TransactionId("tx_clone".to_string());
        let tx_id_clone = tx_id.clone();
        assert_eq!(tx_id.0, tx_id_clone.0);
    }

    // Property-based tests using quickcheck would be added here if the dependency was included
    // For now, we'll add some pseudo-random tests

    #[test]
    fn test_did_identifier_extraction_various_formats() {
        let test_cases = vec![
            ("simple", "simple"),
            ("with-dash", "with-dash"),
            ("with_underscore", "with_underscore"),
            ("123numeric", "123numeric"),
            ("MixedCase123", "MixedCase123"),
            ("special!@#$%", "special!@#$%"),
        ];

        for (input, expected) in test_cases {
            let did = AuraDid::new(input);
            assert_eq!(did.identifier(), expected);
        }
    }

    #[test]
    fn test_concurrent_timestamp_creation() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let timestamps = Arc::new(Mutex::new(Vec::new()));
        let mut handles = vec![];

        for _ in 0..10 {
            let timestamps_clone = Arc::clone(&timestamps);
            let handle = thread::spawn(move || {
                let ts = Timestamp::now();
                timestamps_clone.lock().unwrap().push(ts);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let timestamps = timestamps.lock().unwrap();
        assert_eq!(timestamps.len(), 10);
        
        // All timestamps should be very close in time
        let first = timestamps[0].as_unix();
        for ts in timestamps.iter() {
            assert!((ts.as_unix() - first).abs() < 2); // Within 2 seconds
        }
    }
}
