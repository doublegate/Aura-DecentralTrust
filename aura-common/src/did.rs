use crate::{AuraDid, ServiceEndpoint, Timestamp};
use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: AuraDid,
    pub controller: Option<AuraDid>,
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<VerificationRelationship>,
    pub assertion_method: Vec<VerificationRelationship>,
    pub key_agreement: Vec<VerificationRelationship>,
    pub capability_invocation: Vec<VerificationRelationship>,
    pub capability_delegation: Vec<VerificationRelationship>,
    pub service: Vec<ServiceEndpoint>,
    pub created: Timestamp,
    pub updated: Timestamp,
}

impl DidDocument {
    pub fn new(did: AuraDid) -> Self {
        Self {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            id: did,
            controller: None,
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            capability_invocation: Vec::new(),
            capability_delegation: Vec::new(),
            service: Vec::new(),
            created: Timestamp::now(),
            updated: Timestamp::now(),
        }
    }

    pub fn add_verification_method(&mut self, method: VerificationMethod) {
        self.verification_method.push(method);
        self.updated = Timestamp::now();
    }

    pub fn add_service(&mut self, service: ServiceEndpoint) {
        self.service.push(service);
        self.updated = Timestamp::now();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub id: String,
    pub controller: AuraDid,
    #[serde(rename = "type")]
    pub verification_type: String,
    pub public_key_multibase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VerificationRelationship {
    Reference(String),
    Embedded(VerificationMethod),
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct DidRecord {
    pub did_id: AuraDid,
    pub did_document_hash: Vec<u8>,
    pub owner_public_key: Vec<u8>,
    pub last_updated_block: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidRegistration {
    pub did_document: DidDocument,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidUpdate {
    pub did_id: AuraDid,
    pub new_did_document: DidDocument,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDeactivation {
    pub did_id: AuraDid,
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuraDid;

    fn create_test_did() -> AuraDid {
        AuraDid("did:aura:test123".to_string())
    }

    fn create_test_verification_method() -> VerificationMethod {
        VerificationMethod {
            id: "did:aura:test123#key-1".to_string(),
            controller: create_test_did(),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            public_key_multibase: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
        }
    }

    fn create_test_service() -> ServiceEndpoint {
        ServiceEndpoint {
            id: "did:aura:test123#service-1".to_string(),
            service_type: "MessagingService".to_string(),
            service_endpoint: "https://example.com/messaging".to_string(),
        }
    }

    #[test]
    fn test_did_document_new() {
        let did = create_test_did();
        let doc = DidDocument::new(did.clone());

        assert_eq!(doc.id, did);
        assert_eq!(doc.context.len(), 2);
        assert_eq!(doc.context[0], "https://www.w3.org/ns/did/v1");
        assert_eq!(doc.context[1], "https://w3id.org/security/suites/ed25519-2020/v1");
        assert!(doc.controller.is_none());
        assert!(doc.verification_method.is_empty());
        assert!(doc.authentication.is_empty());
        assert!(doc.assertion_method.is_empty());
        assert!(doc.key_agreement.is_empty());
        assert!(doc.capability_invocation.is_empty());
        assert!(doc.capability_delegation.is_empty());
        assert!(doc.service.is_empty());
    }

    #[test]
    fn test_did_document_add_verification_method() {
        let did = create_test_did();
        let mut doc = DidDocument::new(did);
        let created_time = doc.created;
        let initial_updated = doc.updated;
        
        // Sleep briefly to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        let method = create_test_verification_method();
        doc.add_verification_method(method.clone());

        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.verification_method[0].id, method.id);
        assert_eq!(doc.created, created_time); // Created shouldn't change
        assert!(doc.updated > initial_updated); // Updated should be newer
    }

    #[test]
    fn test_did_document_add_service() {
        let did = create_test_did();
        let mut doc = DidDocument::new(did);
        let initial_updated = doc.updated;
        
        // Sleep briefly to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        let service = create_test_service();
        doc.add_service(service.clone());

        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].id, service.id);
        assert!(doc.updated > initial_updated);
    }

    #[test]
    fn test_did_document_serialization() {
        let did = create_test_did();
        let mut doc = DidDocument::new(did);
        doc.add_verification_method(create_test_verification_method());
        doc.add_service(create_test_service());

        // Test JSON serialization
        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("@context"));
        assert!(json.contains("verificationMethod"));
        assert!(json.contains("service"));

        // Test JSON deserialization
        let deserialized: DidDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, doc.id);
        assert_eq!(deserialized.verification_method.len(), 1);
        assert_eq!(deserialized.service.len(), 1);
    }

    #[test]
    fn test_verification_relationship_variants() {
        // Test Reference variant
        let reference = VerificationRelationship::Reference("did:aura:test#key-1".to_string());
        let json = serde_json::to_string(&reference).unwrap();
        assert_eq!(json, "\"did:aura:test#key-1\"");

        // Test Embedded variant
        let method = create_test_verification_method();
        let embedded = VerificationRelationship::Embedded(method.clone());
        let json = serde_json::to_string(&embedded).unwrap();
        assert!(json.contains("controller"));
        assert!(json.contains("type"));
    }

    #[test]
    fn test_did_record_bincode_serialization() {
        let record = DidRecord {
            did_id: create_test_did(),
            did_document_hash: vec![1, 2, 3, 4],
            owner_public_key: vec![5, 6, 7, 8],
            last_updated_block: 42,
            active: true,
        };

        // Test bincode encoding
        let encoded = bincode::encode_to_vec(&record, bincode::config::standard()).unwrap();
        assert!(!encoded.is_empty());

        // Test bincode decoding
        let (decoded, _): (DidRecord, _) = bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(decoded.did_id, record.did_id);
        assert_eq!(decoded.did_document_hash, record.did_document_hash);
        assert_eq!(decoded.owner_public_key, record.owner_public_key);
        assert_eq!(decoded.last_updated_block, record.last_updated_block);
        assert_eq!(decoded.active, record.active);
    }

    #[test]
    fn test_did_registration_structure() {
        let did = create_test_did();
        let doc = DidDocument::new(did);
        let registration = DidRegistration {
            did_document: doc.clone(),
            signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        assert_eq!(registration.did_document.id, doc.id);
        assert_eq!(registration.signature, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_did_update_structure() {
        let did = create_test_did();
        let doc = DidDocument::new(did.clone());
        let update = DidUpdate {
            did_id: did.clone(),
            new_did_document: doc.clone(),
            signature: vec![0xCA, 0xFE, 0xBA, 0xBE],
        };

        assert_eq!(update.did_id, did);
        assert_eq!(update.new_did_document.id, doc.id);
        assert_eq!(update.signature, vec![0xCA, 0xFE, 0xBA, 0xBE]);
    }

    #[test]
    fn test_did_deactivation_structure() {
        let did = create_test_did();
        let deactivation = DidDeactivation {
            did_id: did.clone(),
            signature: vec![0xAB, 0xCD, 0xEF, 0x12],
        };

        assert_eq!(deactivation.did_id, did);
        assert_eq!(deactivation.signature, vec![0xAB, 0xCD, 0xEF, 0x12]);
    }

    #[test]
    fn test_did_document_with_controller() {
        let did = create_test_did();
        let controller_did = AuraDid("did:aura:controller123".to_string());
        let mut doc = DidDocument::new(did);
        doc.controller = Some(controller_did.clone());

        assert_eq!(doc.controller, Some(controller_did));
    }

    #[test]
    fn test_did_document_with_all_relationships() {
        let did = create_test_did();
        let mut doc = DidDocument::new(did);
        let method = create_test_verification_method();
        
        // Add verification method
        doc.add_verification_method(method.clone());
        
        // Add to all relationship types
        doc.authentication.push(VerificationRelationship::Reference(method.id.clone()));
        doc.assertion_method.push(VerificationRelationship::Embedded(method.clone()));
        doc.key_agreement.push(VerificationRelationship::Reference(method.id.clone()));
        doc.capability_invocation.push(VerificationRelationship::Reference(method.id.clone()));
        doc.capability_delegation.push(VerificationRelationship::Reference(method.id.clone()));

        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1);
        assert_eq!(doc.key_agreement.len(), 1);
        assert_eq!(doc.capability_invocation.len(), 1);
        assert_eq!(doc.capability_delegation.len(), 1);
    }
}
