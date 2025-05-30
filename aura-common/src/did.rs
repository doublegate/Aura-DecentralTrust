use serde::{Deserialize, Serialize};
use crate::{AuraDid, PublicKey, ServiceEndpoint, Timestamp, Result};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
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