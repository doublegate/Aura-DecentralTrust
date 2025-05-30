use serde::{Deserialize, Serialize};
use serde_json::Value;
use bincode::{Encode, Decode};
use crate::{AuraDid, Timestamp};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    pub issuer: CredentialIssuer,
    pub issuance_date: Timestamp,
    pub expiration_date: Option<Timestamp>,
    pub credential_subject: CredentialSubject,
    pub credential_status: Option<CredentialStatus>,
    pub proof: Option<Proof>,
}

impl VerifiableCredential {
    pub fn new(
        issuer: AuraDid,
        subject: AuraDid,
        credential_type: Vec<String>,
        claims: HashMap<String, Value>,
    ) -> Self {
        let mut types = vec!["VerifiableCredential".to_string()];
        types.extend(credential_type);
        
        Self {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            id: None,
            credential_type: types,
            issuer: CredentialIssuer::Did(issuer),
            issuance_date: Timestamp::now(),
            expiration_date: None,
            credential_subject: CredentialSubject {
                id: Some(subject),
                claims,
            },
            credential_status: None,
            proof: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialIssuer {
    Did(AuraDid),
    Object {
        id: AuraDid,
        name: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    pub id: Option<AuraDid>,
    #[serde(flatten)]
    pub claims: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    pub id: String,
    #[serde(rename = "type")]
    pub status_type: String,
    pub status_list_index: Option<u32>,
    pub status_list_credential: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: Timestamp,
    pub verification_method: String,
    pub proof_purpose: String,
    pub proof_value: String,
    pub challenge: Option<String>,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiablePresentation {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub presentation_type: Vec<String>,
    pub holder: AuraDid,
    pub verifiable_credential: Vec<VerifiableCredential>,
    pub proof: Option<Proof>,
}

impl VerifiablePresentation {
    pub fn new(holder: AuraDid, credentials: Vec<VerifiableCredential>) -> Self {
        Self {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            id: None,
            presentation_type: vec!["VerifiablePresentation".to_string()],
            holder,
            verifiable_credential: credentials,
            proof: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSchema {
    pub id: String,
    pub schema_type: String,
    pub name: String,
    pub version: String,
    pub author: AuraDid,
    pub created: Timestamp,
    pub schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SchemaRecord {
    pub schema_id: String,
    pub schema_content_hash: Vec<u8>,
    pub issuer_did: AuraDid,
    pub registered_at_block: u64,
}