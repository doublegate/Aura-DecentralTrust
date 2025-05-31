use crate::{AuraDid, Timestamp};
use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
    Object { id: AuraDid, name: Option<String> },
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_test_did() -> AuraDid {
        AuraDid("did:aura:issuer123".to_string())
    }

    fn create_test_subject_did() -> AuraDid {
        AuraDid("did:aura:subject456".to_string())
    }

    fn create_test_claims() -> HashMap<String, Value> {
        let mut claims = HashMap::new();
        claims.insert("name".to_string(), json!("John Doe"));
        claims.insert("age".to_string(), json!(30));
        claims.insert("email".to_string(), json!("john.doe@example.com"));
        claims
    }

    #[test]
    fn test_verifiable_credential_new() {
        let issuer = create_test_did();
        let subject = create_test_subject_did();
        let claims = create_test_claims();
        let credential_type = vec!["UniversityDegreeCredential".to_string()];

        let vc = VerifiableCredential::new(
            issuer.clone(),
            subject.clone(),
            credential_type.clone(),
            claims.clone(),
        );

        // Check context
        assert_eq!(vc.context.len(), 2);
        assert_eq!(vc.context[0], "https://www.w3.org/2018/credentials/v1");
        assert_eq!(vc.context[1], "https://w3id.org/security/suites/ed25519-2020/v1");

        // Check types
        assert_eq!(vc.credential_type.len(), 2);
        assert_eq!(vc.credential_type[0], "VerifiableCredential");
        assert_eq!(vc.credential_type[1], "UniversityDegreeCredential");

        // Check issuer
        match &vc.issuer {
            CredentialIssuer::Did(did) => assert_eq!(did, &issuer),
            _ => panic!("Expected Did issuer"),
        }

        // Check subject
        assert_eq!(vc.credential_subject.id, Some(subject));
        assert_eq!(vc.credential_subject.claims.len(), 3);
        assert_eq!(vc.credential_subject.claims.get("name"), Some(&json!("John Doe")));

        // Check optional fields
        assert!(vc.id.is_none());
        assert!(vc.expiration_date.is_none());
        assert!(vc.credential_status.is_none());
        assert!(vc.proof.is_none());
    }

    #[test]
    fn test_credential_issuer_variants() {
        // Test DID variant
        let did = create_test_did();
        let issuer_did = CredentialIssuer::Did(did.clone());
        let json = serde_json::to_string(&issuer_did).unwrap();
        assert_eq!(json, "\"did:aura:issuer123\"");

        // Test Object variant
        let issuer_object = CredentialIssuer::Object {
            id: did.clone(),
            name: Some("Test University".to_string()),
        };
        let json = serde_json::to_string(&issuer_object).unwrap();
        assert!(json.contains("\"id\":\"did:aura:issuer123\""));
        assert!(json.contains("\"name\":\"Test University\""));

        // Test deserialization
        let deserialized_did: CredentialIssuer = serde_json::from_str("\"did:aura:test\"").unwrap();
        match deserialized_did {
            CredentialIssuer::Did(did) => assert_eq!(did.0, "did:aura:test"),
            _ => panic!("Expected Did variant"),
        }
    }

    #[test]
    fn test_credential_subject() {
        let subject_did = create_test_subject_did();
        let claims = create_test_claims();

        let subject = CredentialSubject {
            id: Some(subject_did.clone()),
            claims: claims.clone(),
        };

        // Test serialization
        let json = serde_json::to_value(&subject).unwrap();
        assert_eq!(json["id"], "did:aura:subject456");
        assert_eq!(json["name"], "John Doe");
        assert_eq!(json["age"], 30);
        assert_eq!(json["email"], "john.doe@example.com");

        // Test with no ID
        let subject_no_id = CredentialSubject {
            id: None,
            claims,
        };
        let json = serde_json::to_value(&subject_no_id).unwrap();
        // serde includes null values for Option fields, so check it's null not missing
        assert_eq!(json.get("id"), Some(&serde_json::Value::Null));
    }

    #[test]
    fn test_credential_status() {
        let status = CredentialStatus {
            id: "https://example.com/credentials/status/3".to_string(),
            status_type: "RevocationList2020Status".to_string(),
            status_list_index: Some(94567),
            status_list_credential: Some("https://example.com/credentials/status/3".to_string()),
        };

        // Test serialization
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["id"], "https://example.com/credentials/status/3");
        assert_eq!(json["type"], "RevocationList2020Status");
        assert_eq!(json["statusListIndex"], 94567);
        assert_eq!(json["statusListCredential"], "https://example.com/credentials/status/3");

        // Test with minimal fields
        let minimal_status = CredentialStatus {
            id: "status-id".to_string(),
            status_type: "StatusType".to_string(),
            status_list_index: None,
            status_list_credential: None,
        };
        let json = serde_json::to_value(&minimal_status).unwrap();
        // serde includes null values for Option fields
        assert_eq!(json.get("statusListIndex"), Some(&serde_json::Value::Null));
        assert_eq!(json.get("statusListCredential"), Some(&serde_json::Value::Null));
    }

    #[test]
    fn test_proof() {
        let proof = Proof {
            proof_type: "Ed25519Signature2020".to_string(),
            created: Timestamp::from_unix(1234567890),
            verification_method: "did:aura:issuer#key-1".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: "z58DAdFfa9SkqZMVPxAQpic7ndSayn1PzZs6ZjWp1CktyGesjuTSwRdoWhAfGFCF5bppETSTojQCrfFPP2oumHKtz".to_string(),
            challenge: Some("1f44d55f-f161-4938-a659-f8026467f126".to_string()),
            domain: Some("https://example.com".to_string()),
        };

        // Test serialization
        let json = serde_json::to_value(&proof).unwrap();
        assert_eq!(json["type"], "Ed25519Signature2020");
        assert_eq!(json["proofPurpose"], "assertionMethod");
        assert_eq!(json["challenge"], "1f44d55f-f161-4938-a659-f8026467f126");
        assert_eq!(json["domain"], "https://example.com");

        // Test without optional fields
        let minimal_proof = Proof {
            proof_type: "Ed25519Signature2020".to_string(),
            created: Timestamp::now(),
            verification_method: "did:aura:issuer#key-1".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: "signature".to_string(),
            challenge: None,
            domain: None,
        };
        let json = serde_json::to_value(&minimal_proof).unwrap();
        // serde includes null values for Option fields
        assert_eq!(json.get("challenge"), Some(&serde_json::Value::Null));
        assert_eq!(json.get("domain"), Some(&serde_json::Value::Null));
    }

    #[test]
    fn test_verifiable_presentation_new() {
        let holder = create_test_did();
        let issuer = AuraDid("did:aura:issuer999".to_string());
        let subject = create_test_subject_did();
        
        let vc1 = VerifiableCredential::new(
            issuer.clone(),
            subject.clone(),
            vec!["TestCredential".to_string()],
            create_test_claims(),
        );
        
        let vc2 = VerifiableCredential::new(
            issuer,
            subject,
            vec!["AnotherCredential".to_string()],
            HashMap::new(),
        );

        let vp = VerifiablePresentation::new(holder.clone(), vec![vc1, vc2]);

        // Check basic properties
        assert_eq!(vp.context.len(), 2);
        assert_eq!(vp.presentation_type, vec!["VerifiablePresentation"]);
        assert_eq!(vp.holder, holder);
        assert_eq!(vp.verifiable_credential.len(), 2);
        assert!(vp.id.is_none());
        assert!(vp.proof.is_none());
    }

    #[test]
    fn test_verifiable_credential_serialization() {
        let issuer = create_test_did();
        let subject = create_test_subject_did();
        let claims = create_test_claims();
        
        let mut vc = VerifiableCredential::new(
            issuer,
            subject,
            vec!["UniversityDegreeCredential".to_string()],
            claims,
        );

        // Add optional fields
        vc.id = Some("http://example.edu/credentials/1234".to_string());
        vc.expiration_date = Some(Timestamp::from_unix(1893456000)); // 2030-01-01
        vc.credential_status = Some(CredentialStatus {
            id: "https://example.edu/status/24".to_string(),
            status_type: "CredentialStatusList2017".to_string(),
            status_list_index: None,
            status_list_credential: None,
        });

        // Test JSON serialization
        let json = serde_json::to_value(&vc).unwrap();
        assert_eq!(json["@context"].as_array().unwrap().len(), 2);
        assert_eq!(json["id"], "http://example.edu/credentials/1234");
        assert_eq!(json["type"].as_array().unwrap().len(), 2);
        assert!(json["expirationDate"].is_string());
        assert!(json["credentialStatus"].is_object());

        // Test round-trip
        let json_str = serde_json::to_string(&vc).unwrap();
        let deserialized: VerifiableCredential = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.id, vc.id);
        assert_eq!(deserialized.credential_type, vc.credential_type);
    }

    #[test]
    fn test_credential_schema() {
        let author = create_test_did();
        let schema_content = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "name": {
                    "type": "string"
                },
                "age": {
                    "type": "integer",
                    "minimum": 0
                }
            },
            "required": ["name"]
        });

        let schema = CredentialSchema {
            id: "https://example.com/schemas/v1".to_string(),
            schema_type: "JsonSchema".to_string(),
            name: "PersonCredential".to_string(),
            version: "1.0.0".to_string(),
            author: author.clone(),
            created: Timestamp::from_unix(1609459200), // 2021-01-01
            schema: schema_content.clone(),
        };

        // Test serialization
        let json = serde_json::to_value(&schema).unwrap();
        assert_eq!(json["id"], "https://example.com/schemas/v1");
        assert_eq!(json["schema_type"], "JsonSchema");
        assert_eq!(json["name"], "PersonCredential");
        assert_eq!(json["version"], "1.0.0");
        assert_eq!(json["author"], "did:aura:issuer123");
        assert_eq!(json["schema"]["properties"]["name"]["type"], "string");
    }

    #[test]
    fn test_schema_record_bincode() {
        let record = SchemaRecord {
            schema_id: "schema123".to_string(),
            schema_content_hash: vec![1, 2, 3, 4, 5],
            issuer_did: create_test_did(),
            registered_at_block: 12345,
        };

        // Test bincode encoding
        let encoded = bincode::encode_to_vec(&record, bincode::config::standard()).unwrap();
        assert!(!encoded.is_empty());

        // Test bincode decoding
        let (decoded, _): (SchemaRecord, _) = 
            bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(decoded.schema_id, record.schema_id);
        assert_eq!(decoded.schema_content_hash, record.schema_content_hash);
        assert_eq!(decoded.issuer_did.0, record.issuer_did.0);
        assert_eq!(decoded.registered_at_block, record.registered_at_block);
    }

    #[test]
    fn test_complex_credential_with_nested_claims() {
        let issuer = CredentialIssuer::Object {
            id: create_test_did(),
            name: Some("Example University".to_string()),
        };

        let mut claims = HashMap::new();
        claims.insert("degree".to_string(), json!({
            "type": "BachelorDegree",
            "name": "Bachelor of Science and Arts",
            "major": "Computer Science",
            "minor": "Philosophy",
            "gpa": 3.8
        }));
        claims.insert("alumniOf".to_string(), json!({
            "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
            "name": [{
                "value": "Example University",
                "lang": "en"
            }]
        }));

        let subject = CredentialSubject {
            id: Some(create_test_subject_did()),
            claims,
        };

        let vc = VerifiableCredential {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://www.w3.org/2018/credentials/examples/v1".to_string(),
            ],
            id: Some("http://example.edu/credentials/3732".to_string()),
            credential_type: vec![
                "VerifiableCredential".to_string(),
                "UniversityDegreeCredential".to_string(),
            ],
            issuer,
            issuance_date: Timestamp::from_unix(1420070400), // 2015-01-01
            expiration_date: None,
            credential_subject: subject,
            credential_status: None,
            proof: Some(Proof {
                proof_type: "Ed25519Signature2020".to_string(),
                created: Timestamp::from_unix(1420070400),
                verification_method: "https://example.edu/issuers/14#key-1".to_string(),
                proof_purpose: "assertionMethod".to_string(),
                proof_value: "z3FXQjecWufY46...".to_string(),
                challenge: None,
                domain: None,
            }),
        };

        // Test serialization of complex credential
        let json = serde_json::to_value(&vc).unwrap();
        assert!(json["issuer"]["name"].is_string());
        assert_eq!(json["credentialSubject"]["degree"]["type"], "BachelorDegree");
        assert_eq!(json["credentialSubject"]["degree"]["gpa"], 3.8);
        assert!(json["proof"]["proofValue"].is_string());

        // Test round-trip
        let json_str = serde_json::to_string_pretty(&vc).unwrap();
        let deserialized: VerifiableCredential = serde_json::from_str(&json_str).unwrap();
        assert_eq!(
            deserialized.credential_subject.claims.get("degree").unwrap()["major"],
            "Computer Science"
        );
    }

    #[test]
    fn test_empty_credential_and_presentation() {
        // Test minimal credential
        let vc = VerifiableCredential::new(
            create_test_did(),
            create_test_subject_did(),
            vec![],
            HashMap::new(),
        );
        assert_eq!(vc.credential_type, vec!["VerifiableCredential"]);
        assert!(vc.credential_subject.claims.is_empty());

        // Test empty presentation
        let vp = VerifiablePresentation::new(create_test_did(), vec![]);
        assert!(vp.verifiable_credential.is_empty());
        
        // Test serialization
        let json = serde_json::to_value(&vp).unwrap();
        assert_eq!(json["verifiableCredential"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_credential_with_multiple_types() {
        let types = vec![
            "AlumniCredential".to_string(),
            "AchievementCredential".to_string(),
            "EmploymentCredential".to_string(),
        ];

        let vc = VerifiableCredential::new(
            create_test_did(),
            create_test_subject_did(),
            types.clone(),
            HashMap::new(),
        );

        assert_eq!(vc.credential_type.len(), 4); // VerifiableCredential + 3 custom types
        assert_eq!(vc.credential_type[0], "VerifiableCredential");
        for (i, t) in types.iter().enumerate() {
            assert_eq!(&vc.credential_type[i + 1], t);
        }
    }

    #[test]
    fn test_timestamp_handling_in_credentials() {
        let now = Timestamp::now();
        let future = Timestamp::from_unix(now.as_unix() + 86400); // +1 day
        let past = Timestamp::from_unix(now.as_unix() - 86400); // -1 day

        let mut vc = VerifiableCredential::new(
            create_test_did(),
            create_test_subject_did(),
            vec!["TimeTestCredential".to_string()],
            HashMap::new(),
        );

        vc.issuance_date = past;
        vc.expiration_date = Some(future);

        // Verify timestamps are preserved
        assert!(vc.issuance_date.as_unix() < now.as_unix());
        assert!(vc.expiration_date.unwrap().as_unix() > now.as_unix());

        // Test serialization preserves timestamps
        let json_str = serde_json::to_string(&vc).unwrap();
        let deserialized: VerifiableCredential = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.issuance_date.as_unix(), past.as_unix());
        assert_eq!(deserialized.expiration_date.unwrap().as_unix(), future.as_unix());
    }
}
