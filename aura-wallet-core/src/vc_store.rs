use aura_common::{AuraDid, AuraError, Result, Timestamp, VerifiableCredential};
use aura_crypto::{encryption, signing, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub id: String,
    pub credential: VerifiableCredential,
    pub received_at: Timestamp,
    pub tags: Vec<String>,
}

#[derive(Default)]
pub struct VcStore {
    pub(crate) credentials: HashMap<String, StoredCredential>,
    pub(crate) encryption_key: Option<[u8; 32]>,
}

impl VcStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn initialize(&mut self, encryption_key: [u8; 32]) {
        self.encryption_key = Some(encryption_key);
    }

    pub fn store_credential(
        &mut self,
        credential: VerifiableCredential,
        tags: Vec<String>,
    ) -> Result<String> {
        let id = credential
            .id
            .clone()
            .unwrap_or_else(|| format!("urn:uuid:{}", uuid::Uuid::new_v4()));

        let stored_credential = StoredCredential {
            id: id.clone(),
            credential,
            received_at: Timestamp::now(),
            tags,
        };

        self.credentials.insert(id.clone(), stored_credential);

        Ok(id)
    }

    pub fn get_credential(&self, id: &str) -> Result<Option<&StoredCredential>> {
        Ok(self.credentials.get(id))
    }

    pub fn list_credentials(&self) -> Vec<&StoredCredential> {
        self.credentials.values().collect()
    }

    pub fn find_credentials_by_type(&self, credential_type: &str) -> Vec<&StoredCredential> {
        self.credentials
            .values()
            .filter(|sc| {
                sc.credential
                    .credential_type
                    .contains(&credential_type.to_string())
            })
            .collect()
    }

    pub fn find_credentials_by_issuer(&self, issuer: &AuraDid) -> Vec<&StoredCredential> {
        self.credentials
            .values()
            .filter(|sc| match &sc.credential.issuer {
                aura_common::CredentialIssuer::Did(did) => did == issuer,
                aura_common::CredentialIssuer::Object { id, .. } => id == issuer,
            })
            .collect()
    }

    pub fn find_credentials_by_subject(&self, subject: &AuraDid) -> Vec<&StoredCredential> {
        self.credentials
            .values()
            .filter(|sc| sc.credential.credential_subject.id.as_ref() == Some(subject))
            .collect()
    }

    pub fn find_credentials_by_tag(&self, tag: &str) -> Vec<&StoredCredential> {
        self.credentials
            .values()
            .filter(|sc| sc.tags.contains(&tag.to_string()))
            .collect()
    }

    pub fn remove_credential(&mut self, id: &str) -> Result<()> {
        self.credentials
            .remove(id)
            .ok_or_else(|| AuraError::NotFound(format!("Credential {id} not found")))?;
        Ok(())
    }

    pub fn verify_credential_signature(
        &self,
        credential: &VerifiableCredential,
        issuer_public_key: &PublicKey,
    ) -> Result<bool> {
        let proof = credential
            .proof
            .as_ref()
            .ok_or_else(|| AuraError::Validation("Credential has no proof".to_string()))?;

        // Remove proof from credential for verification
        let mut cred_without_proof = credential.clone();
        cred_without_proof.proof = None;

        // Verify signature
        let signature = aura_crypto::Signature::from_bytes(
            hex::decode(&proof.proof_value)
                .map_err(|_| AuraError::Crypto("Invalid proof value format".to_string()))?,
        )
        .map_err(|e| AuraError::Crypto(e.to_string()))?;

        signing::verify_json(issuer_public_key, &cred_without_proof, &signature)
            .map_err(|e| AuraError::Crypto(e.to_string()))
    }

    pub fn export_credentials(&self) -> Result<Vec<u8>> {
        if self.encryption_key.is_none() {
            return Err(AuraError::Internal("VC store not initialized".to_string()));
        }

        let data = serde_json::to_vec(&self.credentials)
            .map_err(|e| AuraError::Serialization(e.to_string()))?;
        let encrypted = encryption::encrypt(self.encryption_key.as_ref().unwrap(), &data)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;

        bincode::encode_to_vec(&encrypted, bincode::config::standard()).map_err(|e| {
            AuraError::Internal(format!("Failed to serialize encrypted credentials: {e}"))
        })
    }

    pub fn import_credentials(&mut self, encrypted_data: &[u8]) -> Result<()> {
        if self.encryption_key.is_none() {
            return Err(AuraError::Internal("VC store not initialized".to_string()));
        }

        let (encrypted, _): (encryption::EncryptedData, _) =
            bincode::decode_from_slice(encrypted_data, bincode::config::standard()).map_err(
                |e| {
                    AuraError::Internal(format!("Failed to deserialize encrypted credentials: {e}"))
                },
            )?;

        let data = encryption::decrypt(self.encryption_key.as_ref().unwrap(), &encrypted)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;

        let credentials: HashMap<String, StoredCredential> =
            serde_json::from_slice(&data).map_err(|e| AuraError::Serialization(e.to_string()))?;

        self.credentials.extend(credentials);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_common::{
        AuraDid, CredentialIssuer, CredentialSubject, Proof, Timestamp, VerifiableCredential,
    };
    use aura_crypto::KeyPair;

    fn create_test_credential(
        id: Option<String>,
        issuer: AuraDid,
        subject: AuraDid,
        cred_type: &str,
    ) -> VerifiableCredential {
        VerifiableCredential {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            id,
            credential_type: vec!["VerifiableCredential".to_string(), cred_type.to_string()],
            issuer: CredentialIssuer::Did(issuer.clone()),
            issuance_date: Timestamp::now(),
            expiration_date: None,
            credential_subject: CredentialSubject {
                id: Some(subject),
                claims: {
                    let mut claims = std::collections::HashMap::new();
                    claims.insert("name".to_string(), serde_json::json!("Test User"));
                    claims.insert("email".to_string(), serde_json::json!("test@example.com"));
                    claims
                },
            },
            credential_status: None,
            proof: None,
        }
    }

    fn setup_vc_store() -> VcStore {
        let mut store = VcStore::new();
        store.initialize([0u8; 32]);
        store
    }

    #[test]
    fn test_new_vc_store() {
        let store = VcStore::new();
        assert!(store.credentials.is_empty());
        assert!(store.encryption_key.is_none());
    }

    #[test]
    fn test_initialize() {
        let mut store = VcStore::new();
        let key = [1u8; 32];
        store.initialize(key);
        assert_eq!(store.encryption_key, Some(key));
    }

    #[test]
    fn test_store_credential_with_id() {
        let mut store = setup_vc_store();
        let issuer = AuraDid("did:aura:issuer123".to_string());
        let subject = AuraDid("did:aura:subject123".to_string());
        let credential = create_test_credential(
            Some("cred123".to_string()),
            issuer,
            subject,
            "TestCredential",
        );

        let id = store
            .store_credential(credential.clone(), vec!["test".to_string()])
            .unwrap();

        assert_eq!(id, "cred123");
        assert_eq!(store.credentials.len(), 1);

        let stored = store.get_credential(&id).unwrap().unwrap();
        assert_eq!(stored.id, id);
        assert_eq!(stored.credential.id, Some("cred123".to_string()));
        assert_eq!(stored.tags, vec!["test"]);
    }

    #[test]
    fn test_store_credential_without_id() {
        let mut store = setup_vc_store();
        let issuer = AuraDid("did:aura:issuer123".to_string());
        let subject = AuraDid("did:aura:subject123".to_string());
        let credential = create_test_credential(None, issuer, subject, "TestCredential");

        let id = store.store_credential(credential, vec![]).unwrap();

        assert!(id.starts_with("urn:uuid:"));
        assert_eq!(store.credentials.len(), 1);
    }

    #[test]
    fn test_get_credential() {
        let mut store = setup_vc_store();
        let issuer = AuraDid("did:aura:issuer123".to_string());
        let subject = AuraDid("did:aura:subject123".to_string());
        let credential = create_test_credential(
            Some("cred123".to_string()),
            issuer,
            subject,
            "TestCredential",
        );

        store.store_credential(credential, vec![]).unwrap();

        let retrieved = store.get_credential("cred123").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, "cred123");

        let not_found = store.get_credential("nonexistent").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_list_credentials() {
        let mut store = setup_vc_store();
        let issuer = AuraDid("did:aura:issuer123".to_string());

        // Store multiple credentials
        for i in 0..3 {
            let subject = AuraDid(format!("did:aura:subject{i}"));
            let credential = create_test_credential(
                Some(format!("cred{i}")),
                issuer.clone(),
                subject,
                "TestCredential",
            );
            store.store_credential(credential, vec![]).unwrap();
        }

        let list = store.list_credentials();
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_find_credentials_by_type() {
        let mut store = setup_vc_store();
        let issuer = AuraDid("did:aura:issuer123".to_string());
        let subject = AuraDid("did:aura:subject123".to_string());

        // Store credentials of different types
        let cred1 = create_test_credential(
            Some("1".to_string()),
            issuer.clone(),
            subject.clone(),
            "Diploma",
        );
        let cred2 = create_test_credential(
            Some("2".to_string()),
            issuer.clone(),
            subject.clone(),
            "License",
        );
        let cred3 = create_test_credential(
            Some("3".to_string()),
            issuer.clone(),
            subject.clone(),
            "Diploma",
        );

        store.store_credential(cred1, vec![]).unwrap();
        store.store_credential(cred2, vec![]).unwrap();
        store.store_credential(cred3, vec![]).unwrap();

        let diplomas = store.find_credentials_by_type("Diploma");
        assert_eq!(diplomas.len(), 2);

        let licenses = store.find_credentials_by_type("License");
        assert_eq!(licenses.len(), 1);
    }

    #[test]
    fn test_find_credentials_by_issuer() {
        let mut store = setup_vc_store();
        let issuer1 = AuraDid("did:aura:issuer1".to_string());
        let issuer2 = AuraDid("did:aura:issuer2".to_string());
        let subject = AuraDid("did:aura:subject123".to_string());

        // Store credentials from different issuers
        store
            .store_credential(
                create_test_credential(
                    Some("1".to_string()),
                    issuer1.clone(),
                    subject.clone(),
                    "Test",
                ),
                vec![],
            )
            .unwrap();
        store
            .store_credential(
                create_test_credential(
                    Some("2".to_string()),
                    issuer2.clone(),
                    subject.clone(),
                    "Test",
                ),
                vec![],
            )
            .unwrap();
        store
            .store_credential(
                create_test_credential(
                    Some("3".to_string()),
                    issuer1.clone(),
                    subject.clone(),
                    "Test",
                ),
                vec![],
            )
            .unwrap();

        let from_issuer1 = store.find_credentials_by_issuer(&issuer1);
        assert_eq!(from_issuer1.len(), 2);

        let from_issuer2 = store.find_credentials_by_issuer(&issuer2);
        assert_eq!(from_issuer2.len(), 1);
    }

    #[test]
    fn test_find_credentials_by_issuer_object() {
        let mut store = setup_vc_store();
        let issuer_did = AuraDid("did:aura:issuer1".to_string());
        let subject = AuraDid("did:aura:subject123".to_string());

        // Create credential with issuer as object
        let mut credential =
            create_test_credential(Some("1".to_string()), issuer_did.clone(), subject, "Test");
        credential.issuer = CredentialIssuer::Object {
            id: issuer_did.clone(),
            name: Some("Test Issuer".to_string()),
        };

        store.store_credential(credential, vec![]).unwrap();

        let found = store.find_credentials_by_issuer(&issuer_did);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_find_credentials_by_subject() {
        let mut store = setup_vc_store();
        let issuer = AuraDid("did:aura:issuer123".to_string());
        let subject1 = AuraDid("did:aura:subject1".to_string());
        let subject2 = AuraDid("did:aura:subject2".to_string());

        // Store credentials for different subjects
        store
            .store_credential(
                create_test_credential(
                    Some("1".to_string()),
                    issuer.clone(),
                    subject1.clone(),
                    "Test",
                ),
                vec![],
            )
            .unwrap();
        store
            .store_credential(
                create_test_credential(
                    Some("2".to_string()),
                    issuer.clone(),
                    subject2.clone(),
                    "Test",
                ),
                vec![],
            )
            .unwrap();
        store
            .store_credential(
                create_test_credential(
                    Some("3".to_string()),
                    issuer.clone(),
                    subject1.clone(),
                    "Test",
                ),
                vec![],
            )
            .unwrap();

        let for_subject1 = store.find_credentials_by_subject(&subject1);
        assert_eq!(for_subject1.len(), 2);

        let for_subject2 = store.find_credentials_by_subject(&subject2);
        assert_eq!(for_subject2.len(), 1);
    }

    #[test]
    fn test_find_credentials_by_tag() {
        let mut store = setup_vc_store();
        let issuer = AuraDid("did:aura:issuer123".to_string());
        let subject = AuraDid("did:aura:subject123".to_string());

        // Store credentials with different tags
        store
            .store_credential(
                create_test_credential(
                    Some("1".to_string()),
                    issuer.clone(),
                    subject.clone(),
                    "Test",
                ),
                vec!["education".to_string(), "verified".to_string()],
            )
            .unwrap();
        store
            .store_credential(
                create_test_credential(
                    Some("2".to_string()),
                    issuer.clone(),
                    subject.clone(),
                    "Test",
                ),
                vec!["work".to_string(), "verified".to_string()],
            )
            .unwrap();
        store
            .store_credential(
                create_test_credential(
                    Some("3".to_string()),
                    issuer.clone(),
                    subject.clone(),
                    "Test",
                ),
                vec!["education".to_string()],
            )
            .unwrap();

        let education = store.find_credentials_by_tag("education");
        assert_eq!(education.len(), 2);

        let verified = store.find_credentials_by_tag("verified");
        assert_eq!(verified.len(), 2);

        let work = store.find_credentials_by_tag("work");
        assert_eq!(work.len(), 1);
    }

    #[test]
    fn test_remove_credential() {
        let mut store = setup_vc_store();
        let issuer = AuraDid("did:aura:issuer123".to_string());
        let subject = AuraDid("did:aura:subject123".to_string());
        let credential = create_test_credential(
            Some("cred123".to_string()),
            issuer,
            subject,
            "TestCredential",
        );

        store.store_credential(credential, vec![]).unwrap();
        assert_eq!(store.credentials.len(), 1);

        store.remove_credential("cred123").unwrap();
        assert_eq!(store.credentials.len(), 0);

        // Try to remove again
        let result = store.remove_credential("cred123");
        assert!(result.is_err());
        match result {
            Err(AuraError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_verify_credential_signature() {
        let store = setup_vc_store();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        let subject = AuraDid("did:aura:subject123".to_string());

        // Create issuer key pair
        let issuer_keypair = KeyPair::generate().unwrap();

        // Create credential
        let mut credential = create_test_credential(
            Some("cred123".to_string()),
            issuer_did.clone(),
            subject,
            "TestCredential",
        );

        // Sign the credential
        let signature = signing::sign_json(issuer_keypair.private_key(), &credential).unwrap();

        // Add proof
        credential.proof = Some(Proof {
            proof_type: "Ed25519Signature2020".to_string(),
            created: Timestamp::now(),
            verification_method: format!("{issuer_did}#key-1"),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: hex::encode(signature.to_bytes()),
            challenge: None,
            domain: None,
        });

        // Verify signature
        let valid = store
            .verify_credential_signature(&credential, &issuer_keypair.public_key())
            .unwrap();
        assert!(valid);

        // Verify with wrong key
        let wrong_keypair = KeyPair::generate().unwrap();
        let invalid = store
            .verify_credential_signature(&credential, &wrong_keypair.public_key())
            .unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_verify_credential_no_proof() {
        let store = setup_vc_store();
        let issuer = AuraDid("did:aura:issuer123".to_string());
        let subject = AuraDid("did:aura:subject123".to_string());
        let credential = create_test_credential(
            Some("cred123".to_string()),
            issuer,
            subject,
            "TestCredential",
        );

        let keypair = KeyPair::generate().unwrap();
        let result = store.verify_credential_signature(&credential, &keypair.public_key());

        assert!(result.is_err());
        match result {
            Err(AuraError::Validation(msg)) => {
                assert!(msg.contains("Credential has no proof"));
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_export_import_credentials() {
        let mut store1 = setup_vc_store();
        let issuer = AuraDid("did:aura:issuer123".to_string());

        // Store multiple credentials
        for i in 0..3 {
            let subject = AuraDid(format!("did:aura:subject{i}"));
            let credential = create_test_credential(
                Some(format!("cred{i}")),
                issuer.clone(),
                subject,
                "TestCredential",
            );
            store1
                .store_credential(credential, vec![format!("tag{}", i)])
                .unwrap();
        }

        // Export
        let exported = store1.export_credentials().unwrap();

        // Import into new store
        let mut store2 = setup_vc_store();
        store2.import_credentials(&exported).unwrap();

        // Verify all credentials are present
        assert_eq!(store2.credentials.len(), 3);
        for i in 0..3 {
            let id = format!("cred{i}");
            let cred = store2.get_credential(&id).unwrap().unwrap();
            assert_eq!(cred.tags, vec![format!("tag{i}")]);
        }
    }

    #[test]
    fn test_export_not_initialized() {
        let store = VcStore::new();
        let result = store.export_credentials();

        assert!(result.is_err());
        match result {
            Err(AuraError::Internal(msg)) => {
                assert!(msg.contains("VC store not initialized"));
            }
            _ => panic!("Expected Internal error"),
        }
    }

    #[test]
    fn test_import_not_initialized() {
        let store1 = setup_vc_store();
        let exported = store1.export_credentials().unwrap();

        let mut store2 = VcStore::new();
        let result = store2.import_credentials(&exported);

        assert!(result.is_err());
        match result {
            Err(AuraError::Internal(msg)) => {
                assert!(msg.contains("VC store not initialized"));
            }
            _ => panic!("Expected Internal error"),
        }
    }

    #[test]
    fn test_multiple_tags() {
        let mut store = setup_vc_store();
        let issuer = AuraDid("did:aura:issuer123".to_string());
        let subject = AuraDid("did:aura:subject123".to_string());
        let credential = create_test_credential(
            Some("cred123".to_string()),
            issuer,
            subject,
            "TestCredential",
        );

        let tags = vec![
            "education".to_string(),
            "verified".to_string(),
            "2024".to_string(),
            "diploma".to_string(),
        ];

        store.store_credential(credential, tags.clone()).unwrap();

        let stored = store.get_credential("cred123").unwrap().unwrap();
        assert_eq!(stored.tags, tags);

        // Find by each tag
        for tag in &tags {
            let found = store.find_credentials_by_tag(tag);
            assert_eq!(found.len(), 1);
        }
    }
}
