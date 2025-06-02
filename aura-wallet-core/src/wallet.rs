use crate::{DidManager, KeyManager, PresentationGenerator, VcStore};
use aura_common::{
    AuraDid, AuraError, DidDocument, Result, VerifiableCredential, VerifiablePresentation,
};
use aura_crypto::{KeyPair, PublicKey};

pub struct AuraWallet {
    did_manager: DidManager,
    vc_store: VcStore,
}

impl Default for AuraWallet {
    fn default() -> Self {
        let key_manager = KeyManager::new();
        let did_manager = DidManager::new(key_manager);
        Self {
            did_manager,
            vc_store: VcStore::new(),
        }
    }
}

impl AuraWallet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn initialize(&mut self, password: &str) -> Result<()> {
        // Initialize the key manager through did_manager
        self.did_manager.key_manager.initialize(password)?;

        // Derive encryption key for VC store from password (deterministic)
        let mut key_data = [0u8; 32];
        let password_hash = aura_crypto::hashing::sha256(password.as_bytes());
        key_data.copy_from_slice(&password_hash);
        self.vc_store.initialize(key_data);

        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        self.did_manager.key_manager.is_initialized()
    }

    // DID Management
    pub fn create_did(&mut self) -> Result<(AuraDid, DidDocument, KeyPair)> {
        self.did_manager.create_did()
    }

    pub fn list_dids(&self) -> Vec<AuraDid> {
        self.did_manager.list_dids()
    }

    pub fn get_did_public_key(&self, did: &AuraDid) -> Result<PublicKey> {
        self.did_manager.get_public_key(did)
    }

    // Credential Management
    pub fn store_credential(
        &mut self,
        credential: VerifiableCredential,
        tags: Vec<String>,
    ) -> Result<String> {
        self.vc_store.store_credential(credential, tags)
    }

    pub fn get_credential(&self, id: &str) -> Result<Option<&crate::vc_store::StoredCredential>> {
        self.vc_store.get_credential(id)
    }

    pub fn list_credentials(&self) -> Vec<&crate::vc_store::StoredCredential> {
        self.vc_store.list_credentials()
    }

    pub fn find_credentials_by_type(
        &self,
        credential_type: &str,
    ) -> Vec<&crate::vc_store::StoredCredential> {
        self.vc_store.find_credentials_by_type(credential_type)
    }

    pub fn find_credentials_by_issuer(
        &self,
        issuer: &AuraDid,
    ) -> Vec<&crate::vc_store::StoredCredential> {
        self.vc_store.find_credentials_by_issuer(issuer)
    }

    pub fn find_credentials_by_subject(
        &self,
        subject: &AuraDid,
    ) -> Vec<&crate::vc_store::StoredCredential> {
        self.vc_store.find_credentials_by_subject(subject)
    }

    pub fn remove_credential(&mut self, id: &str) -> Result<()> {
        self.vc_store.remove_credential(id)
    }

    pub fn verify_credential(
        &self,
        credential: &VerifiableCredential,
        issuer_public_key: &PublicKey,
    ) -> Result<bool> {
        self.vc_store
            .verify_credential_signature(credential, issuer_public_key)
    }

    // Presentation Management
    pub fn create_presentation(
        &self,
        holder_did: &AuraDid,
        credential_ids: Vec<String>,
        challenge: Option<String>,
        domain: Option<String>,
    ) -> Result<VerifiablePresentation> {
        let presentation_generator =
            PresentationGenerator::new(self.vc_store.clone(), self.did_manager.clone());
        presentation_generator.create_presentation(holder_did, credential_ids, challenge, domain)
    }

    pub fn create_selective_presentation(
        &self,
        holder_did: &AuraDid,
        credential_id: String,
        disclosed_claims: Vec<String>,
        challenge: Option<String>,
        domain: Option<String>,
    ) -> Result<VerifiablePresentation> {
        let presentation_generator =
            PresentationGenerator::new(self.vc_store.clone(), self.did_manager.clone());
        presentation_generator.create_selective_presentation(
            holder_did,
            credential_id,
            disclosed_claims,
            challenge,
            domain,
        )
    }

    pub fn verify_presentation(
        &self,
        presentation: &VerifiablePresentation,
        holder_public_key: &PublicKey,
        expected_challenge: Option<&str>,
        expected_domain: Option<&str>,
    ) -> Result<bool> {
        let presentation_generator =
            PresentationGenerator::new(self.vc_store.clone(), self.did_manager.clone());
        presentation_generator.verify_presentation(
            presentation,
            holder_public_key,
            expected_challenge,
            expected_domain,
        )
    }

    // Export/Import
    pub fn export_wallet(&self) -> Result<WalletBackup> {
        if !self.is_initialized() {
            return Err(AuraError::Internal("Wallet not initialized".to_string()));
        }

        Ok(WalletBackup {
            keys: self.did_manager.key_manager.export_keys()?,
            credentials: self.vc_store.export_credentials()?,
        })
    }

    pub fn import_wallet(&mut self, backup: WalletBackup, password: &str) -> Result<()> {
        // Initialize through the standard method
        self.initialize(password)?;

        // Import keys into the key manager
        self.did_manager.key_manager.import_keys(backup.keys)?;

        // Import credentials
        self.vc_store.import_credentials(&backup.credentials)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBackup {
    pub keys: Vec<crate::key_manager::StoredKey>,
    pub credentials: Vec<u8>,
}

use serde::{Deserialize, Serialize};

// Implement Clone for components to fix the initialization issue
impl Clone for KeyManager {
    fn clone(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            master_key: self.master_key.clone(),
        }
    }
}

impl Clone for DidManager {
    fn clone(&self) -> Self {
        Self {
            key_manager: self.key_manager.clone(),
        }
    }
}

impl Clone for VcStore {
    fn clone(&self) -> Self {
        Self {
            credentials: self.credentials.clone(),
            encryption_key: self.encryption_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_common::{CredentialIssuer, CredentialSubject, Timestamp, VerifiableCredential};
    use aura_crypto::KeyPair;
    use std::collections::HashMap;

    fn create_test_credential(
        id: String,
        issuer: AuraDid,
        subject: AuraDid,
    ) -> VerifiableCredential {
        VerifiableCredential {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            id: Some(id),
            credential_type: vec![
                "VerifiableCredential".to_string(),
                "TestCredential".to_string(),
            ],
            issuer: CredentialIssuer::Did(issuer),
            issuance_date: Timestamp::now(),
            expiration_date: None,
            credential_subject: CredentialSubject {
                id: Some(subject),
                claims: {
                    let mut claims = HashMap::new();
                    claims.insert("name".to_string(), serde_json::json!("John Doe"));
                    claims.insert("age".to_string(), serde_json::json!(30));
                    claims
                },
            },
            credential_status: None,
            proof: None,
        }
    }

    #[test]
    fn test_new_wallet() {
        let wallet = AuraWallet::new();
        assert!(!wallet.is_initialized());
    }

    #[test]
    fn test_initialize_wallet() {
        let mut wallet = AuraWallet::new();
        wallet.initialize("test_password").unwrap();
        assert!(wallet.is_initialized());
    }

    #[test]
    fn test_create_did() {
        let mut wallet = AuraWallet::new();
        wallet.initialize("test_password").unwrap();

        let (did, did_document, key_pair) = wallet.create_did().unwrap();

        assert!(did.0.starts_with("did:aura:"));
        assert_eq!(did_document.id, did);

        // Verify we can retrieve the public key
        let public_key = wallet.get_did_public_key(&did).unwrap();
        assert_eq!(public_key, key_pair.public_key());
    }

    #[test]
    fn test_list_dids() {
        let mut wallet = AuraWallet::new();
        wallet.initialize("test_password").unwrap();

        // Initially empty
        assert_eq!(wallet.list_dids().len(), 0);

        // Create some DIDs
        let mut created_dids = Vec::new();
        for _ in 0..3 {
            let (did, _, _) = wallet.create_did().unwrap();
            created_dids.push(did);
        }

        // List and verify
        let listed = wallet.list_dids();
        assert_eq!(listed.len(), 3);
        for did in &created_dids {
            assert!(listed.contains(did));
        }
    }

    #[test]
    fn test_store_and_get_credential() {
        let mut wallet = AuraWallet::new();
        wallet.initialize("test_password").unwrap();

        let (holder_did, _, _) = wallet.create_did().unwrap();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());

        let credential = create_test_credential("cred123".to_string(), issuer_did, holder_did);
        let tags = vec!["education".to_string(), "diploma".to_string()];

        // Store credential
        let id = wallet.store_credential(credential, tags.clone()).unwrap();
        assert_eq!(id, "cred123");

        // Get credential
        let retrieved = wallet.get_credential(&id).unwrap().unwrap();
        assert_eq!(retrieved.id, id);
        assert_eq!(retrieved.tags, tags);
    }

    #[test]
    fn test_list_credentials() {
        let mut wallet = AuraWallet::new();
        wallet.initialize("test_password").unwrap();

        let (holder_did, _, _) = wallet.create_did().unwrap();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());

        // Store multiple credentials
        for i in 0..3 {
            let credential =
                create_test_credential(format!("cred{i}"), issuer_did.clone(), holder_did.clone());
            wallet.store_credential(credential, vec![]).unwrap();
        }

        let list = wallet.list_credentials();
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_find_credentials_by_type() {
        let mut wallet = AuraWallet::new();
        wallet.initialize("test_password").unwrap();

        let (holder_did, _, _) = wallet.create_did().unwrap();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());

        // Store different types of credentials
        let mut cred1 =
            create_test_credential("1".to_string(), issuer_did.clone(), holder_did.clone());
        cred1.credential_type = vec!["VerifiableCredential".to_string(), "Diploma".to_string()];

        let mut cred2 =
            create_test_credential("2".to_string(), issuer_did.clone(), holder_did.clone());
        cred2.credential_type = vec!["VerifiableCredential".to_string(), "License".to_string()];

        wallet.store_credential(cred1, vec![]).unwrap();
        wallet.store_credential(cred2, vec![]).unwrap();

        let diplomas = wallet.find_credentials_by_type("Diploma");
        assert_eq!(diplomas.len(), 1);

        let licenses = wallet.find_credentials_by_type("License");
        assert_eq!(licenses.len(), 1);
    }

    #[test]
    fn test_find_credentials_by_issuer() {
        let mut wallet = AuraWallet::new();
        wallet.initialize("test_password").unwrap();

        let (holder_did, _, _) = wallet.create_did().unwrap();
        let issuer1 = AuraDid("did:aura:issuer1".to_string());
        let issuer2 = AuraDid("did:aura:issuer2".to_string());

        // Store credentials from different issuers
        wallet
            .store_credential(
                create_test_credential("1".to_string(), issuer1.clone(), holder_did.clone()),
                vec![],
            )
            .unwrap();
        wallet
            .store_credential(
                create_test_credential("2".to_string(), issuer2.clone(), holder_did.clone()),
                vec![],
            )
            .unwrap();

        let from_issuer1 = wallet.find_credentials_by_issuer(&issuer1);
        assert_eq!(from_issuer1.len(), 1);

        let from_issuer2 = wallet.find_credentials_by_issuer(&issuer2);
        assert_eq!(from_issuer2.len(), 1);
    }

    #[test]
    fn test_find_credentials_by_subject() {
        let mut wallet = AuraWallet::new();
        wallet.initialize("test_password").unwrap();

        let (holder_did1, _, _) = wallet.create_did().unwrap();
        let (holder_did2, _, _) = wallet.create_did().unwrap();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());

        // Store credentials for different subjects
        wallet
            .store_credential(
                create_test_credential("1".to_string(), issuer_did.clone(), holder_did1.clone()),
                vec![],
            )
            .unwrap();
        wallet
            .store_credential(
                create_test_credential("2".to_string(), issuer_did.clone(), holder_did2.clone()),
                vec![],
            )
            .unwrap();

        let for_holder1 = wallet.find_credentials_by_subject(&holder_did1);
        assert_eq!(for_holder1.len(), 1);

        let for_holder2 = wallet.find_credentials_by_subject(&holder_did2);
        assert_eq!(for_holder2.len(), 1);
    }

    #[test]
    fn test_remove_credential() {
        let mut wallet = AuraWallet::new();
        wallet.initialize("test_password").unwrap();

        let (holder_did, _, _) = wallet.create_did().unwrap();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());

        let credential = create_test_credential("cred123".to_string(), issuer_did, holder_did);
        wallet.store_credential(credential, vec![]).unwrap();

        assert_eq!(wallet.list_credentials().len(), 1);

        wallet.remove_credential("cred123").unwrap();
        assert_eq!(wallet.list_credentials().len(), 0);

        // Try to remove again
        let result = wallet.remove_credential("cred123");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_credential() {
        let wallet = AuraWallet::new();

        let issuer_keypair = KeyPair::generate().unwrap();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        let subject_did = AuraDid("did:aura:subject123".to_string());

        // Create credential
        let mut credential =
            create_test_credential("cred123".to_string(), issuer_did.clone(), subject_did);

        // Sign the credential
        let signature =
            aura_crypto::signing::sign_json(issuer_keypair.private_key(), &credential).unwrap();

        // Add proof
        credential.proof = Some(aura_common::Proof {
            proof_type: "Ed25519Signature2020".to_string(),
            created: Timestamp::now(),
            verification_method: format!("{issuer_did}#key-1"),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: hex::encode(signature.to_bytes()),
            challenge: None,
            domain: None,
        });

        // Verify
        let valid = wallet
            .verify_credential(&credential, &issuer_keypair.public_key())
            .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_create_presentation() {
        let mut wallet = AuraWallet::new();
        wallet.initialize("test_password").unwrap();

        let (holder_did, _, _) = wallet.create_did().unwrap();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());

        // Store some credentials
        let cred1 =
            create_test_credential("cred1".to_string(), issuer_did.clone(), holder_did.clone());
        let cred2 =
            create_test_credential("cred2".to_string(), issuer_did.clone(), holder_did.clone());

        wallet.store_credential(cred1, vec![]).unwrap();
        wallet.store_credential(cred2, vec![]).unwrap();

        // Create presentation
        let presentation = wallet
            .create_presentation(
                &holder_did,
                vec!["cred1".to_string(), "cred2".to_string()],
                Some("challenge123".to_string()),
                Some("https://example.com".to_string()),
            )
            .unwrap();

        assert_eq!(presentation.holder, holder_did);
        assert_eq!(presentation.verifiable_credential.len(), 2);
        assert!(presentation.proof.is_some());
    }

    #[test]
    fn test_create_selective_presentation() {
        let mut wallet = AuraWallet::new();
        wallet.initialize("test_password").unwrap();

        let (holder_did, _, _) = wallet.create_did().unwrap();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());

        // Store credential
        let credential =
            create_test_credential("cred1".to_string(), issuer_did, holder_did.clone());
        wallet.store_credential(credential, vec![]).unwrap();

        // Create selective presentation
        let presentation = wallet
            .create_selective_presentation(
                &holder_did,
                "cred1".to_string(),
                vec!["name".to_string()],
                None,
                None,
            )
            .unwrap();

        // Verify only selected claims are included
        let claims = &presentation.verifiable_credential[0]
            .credential_subject
            .claims;
        assert_eq!(claims.len(), 1);
        assert!(claims.contains_key("name"));
        assert!(!claims.contains_key("age"));
    }

    #[test]
    fn test_verify_presentation() {
        let mut wallet = AuraWallet::new();
        wallet.initialize("test_password").unwrap();

        let (holder_did, _, holder_keypair) = wallet.create_did().unwrap();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());

        // Store credential
        let credential =
            create_test_credential("cred1".to_string(), issuer_did, holder_did.clone());
        wallet.store_credential(credential, vec![]).unwrap();

        // Create presentation
        let challenge = "challenge123";
        let domain = "https://example.com";
        let presentation = wallet
            .create_presentation(
                &holder_did,
                vec!["cred1".to_string()],
                Some(challenge.to_string()),
                Some(domain.to_string()),
            )
            .unwrap();

        // Verify
        let valid = wallet
            .verify_presentation(
                &presentation,
                &holder_keypair.public_key(),
                Some(challenge),
                Some(domain),
            )
            .unwrap();

        assert!(valid);
    }

    #[test]
    fn test_export_import_wallet() {
        let mut wallet1 = AuraWallet::new();
        wallet1.initialize("test_password").unwrap();

        // Create DIDs and store credentials
        let (did1, _, _) = wallet1.create_did().unwrap();
        let (did2, _, _) = wallet1.create_did().unwrap();

        // Verify DIDs are created in wallet1
        let wallet1_dids = wallet1.list_dids();
        assert_eq!(wallet1_dids.len(), 2);
        let issuer_did = AuraDid("did:aura:issuer123".to_string());

        let cred1 = create_test_credential("cred1".to_string(), issuer_did.clone(), did1.clone());
        let cred2 = create_test_credential("cred2".to_string(), issuer_did.clone(), did2.clone());

        wallet1
            .store_credential(cred1, vec!["tag1".to_string()])
            .unwrap();
        wallet1
            .store_credential(cred2, vec!["tag2".to_string()])
            .unwrap();

        // Export wallet
        let backup = wallet1.export_wallet().unwrap();

        // Verify backup has keys
        assert_eq!(backup.keys.len(), 2);

        // Import into new wallet
        let mut wallet2 = AuraWallet::new();
        wallet2.import_wallet(backup, "test_password").unwrap();

        // Verify DIDs
        let dids = wallet2.list_dids();
        assert_eq!(dids.len(), 2);
        assert!(dids.contains(&did1));
        assert!(dids.contains(&did2));

        // Verify credentials
        let creds = wallet2.list_credentials();
        assert_eq!(creds.len(), 2);

        let cred1_restored = wallet2.get_credential("cred1").unwrap().unwrap();
        assert_eq!(cred1_restored.tags, vec!["tag1"]);

        let cred2_restored = wallet2.get_credential("cred2").unwrap().unwrap();
        assert_eq!(cred2_restored.tags, vec!["tag2"]);
    }

    #[test]
    fn test_export_not_initialized() {
        let wallet = AuraWallet::new();
        let result = wallet.export_wallet();

        assert!(result.is_err());
        match result {
            Err(AuraError::Internal(msg)) => {
                assert!(msg.contains("Wallet not initialized"));
            }
            _ => panic!("Expected Internal error"),
        }
    }

    #[test]
    fn test_multiple_operations() {
        let mut wallet = AuraWallet::new();
        wallet.initialize("test_password").unwrap();

        // Create multiple DIDs
        let mut dids = Vec::new();
        for _ in 0..3 {
            let (did, _, _) = wallet.create_did().unwrap();
            dids.push(did);
        }

        let issuer_did = AuraDid("did:aura:issuer123".to_string());

        // Store credentials for each DID
        for (i, did) in dids.iter().enumerate() {
            let credential =
                create_test_credential(format!("cred{i}"), issuer_did.clone(), did.clone());
            wallet
                .store_credential(credential, vec![format!("tag{}", i)])
                .unwrap();
        }

        // Create presentations for each DID
        for (i, did) in dids.iter().enumerate() {
            let presentation = wallet
                .create_presentation(did, vec![format!("cred{}", i)], None, None)
                .unwrap();

            assert_eq!(presentation.holder, *did);
            assert_eq!(presentation.verifiable_credential.len(), 1);
        }

        // Verify we can find credentials by subject
        for did in &dids {
            let creds = wallet.find_credentials_by_subject(did);
            assert_eq!(creds.len(), 1);
        }
    }
}
