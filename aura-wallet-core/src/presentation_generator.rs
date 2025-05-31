use crate::{DidManager, VcStore};
use aura_common::{AuraDid, AuraError, Proof, Result, Timestamp, VerifiablePresentation};
use aura_crypto::{signing, PublicKey};
use std::collections::HashMap;

pub struct PresentationGenerator {
    vc_store: VcStore,
    did_manager: DidManager,
}

impl PresentationGenerator {
    pub fn new(vc_store: VcStore, did_manager: DidManager) -> Self {
        Self {
            vc_store,
            did_manager,
        }
    }

    pub fn create_presentation(
        &self,
        holder_did: &AuraDid,
        credential_ids: Vec<String>,
        challenge: Option<String>,
        domain: Option<String>,
    ) -> Result<VerifiablePresentation> {
        // Verify holder DID exists
        let _ = self.did_manager.get_public_key(holder_did)?;

        // Collect credentials
        let mut credentials = Vec::new();
        for id in credential_ids {
            let stored_cred = self
                .vc_store
                .get_credential(&id)?
                .ok_or_else(|| AuraError::NotFound(format!("Credential {id} not found")))?;
            credentials.push(stored_cred.credential.clone());
        }

        // Create presentation
        let mut presentation = VerifiablePresentation::new(holder_did.clone(), credentials);

        // Add proof
        let proof = self.create_presentation_proof(holder_did, &presentation, challenge, domain)?;
        presentation.proof = Some(proof);

        Ok(presentation)
    }

    pub fn create_selective_presentation(
        &self,
        holder_did: &AuraDid,
        credential_id: String,
        disclosed_claims: Vec<String>,
        challenge: Option<String>,
        domain: Option<String>,
    ) -> Result<VerifiablePresentation> {
        // Get the credential
        let stored_cred = self
            .vc_store
            .get_credential(&credential_id)?
            .ok_or_else(|| AuraError::NotFound(format!("Credential {credential_id} not found")))?;

        // Create a copy with only disclosed claims
        let mut selective_credential = stored_cred.credential.clone();
        let all_claims = selective_credential.credential_subject.claims.clone();
        let mut disclosed_claims_map = HashMap::new();

        for claim_key in disclosed_claims {
            if let Some(value) = all_claims.get(&claim_key) {
                disclosed_claims_map.insert(claim_key, value.clone());
            }
        }

        selective_credential.credential_subject.claims = disclosed_claims_map;

        // Create presentation with selective credential
        let mut presentation =
            VerifiablePresentation::new(holder_did.clone(), vec![selective_credential]);

        // Add proof
        let proof = self.create_presentation_proof(holder_did, &presentation, challenge, domain)?;
        presentation.proof = Some(proof);

        Ok(presentation)
    }

    fn create_presentation_proof(
        &self,
        holder_did: &AuraDid,
        presentation: &VerifiablePresentation,
        challenge: Option<String>,
        domain: Option<String>,
    ) -> Result<Proof> {
        // Get holder's key
        let key_pair = self.did_manager.key_manager.get_key_pair(holder_did)?;

        // Create proof without the proof field
        let mut pres_for_signing = presentation.clone();
        pres_for_signing.proof = None;

        // Sign the presentation
        let signature = signing::sign_json(key_pair.private_key(), &pres_for_signing)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;

        Ok(Proof {
            proof_type: "Ed25519Signature2020".to_string(),
            created: Timestamp::now(),
            verification_method: format!("{holder_did}#key-1"),
            proof_purpose: "authentication".to_string(),
            proof_value: hex::encode(signature.to_bytes()),
            challenge,
            domain,
        })
    }

    pub fn verify_presentation(
        &self,
        presentation: &VerifiablePresentation,
        holder_public_key: &PublicKey,
        expected_challenge: Option<&str>,
        expected_domain: Option<&str>,
    ) -> Result<bool> {
        // Verify presentation proof
        let proof = presentation
            .proof
            .as_ref()
            .ok_or_else(|| AuraError::Validation("Presentation has no proof".to_string()))?;

        // Check challenge if expected
        if let Some(challenge) = expected_challenge {
            if proof.challenge.as_deref() != Some(challenge) {
                return Ok(false);
            }
        }

        // Check domain if expected
        if let Some(domain) = expected_domain {
            if proof.domain.as_deref() != Some(domain) {
                return Ok(false);
            }
        }

        // Verify signature
        let mut pres_without_proof = presentation.clone();
        pres_without_proof.proof = None;

        let signature = aura_crypto::Signature::from_bytes(
            hex::decode(&proof.proof_value)
                .map_err(|_| AuraError::Crypto("Invalid proof value format".to_string()))?,
        )
        .map_err(|e| AuraError::Crypto(e.to_string()))?;

        signing::verify_json(holder_public_key, &pres_without_proof, &signature)
            .map_err(|e| AuraError::Crypto(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyManager, VcStore};
    use aura_common::{AuraDid, CredentialIssuer, CredentialSubject, VerifiableCredential};
    use aura_crypto::KeyPair;
    
    fn create_test_credential(id: String, issuer: AuraDid, subject: AuraDid) -> VerifiableCredential {
        VerifiableCredential {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            id: Some(id),
            credential_type: vec!["VerifiableCredential".to_string(), "TestCredential".to_string()],
            issuer: CredentialIssuer::Did(issuer),
            issuance_date: Timestamp::now(),
            expiration_date: None,
            credential_subject: CredentialSubject {
                id: Some(subject),
                claims: {
                    let mut claims = HashMap::new();
                    claims.insert("name".to_string(), serde_json::json!("John Doe"));
                    claims.insert("age".to_string(), serde_json::json!(30));
                    claims.insert("email".to_string(), serde_json::json!("john@example.com"));
                    claims.insert("city".to_string(), serde_json::json!("New York"));
                    claims
                },
            },
            credential_status: None,
            proof: None,
        }
    }
    
    fn setup_presentation_generator() -> (PresentationGenerator, AuraDid, KeyPair) {
        // Setup key manager
        let mut key_manager = KeyManager::new();
        key_manager.initialize("test_password").unwrap();
        
        // Setup DID manager
        let mut did_manager = DidManager::new(key_manager);
        let (holder_did, _, holder_keypair) = did_manager.create_did().unwrap();
        
        // Setup VC store
        let mut vc_store = VcStore::new();
        vc_store.initialize([0u8; 32]);
        
        // Create presentation generator
        let generator = PresentationGenerator::new(vc_store, did_manager);
        
        (generator, holder_did, holder_keypair)
    }
    
    #[test]
    fn test_create_presentation() {
        let (mut generator, holder_did, _) = setup_presentation_generator();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        // Store some credentials
        let cred1 = create_test_credential("cred1".to_string(), issuer_did.clone(), holder_did.clone());
        let cred2 = create_test_credential("cred2".to_string(), issuer_did.clone(), holder_did.clone());
        
        generator.vc_store.store_credential(cred1, vec![]).unwrap();
        generator.vc_store.store_credential(cred2, vec![]).unwrap();
        
        // Create presentation
        let presentation = generator.create_presentation(
            &holder_did,
            vec!["cred1".to_string(), "cred2".to_string()],
            Some("challenge123".to_string()),
            Some("https://example.com".to_string()),
        ).unwrap();
        
        // Verify presentation structure
        assert_eq!(presentation.holder, holder_did);
        assert_eq!(presentation.verifiable_credential.len(), 2);
        assert!(presentation.proof.is_some());
        
        let proof = presentation.proof.as_ref().unwrap();
        assert_eq!(proof.proof_type, "Ed25519Signature2020");
        assert_eq!(proof.proof_purpose, "authentication");
        assert_eq!(proof.challenge, Some("challenge123".to_string()));
        assert_eq!(proof.domain, Some("https://example.com".to_string()));
    }
    
    #[test]
    fn test_create_presentation_credential_not_found() {
        let (generator, holder_did, _) = setup_presentation_generator();
        
        let result = generator.create_presentation(
            &holder_did,
            vec!["nonexistent".to_string()],
            None,
            None,
        );
        
        assert!(result.is_err());
        match result {
            Err(AuraError::NotFound(msg)) => {
                assert!(msg.contains("Credential nonexistent not found"));
            },
            _ => panic!("Expected NotFound error"),
        }
    }
    
    #[test]
    fn test_create_presentation_invalid_holder() {
        let (generator, _, _) = setup_presentation_generator();
        let invalid_did = AuraDid("did:aura:invalid".to_string());
        
        let result = generator.create_presentation(
            &invalid_did,
            vec![],
            None,
            None,
        );
        
        assert!(result.is_err());
        match result {
            Err(AuraError::NotFound(_)) => {},
            _ => panic!("Expected NotFound error"),
        }
    }
    
    #[test]
    fn test_create_selective_presentation() {
        let (mut generator, holder_did, _) = setup_presentation_generator();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        // Store credential with multiple claims
        let credential = create_test_credential("cred1".to_string(), issuer_did, holder_did.clone());
        generator.vc_store.store_credential(credential, vec![]).unwrap();
        
        // Create selective presentation with only some claims
        let presentation = generator.create_selective_presentation(
            &holder_did,
            "cred1".to_string(),
            vec!["name".to_string(), "email".to_string()],
            None,
            None,
        ).unwrap();
        
        // Verify only selected claims are included
        assert_eq!(presentation.verifiable_credential.len(), 1);
        let presented_cred = &presentation.verifiable_credential[0];
        let claims = &presented_cred.credential_subject.claims;
        
        assert_eq!(claims.len(), 2);
        assert!(claims.contains_key("name"));
        assert!(claims.contains_key("email"));
        assert!(!claims.contains_key("age"));
        assert!(!claims.contains_key("city"));
    }
    
    #[test]
    fn test_create_selective_presentation_nonexistent_claims() {
        let (mut generator, holder_did, _) = setup_presentation_generator();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        // Store credential
        let credential = create_test_credential("cred1".to_string(), issuer_did, holder_did.clone());
        generator.vc_store.store_credential(credential, vec![]).unwrap();
        
        // Request non-existent claims
        let presentation = generator.create_selective_presentation(
            &holder_did,
            "cred1".to_string(),
            vec!["nonexistent".to_string(), "name".to_string()],
            None,
            None,
        ).unwrap();
        
        // Verify only existing claims are included
        let claims = &presentation.verifiable_credential[0].credential_subject.claims;
        assert_eq!(claims.len(), 1);
        assert!(claims.contains_key("name"));
        assert!(!claims.contains_key("nonexistent"));
    }
    
    #[test]
    fn test_verify_presentation() {
        let (mut generator, holder_did, holder_keypair) = setup_presentation_generator();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        // Store credential
        let credential = create_test_credential("cred1".to_string(), issuer_did, holder_did.clone());
        generator.vc_store.store_credential(credential, vec![]).unwrap();
        
        // Create presentation with challenge and domain
        let challenge = "challenge123";
        let domain = "https://example.com";
        let presentation = generator.create_presentation(
            &holder_did,
            vec!["cred1".to_string()],
            Some(challenge.to_string()),
            Some(domain.to_string()),
        ).unwrap();
        
        // Verify presentation
        let valid = generator.verify_presentation(
            &presentation,
            holder_keypair.public_key(),
            Some(challenge),
            Some(domain),
        ).unwrap();
        
        assert!(valid);
    }
    
    #[test]
    fn test_verify_presentation_wrong_challenge() {
        let (mut generator, holder_did, holder_keypair) = setup_presentation_generator();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        // Store credential
        let credential = create_test_credential("cred1".to_string(), issuer_did, holder_did.clone());
        generator.vc_store.store_credential(credential, vec![]).unwrap();
        
        // Create presentation with challenge
        let presentation = generator.create_presentation(
            &holder_did,
            vec!["cred1".to_string()],
            Some("challenge123".to_string()),
            None,
        ).unwrap();
        
        // Verify with wrong challenge
        let valid = generator.verify_presentation(
            &presentation,
            holder_keypair.public_key(),
            Some("wrong_challenge"),
            None,
        ).unwrap();
        
        assert!(!valid);
    }
    
    #[test]
    fn test_verify_presentation_wrong_domain() {
        let (mut generator, holder_did, holder_keypair) = setup_presentation_generator();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        // Store credential
        let credential = create_test_credential("cred1".to_string(), issuer_did, holder_did.clone());
        generator.vc_store.store_credential(credential, vec![]).unwrap();
        
        // Create presentation with domain
        let presentation = generator.create_presentation(
            &holder_did,
            vec!["cred1".to_string()],
            None,
            Some("https://example.com".to_string()),
        ).unwrap();
        
        // Verify with wrong domain
        let valid = generator.verify_presentation(
            &presentation,
            holder_keypair.public_key(),
            None,
            Some("https://wrong.com"),
        ).unwrap();
        
        assert!(!valid);
    }
    
    #[test]
    fn test_verify_presentation_wrong_key() {
        let (mut generator, holder_did, _) = setup_presentation_generator();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        // Store credential
        let credential = create_test_credential("cred1".to_string(), issuer_did, holder_did.clone());
        generator.vc_store.store_credential(credential, vec![]).unwrap();
        
        // Create presentation
        let presentation = generator.create_presentation(
            &holder_did,
            vec!["cred1".to_string()],
            None,
            None,
        ).unwrap();
        
        // Verify with wrong key
        let wrong_keypair = KeyPair::generate().unwrap();
        let valid = generator.verify_presentation(
            &presentation,
            wrong_keypair.public_key(),
            None,
            None,
        ).unwrap();
        
        assert!(!valid);
    }
    
    #[test]
    fn test_verify_presentation_no_proof() {
        let (generator, holder_did, holder_keypair) = setup_presentation_generator();
        
        // Create presentation without proof
        let presentation = VerifiablePresentation::new(holder_did, vec![]);
        
        let result = generator.verify_presentation(
            &presentation,
            holder_keypair.public_key(),
            None,
            None,
        );
        
        assert!(result.is_err());
        match result {
            Err(AuraError::Validation(msg)) => {
                assert!(msg.contains("Presentation has no proof"));
            },
            _ => panic!("Expected Validation error"),
        }
    }
    
    #[test]
    fn test_create_empty_presentation() {
        let (generator, holder_did, _) = setup_presentation_generator();
        
        // Create presentation with no credentials
        let presentation = generator.create_presentation(
            &holder_did,
            vec![],
            None,
            None,
        ).unwrap();
        
        assert_eq!(presentation.holder, holder_did);
        assert_eq!(presentation.verifiable_credential.len(), 0);
        assert!(presentation.proof.is_some());
    }
    
    #[test]
    fn test_presentation_proof_fields() {
        let (mut generator, holder_did, _) = setup_presentation_generator();
        let issuer_did = AuraDid("did:aura:issuer123".to_string());
        
        // Store credential
        let credential = create_test_credential("cred1".to_string(), issuer_did, holder_did.clone());
        generator.vc_store.store_credential(credential, vec![]).unwrap();
        
        // Create presentation without challenge/domain
        let presentation1 = generator.create_presentation(
            &holder_did,
            vec!["cred1".to_string()],
            None,
            None,
        ).unwrap();
        
        let proof1 = presentation1.proof.as_ref().unwrap();
        assert!(proof1.challenge.is_none());
        assert!(proof1.domain.is_none());
        
        // Create presentation with challenge/domain
        let presentation2 = generator.create_presentation(
            &holder_did,
            vec!["cred1".to_string()],
            Some("test-challenge".to_string()),
            Some("https://test.com".to_string()),
        ).unwrap();
        
        let proof2 = presentation2.proof.as_ref().unwrap();
        assert_eq!(proof2.challenge, Some("test-challenge".to_string()));
        assert_eq!(proof2.domain, Some("https://test.com".to_string()));
        assert_eq!(proof2.verification_method, format!("{holder_did}#key-1"));
    }
}
