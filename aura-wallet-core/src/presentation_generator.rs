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
                .ok_or_else(|| AuraError::NotFound(format!("Credential {} not found", id)))?;
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
            .ok_or_else(|| {
                AuraError::NotFound(format!("Credential {} not found", credential_id))
            })?;

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
            verification_method: format!("{}#key-1", holder_did),
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
