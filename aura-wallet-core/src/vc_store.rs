use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use aura_common::{
    AuraError, Result, AuraDid, VerifiableCredential, Proof, Timestamp,
};
use aura_crypto::{encryption, PublicKey, signing};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub id: String,
    pub credential: VerifiableCredential,
    pub received_at: Timestamp,
    pub tags: Vec<String>,
}

pub struct VcStore {
    credentials: HashMap<String, StoredCredential>,
    encryption_key: Option<[u8; 32]>,
}

impl VcStore {
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
            encryption_key: None,
        }
    }
    
    pub fn initialize(&mut self, encryption_key: [u8; 32]) {
        self.encryption_key = Some(encryption_key);
    }
    
    pub fn store_credential(
        &mut self,
        credential: VerifiableCredential,
        tags: Vec<String>,
    ) -> Result<String> {
        let id = credential.id.clone().unwrap_or_else(|| {
            format!("urn:uuid:{}", uuid::Uuid::new_v4())
        });
        
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
            .filter(|sc| sc.credential.credential_type.contains(&credential_type.to_string()))
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
            .filter(|sc| {
                sc.credential.credential_subject.id.as_ref() == Some(subject)
            })
            .collect()
    }
    
    pub fn find_credentials_by_tag(&self, tag: &str) -> Vec<&StoredCredential> {
        self.credentials
            .values()
            .filter(|sc| sc.tags.contains(&tag.to_string()))
            .collect()
    }
    
    pub fn remove_credential(&mut self, id: &str) -> Result<()> {
        self.credentials.remove(id)
            .ok_or_else(|| AuraError::NotFound(format!("Credential {} not found", id)))?;
        Ok(())
    }
    
    pub fn verify_credential_signature(
        &self,
        credential: &VerifiableCredential,
        issuer_public_key: &PublicKey,
    ) -> Result<bool> {
        let proof = credential.proof.as_ref()
            .ok_or_else(|| AuraError::Validation("Credential has no proof".to_string()))?;
        
        // Remove proof from credential for verification
        let mut cred_without_proof = credential.clone();
        cred_without_proof.proof = None;
        
        // Verify signature
        let signature = aura_crypto::Signature::from_bytes(
            hex::decode(&proof.proof_value)
                .map_err(|_| AuraError::Crypto("Invalid proof value format".to_string()))?
        )
        .map_err(|e| AuraError::Crypto(e.to_string()))?;
        
        signing::verify_json(issuer_public_key, &cred_without_proof, &signature)
            .map_err(|e| AuraError::Crypto(e.to_string()))
    }
    
    pub fn export_credentials(&self) -> Result<Vec<u8>> {
        if self.encryption_key.is_none() {
            return Err(AuraError::Internal("VC store not initialized".to_string()));
        }
        
        let data = serde_json::to_vec(&self.credentials)?;
        let encrypted = encryption::encrypt(self.encryption_key.as_ref().unwrap(), &data)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;
        
        Ok(bincode::serialize(&encrypted)
            .map_err(|e| AuraError::Serialization(serde_json::Error::custom(e)))?)
    }
    
    pub fn import_credentials(&mut self, encrypted_data: &[u8]) -> Result<()> {
        if self.encryption_key.is_none() {
            return Err(AuraError::Internal("VC store not initialized".to_string()));
        }
        
        let encrypted: encryption::EncryptedData = bincode::deserialize(encrypted_data)
            .map_err(|e| AuraError::Serialization(serde_json::Error::custom(e)))?;
        
        let data = encryption::decrypt(self.encryption_key.as_ref().unwrap(), &encrypted)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;
        
        let credentials: HashMap<String, StoredCredential> = serde_json::from_slice(&data)?;
        
        self.credentials.extend(credentials);
        
        Ok(())
    }
}