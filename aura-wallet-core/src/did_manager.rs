use aura_common::{
    AuraError, Result, AuraDid, DidDocument, VerificationMethod, VerificationRelationship,
    ServiceEndpoint,
};
use aura_crypto::{KeyPair, PublicKey};
use crate::key_manager::KeyManager;

pub struct DidManager {
    pub(crate) key_manager: KeyManager,
}

impl DidManager {
    pub fn new(key_manager: KeyManager) -> Self {
        Self { key_manager }
    }
    
    pub fn create_did(&mut self) -> Result<(AuraDid, DidDocument, KeyPair)> {
        // Generate a unique identifier (in production, use a more sophisticated method)
        let identifier = uuid::Uuid::new_v4().to_string();
        let did = AuraDid::new(&identifier);
        
        // Generate key pair for this DID
        let key_pair = self.key_manager.generate_key_pair(&did)?;
        
        // Create DID document
        let mut did_document = DidDocument::new(did.clone());
        
        // Add verification method
        let verification_method = VerificationMethod {
            id: format!("{}#key-1", did),
            controller: did.clone(),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            public_key_multibase: self.encode_public_key(&key_pair.public_key()),
        };
        
        did_document.add_verification_method(verification_method.clone());
        
        // Add verification relationships
        did_document.authentication.push(VerificationRelationship::Reference(
            format!("{}#key-1", did)
        ));
        did_document.assertion_method.push(VerificationRelationship::Reference(
            format!("{}#key-1", did)
        ));
        did_document.key_agreement.push(VerificationRelationship::Reference(
            format!("{}#key-1", did)
        ));
        
        Ok((did, did_document, key_pair))
    }
    
    pub fn update_did_document(
        &self,
        did: &AuraDid,
        mut did_document: DidDocument,
    ) -> Result<DidDocument> {
        // Verify ownership
        let _ = self.key_manager.get_public_key(did)?;
        
        // Update timestamp
        did_document.updated = aura_common::Timestamp::now();
        
        Ok(did_document)
    }
    
    pub fn add_service_endpoint(
        &self,
        did: &AuraDid,
        mut did_document: DidDocument,
        service_type: String,
        service_endpoint: String,
    ) -> Result<DidDocument> {
        // Verify ownership
        let _ = self.key_manager.get_public_key(did)?;
        
        let service = ServiceEndpoint {
            id: format!("{}#service-{}", did, uuid::Uuid::new_v4()),
            service_type,
            service_endpoint,
        };
        
        did_document.add_service(service);
        
        Ok(did_document)
    }
    
    pub fn sign_did_operation(&self, did: &AuraDid, data: &[u8]) -> Result<Vec<u8>> {
        let key_pair = self.key_manager.get_key_pair(did)?;
        let signature = aura_crypto::sign(key_pair.private_key(), data)
            .map_err(|e| AuraError::Crypto(e.to_string()))?;
        Ok(signature.to_bytes().to_vec())
    }
    
    pub fn get_public_key(&self, did: &AuraDid) -> Result<PublicKey> {
        self.key_manager.get_public_key(did)
    }
    
    pub fn list_dids(&self) -> Vec<AuraDid> {
        self.key_manager.list_dids()
    }
    
    fn encode_public_key(&self, public_key: &PublicKey) -> String {
        // Encode as multibase (base58btc)
        let mut data = vec![0xed, 0x01]; // multicodec prefix for Ed25519
        data.extend_from_slice(&public_key.to_bytes());
        
        multibase::encode(multibase::Base::Base58Btc, &data)
    }
    
    pub fn decode_public_key(&self, multibase_key: &str) -> Result<PublicKey> {
        let (_, data) = multibase::decode(multibase_key)
            .map_err(|e| AuraError::Crypto(format!("Invalid multibase key: {}", e)))?;
        
        // Skip multicodec prefix (2 bytes)
        if data.len() < 34 || data[0] != 0xed || data[1] != 0x01 {
            return Err(AuraError::Crypto("Invalid Ed25519 public key format".to_string()));
        }
        
        PublicKey::from_bytes(&data[2..])
            .map_err(|e| AuraError::Crypto(e.to_string()))
    }
}