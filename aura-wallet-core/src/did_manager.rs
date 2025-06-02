use crate::key_manager::KeyManager;
use aura_common::{
    AuraDid, AuraError, DidDocument, Result, ServiceEndpoint, VerificationMethod,
    VerificationRelationship,
};
use aura_crypto::{KeyPair, PublicKey};

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
            id: format!("{did}#key-1"),
            controller: did.clone(),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            public_key_multibase: Some(self.encode_public_key(&key_pair.public_key())),
            public_key_jwk: None,
            public_key_base58: None,
        };

        did_document.add_verification_method(verification_method.clone());

        // Add verification relationships
        did_document
            .authentication
            .push(VerificationRelationship::Reference(format!("{did}#key-1")));
        did_document
            .assertion_method
            .push(VerificationRelationship::Reference(format!("{did}#key-1")));
        did_document
            .key_agreement
            .push(VerificationRelationship::Reference(format!("{did}#key-1")));

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
            id: format!("{did}#service-{}", uuid::Uuid::new_v4()),
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
            .map_err(|e| AuraError::Crypto(format!("Invalid multibase key: {e}")))?;

        // Skip multicodec prefix (2 bytes)
        if data.len() < 34 || data[0] != 0xed || data[1] != 0x01 {
            return Err(AuraError::Crypto(
                "Invalid Ed25519 public key format".to_string(),
            ));
        }

        PublicKey::from_bytes(&data[2..]).map_err(|e| AuraError::Crypto(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_common::AuraDid;

    fn setup_did_manager() -> DidManager {
        let mut key_manager = KeyManager::new();
        key_manager.initialize("test_password").unwrap();
        DidManager::new(key_manager)
    }

    #[test]
    fn test_create_did() {
        let mut dm = setup_did_manager();

        let (did, did_document, key_pair) = dm.create_did().unwrap();

        // Verify DID format
        assert!(did.0.starts_with("did:aura:"));

        // Verify DID document
        assert_eq!(did_document.id, did);
        assert_eq!(did_document.verification_method.len(), 1);
        assert_eq!(did_document.authentication.len(), 1);
        assert_eq!(did_document.assertion_method.len(), 1);
        assert_eq!(did_document.key_agreement.len(), 1);

        // Verify verification method
        let vm = &did_document.verification_method[0];
        assert_eq!(vm.id, format!("{did}#key-1"));
        assert_eq!(vm.controller, did);
        assert_eq!(vm.verification_type, "Ed25519VerificationKey2020");

        // Verify key pair is stored
        let stored_key = dm.key_manager.get_key_pair(&did).unwrap();
        assert_eq!(stored_key.public_key(), key_pair.public_key());
    }

    #[test]
    fn test_create_multiple_dids() {
        let mut dm = setup_did_manager();

        let (did1, _, _) = dm.create_did().unwrap();
        let (did2, _, _) = dm.create_did().unwrap();
        let (did3, _, _) = dm.create_did().unwrap();

        // Verify all DIDs are unique
        assert_ne!(did1, did2);
        assert_ne!(did2, did3);
        assert_ne!(did1, did3);

        // Verify all are stored
        let dids = dm.list_dids();
        assert_eq!(dids.len(), 3);
        assert!(dids.contains(&did1));
        assert!(dids.contains(&did2));
        assert!(dids.contains(&did3));
    }

    #[test]
    fn test_update_did_document() {
        let mut dm = setup_did_manager();

        let (did, did_document, _) = dm.create_did().unwrap();
        let original_updated = did_document.updated;

        // Wait a bit to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Update document
        let updated_document = dm.update_did_document(&did, did_document.clone()).unwrap();

        // Verify timestamp was updated
        assert!(updated_document.updated.as_unix() > original_updated.as_unix());
        assert_eq!(updated_document.id, did);
    }

    #[test]
    fn test_update_did_document_not_owned() {
        let dm = setup_did_manager();
        let did = AuraDid("did:aura:notowned".to_string());
        let did_document = DidDocument::new(did.clone());

        let result = dm.update_did_document(&did, did_document);
        assert!(result.is_err());
        match result {
            Err(AuraError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_add_service_endpoint() {
        let mut dm = setup_did_manager();

        let (did, did_document, _) = dm.create_did().unwrap();

        let updated_doc = dm
            .add_service_endpoint(
                &did,
                did_document,
                "LinkedDomains".to_string(),
                "https://example.com".to_string(),
            )
            .unwrap();

        // Verify service was added
        assert_eq!(updated_doc.service.len(), 1);

        let service = &updated_doc.service[0];
        assert!(service.id.starts_with(&format!("{did}#service-")));
        assert_eq!(service.service_type, "LinkedDomains");
        assert_eq!(service.service_endpoint, "https://example.com");
    }

    #[test]
    fn test_add_multiple_service_endpoints() {
        let mut dm = setup_did_manager();

        let (did, did_document, _) = dm.create_did().unwrap();

        // Add first service
        let doc1 = dm
            .add_service_endpoint(
                &did,
                did_document,
                "LinkedDomains".to_string(),
                "https://example.com".to_string(),
            )
            .unwrap();

        // Add second service
        let doc2 = dm
            .add_service_endpoint(
                &did,
                doc1,
                "CredentialRegistry".to_string(),
                "https://registry.example.com".to_string(),
            )
            .unwrap();

        assert_eq!(doc2.service.len(), 2);
    }

    #[test]
    fn test_add_service_endpoint_not_owned() {
        let dm = setup_did_manager();
        let did = AuraDid("did:aura:notowned".to_string());
        let did_document = DidDocument::new(did.clone());

        let result = dm.add_service_endpoint(
            &did,
            did_document,
            "Test".to_string(),
            "https://test.com".to_string(),
        );

        assert!(result.is_err());
        match result {
            Err(AuraError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_sign_did_operation() {
        let mut dm = setup_did_manager();

        let (did, _, _) = dm.create_did().unwrap();
        let data = b"test data to sign";

        let signature = dm.sign_did_operation(&did, data).unwrap();

        // Verify signature length (Ed25519 signatures are 64 bytes)
        assert_eq!(signature.len(), 64);

        // Verify signature is valid
        let public_key = dm.get_public_key(&did).unwrap();
        let sig = aura_crypto::Signature::from_bytes(signature.clone()).unwrap();
        let valid = aura_crypto::verify(&public_key, data, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sign_did_operation_not_owned() {
        let dm = setup_did_manager();
        let did = AuraDid("did:aura:notowned".to_string());
        let data = b"test data";

        let result = dm.sign_did_operation(&did, data);
        assert!(result.is_err());
        match result {
            Err(AuraError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_get_public_key() {
        let mut dm = setup_did_manager();

        let (did, _, key_pair) = dm.create_did().unwrap();
        let public_key = dm.get_public_key(&did).unwrap();

        assert_eq!(public_key, key_pair.public_key());
    }

    #[test]
    fn test_get_public_key_not_found() {
        let dm = setup_did_manager();
        let did = AuraDid("did:aura:notfound".to_string());

        let result = dm.get_public_key(&did);
        assert!(result.is_err());
        match result {
            Err(AuraError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_list_dids() {
        let mut dm = setup_did_manager();

        // Initially empty
        assert_eq!(dm.list_dids().len(), 0);

        // Create some DIDs
        let mut created_dids = Vec::new();
        for _ in 0..3 {
            let (did, _, _) = dm.create_did().unwrap();
            created_dids.push(did);
        }

        // List and verify
        let listed = dm.list_dids();
        assert_eq!(listed.len(), 3);
        for did in &created_dids {
            assert!(listed.contains(did));
        }
    }

    #[test]
    fn test_encode_decode_public_key() {
        let dm = setup_did_manager();
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key();

        // Encode
        let encoded = dm.encode_public_key(&public_key);
        assert!(encoded.starts_with('z')); // Base58btc multibase prefix

        // Decode
        let decoded = dm.decode_public_key(&encoded).unwrap();
        assert_eq!(decoded, public_key);
    }

    #[test]
    fn test_decode_invalid_multibase() {
        let dm = setup_did_manager();

        let result = dm.decode_public_key("invalid-multibase");
        assert!(result.is_err());
        match result {
            Err(AuraError::Crypto(msg)) => {
                assert!(msg.contains("Invalid multibase key"));
            }
            _ => panic!("Expected Crypto error"),
        }
    }

    #[test]
    fn test_decode_wrong_key_type() {
        let dm = setup_did_manager();

        // Create a multibase string with wrong prefix
        let mut data = vec![0x12, 0x20]; // SHA-256 multicodec prefix instead of Ed25519
        data.extend_from_slice(&[0u8; 32]);
        let encoded = multibase::encode(multibase::Base::Base58Btc, &data);

        let result = dm.decode_public_key(&encoded);
        assert!(result.is_err());
        match result {
            Err(AuraError::Crypto(msg)) => {
                assert!(msg.contains("Invalid Ed25519 public key format"));
            }
            _ => panic!("Expected Crypto error"),
        }
    }

    #[test]
    fn test_decode_key_too_short() {
        let dm = setup_did_manager();

        // Create a multibase string that's too short
        let data = vec![0xed, 0x01, 0x00]; // Only 3 bytes
        let encoded = multibase::encode(multibase::Base::Base58Btc, &data);

        let result = dm.decode_public_key(&encoded);
        assert!(result.is_err());
        match result {
            Err(AuraError::Crypto(msg)) => {
                assert!(msg.contains("Invalid Ed25519 public key format"));
            }
            _ => panic!("Expected Crypto error"),
        }
    }

    #[test]
    fn test_verification_relationships() {
        let mut dm = setup_did_manager();

        let (did, did_document, _) = dm.create_did().unwrap();

        // Check all verification relationships point to the same key
        let key_ref = format!("{did}#key-1");

        assert_eq!(did_document.authentication.len(), 1);
        match &did_document.authentication[0] {
            VerificationRelationship::Reference(ref_id) => {
                assert_eq!(ref_id, &key_ref);
            }
            _ => panic!("Expected Reference"),
        }

        assert_eq!(did_document.assertion_method.len(), 1);
        match &did_document.assertion_method[0] {
            VerificationRelationship::Reference(ref_id) => {
                assert_eq!(ref_id, &key_ref);
            }
            _ => panic!("Expected Reference"),
        }

        assert_eq!(did_document.key_agreement.len(), 1);
        match &did_document.key_agreement[0] {
            VerificationRelationship::Reference(ref_id) => {
                assert_eq!(ref_id, &key_ref);
            }
            _ => panic!("Expected Reference"),
        }
    }
}
