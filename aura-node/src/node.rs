use crate::config::NodeConfig;
use crate::network::NetworkManager;
use aura_common::{AuraError, BlockNumber, Result};
use aura_crypto::KeyPair;
use aura_ledger::{
    did_registry::DidRegistry, revocation_registry::RevocationRegistry, storage::Storage,
    vc_schema_registry::VcSchemaRegistry, Block, ProofOfAuthority, Transaction, TransactionType,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

// Struct to hold block production parameters
struct BlockProductionParams {
    storage: Arc<Storage>,
    transaction_pool: Arc<RwLock<Vec<Transaction>>>,
    _did_registry: Arc<RwLock<DidRegistry>>,
    network: Arc<Mutex<NetworkManager>>,
    consensus: Arc<RwLock<ProofOfAuthority>>,
    validator_key: KeyPair,
    block_number: BlockNumber,
    max_transactions: usize,
}

pub struct AuraNode {
    config: NodeConfig,
    is_validator: bool,
    storage: Arc<Storage>,
    consensus: Arc<RwLock<ProofOfAuthority>>,
    did_registry: Arc<RwLock<DidRegistry>>,
    #[allow(dead_code)]
    schema_registry: Arc<RwLock<VcSchemaRegistry>>,
    #[allow(dead_code)]
    revocation_registry: Arc<RwLock<RevocationRegistry>>,
    network: Arc<tokio::sync::Mutex<NetworkManager>>,
    validator_key: Option<KeyPair>,
    transaction_pool: Arc<RwLock<Vec<Transaction>>>,
}

impl AuraNode {
    pub async fn new(
        config: NodeConfig,
        data_dir: PathBuf,
        is_validator: bool,
    ) -> anyhow::Result<Self> {
        info!("Initializing Aura Node...");

        // Initialize storage
        let storage_path = data_dir.join("ledger");
        let storage = Arc::new(Storage::new(storage_path)?);

        // Initialize consensus
        let consensus = if let Some(latest_block_num) = storage.get_latest_block_number()? {
            // Load consensus state from the latest block
            let _latest_block = storage
                .get_block(&latest_block_num)?
                .ok_or_else(|| anyhow::anyhow!("Latest block not found"))?;

            // For now, create a new consensus with hardcoded validators
            // In production, this would be loaded from genesis or chain state
            Arc::new(RwLock::new(ProofOfAuthority::new(vec![])))
        } else {
            // Initialize with genesis validators
            Arc::new(RwLock::new(ProofOfAuthority::new(vec![])))
        };

        // Initialize registries
        let did_registry = Arc::new(RwLock::new(DidRegistry::new(storage.clone())));
        let schema_registry = Arc::new(RwLock::new(VcSchemaRegistry::new(storage.clone())));
        let revocation_registry = Arc::new(RwLock::new(RevocationRegistry::new(storage.clone())));

        // Load validator key if this is a validator node
        let validator_key = if is_validator {
            if let Some(_key_path) = &config.consensus.validator_key_path {
                // In production, load from secure storage
                // For now, generate a new key
                Some(
                    KeyPair::generate()
                        .map_err(|e| anyhow::anyhow!("Failed to generate key: {}", e))?,
                )
            } else {
                warn!("Validator node without key path configured, generating ephemeral key");
                Some(
                    KeyPair::generate()
                        .map_err(|e| anyhow::anyhow!("Failed to generate key: {}", e))?,
                )
            }
        } else {
            None
        };

        // Initialize network
        let network = Arc::new(Mutex::new(
            NetworkManager::new(config.network.clone()).await?,
        ));

        Ok(Self {
            config,
            is_validator,
            storage,
            consensus,
            did_registry,
            schema_registry,
            revocation_registry,
            network,
            validator_key,
            transaction_pool: Arc::new(RwLock::new(Vec::new())),
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        info!("Starting Aura Node...");

        // Start network service
        let network_handle = self.start_network_service().await?;

        // Start block production if validator
        if self.is_validator {
            let block_production_handle = self.start_block_production().await?;

            // Wait for both services
            tokio::select! {
                _ = network_handle => {
                    warn!("Network service ended");
                }
                _ = block_production_handle => {
                    warn!("Block production ended");
                }
            }
        } else {
            // Just run network service for query nodes
            network_handle.await?;
        }

        Ok(())
    }

    async fn start_network_service(&self) -> anyhow::Result<tokio::task::JoinHandle<()>> {
        let network = self.network.clone();

        let handle = tokio::spawn(async move {
            info!("Network service started");

            loop {
                let mut network_guard = network.lock().await;
                if let Err(e) = network_guard.run().await {
                    error!("Network error: {}", e);
                    break;
                }
            }
        });

        Ok(handle)
    }

    async fn start_block_production(&self) -> anyhow::Result<tokio::task::JoinHandle<()>> {
        let block_time = tokio::time::Duration::from_secs(self.config.consensus.block_time_secs);
        let max_tx_per_block = self.config.consensus.max_transactions_per_block;

        let storage = self.storage.clone();
        let consensus = self.consensus.clone();
        let validator_key = self.validator_key.clone();
        let transaction_pool = self.transaction_pool.clone();
        let did_registry = self.did_registry.clone();
        let network = self.network.clone();

        let handle = tokio::spawn(async move {
            info!("Block production started");

            let mut interval = tokio::time::interval(block_time);

            loop {
                interval.tick().await;

                // Check if it's our turn to produce a block
                let latest_block_num = match storage.get_latest_block_number() {
                    Ok(Some(num)) => num,
                    Ok(None) => BlockNumber(0),
                    Err(e) => {
                        error!("Failed to get latest block number: {}", e);
                        continue;
                    }
                };

                let next_block_num = BlockNumber(latest_block_num.0 + 1);

                // Check if we're the validator for this block
                let consensus_guard = consensus.read().await;
                let expected_validator = match consensus_guard.get_block_validator(&next_block_num)
                {
                    Ok(validator) => validator,
                    Err(e) => {
                        error!("Failed to get block validator: {}", e);
                        continue;
                    }
                };

                if let Some(ref validator_key_ref) = validator_key {
                    if expected_validator.to_bytes() == validator_key_ref.public_key().to_bytes() {
                        drop(consensus_guard); // Release the read lock

                        // It's our turn to produce a block
                        let params = BlockProductionParams {
                            storage: storage.clone(),
                            transaction_pool: transaction_pool.clone(),
                            _did_registry: did_registry.clone(),
                            network: network.clone(),
                            consensus: consensus.clone(),
                            validator_key: validator_key_ref.clone(),
                            block_number: next_block_num,
                            max_transactions: max_tx_per_block,
                        };

                        if let Err(e) = Self::produce_block_static(params).await {
                            error!("Failed to produce block: {}", e);
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn produce_block_static(params: BlockProductionParams) -> anyhow::Result<()> {
        info!("Producing block {}", params.block_number.0);

        // Get transactions from the pool
        let mut tx_pool = params.transaction_pool.write().await;
        let drain_count = params.max_transactions.min(tx_pool.len());
        let transactions: Vec<Transaction> = tx_pool.drain(..drain_count).collect();
        drop(tx_pool);

        // Get previous block hash
        let previous_hash = if params.block_number.0 > 1 {
            let prev_block = params
                .storage
                .get_block(&BlockNumber(params.block_number.0 - 1))?
                .ok_or_else(|| anyhow::anyhow!("Previous block not found"))?;
            prev_block.hash()
        } else {
            [0u8; 32] // Genesis block has zero hash as previous
        };

        // Create new block
        let mut block = Block::new(
            params.block_number,
            previous_hash,
            transactions,
            params.validator_key.public_key().clone(),
        );

        // Sign the block
        let consensus_guard = params.consensus.write().await;
        consensus_guard
            .sign_block(&mut block, params.validator_key.private_key())
            .map_err(|e| anyhow::anyhow!("Failed to sign block: {}", e))?;
        drop(consensus_guard);

        // Process transactions
        for _tx in &block.transactions {
            // TODO: Implement transaction processing in static context
            // For now, skip processing to allow compilation
        }

        // Store the block
        params.storage.put_block(&block)?;
        params
            .storage
            .set_latest_block_number(&params.block_number)?;

        info!(
            "Block {} produced with {} transactions",
            params.block_number.0,
            block.transactions.len()
        );

        // Broadcast block to network
        let block_data = serde_json::to_vec(&block)
            .map_err(|e| anyhow::anyhow!("Failed to serialize block: {}", e))?;
        let mut network_guard = params.network.lock().await;
        network_guard.broadcast_block(block_data).await?;

        Ok(())
    }

    #[allow(dead_code)]
    async fn process_transaction(
        &self,
        tx: &Transaction,
        block_number: BlockNumber,
    ) -> anyhow::Result<()> {
        // Verify transaction
        if !tx.verify()? {
            return Err(anyhow::anyhow!("Invalid transaction signature"));
        }

        // Process based on transaction type
        match &tx.transaction_type {
            TransactionType::RegisterDid { did_document } => {
                let mut registry = self.did_registry.write().await;
                registry.register_did(did_document, tx.sender.clone(), block_number)?;
            }
            TransactionType::UpdateDid { did, did_document } => {
                let mut registry = self.did_registry.write().await;
                registry.update_did(did, did_document, &tx.sender, block_number)?;
            }
            TransactionType::DeactivateDid { did } => {
                let mut registry = self.did_registry.write().await;
                registry.deactivate_did(did, &tx.sender, block_number)?;
            }
            TransactionType::RegisterSchema { schema } => {
                let mut registry = self.schema_registry.write().await;
                registry.register_schema(schema, &schema.author, block_number)?;
            }
            TransactionType::UpdateRevocationList {
                list_id,
                revoked_indices,
            } => {
                let mut registry = self.revocation_registry.write().await;
                // For revocation updates, we need to determine the issuer from the transaction sender
                // In a real implementation, this would be more sophisticated
                let issuer_did = aura_common::AuraDid::new("temp"); // Placeholder
                registry.update_revocation_list(
                    list_id,
                    &issuer_did,
                    revoked_indices.clone(),
                    block_number,
                )?;
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn submit_transaction(&self, transaction: Transaction) -> Result<()> {
        // Verify transaction
        if !transaction.verify()? {
            return Err(AuraError::InvalidSignature);
        }

        // Add to transaction pool
        let mut tx_pool = self.transaction_pool.write().await;
        tx_pool.push(transaction);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_common::{AuraDid, DidDocument, VerificationMethod, VerificationRelationship, Timestamp};
    use aura_crypto::{PrivateKey, PublicKey};
    use aura_ledger::{Block, transaction::CredentialSchema};
    use std::collections::HashMap;
    use tempfile::TempDir;

    async fn create_test_node(is_validator: bool) -> (AuraNode, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        
        let config = NodeConfig {
            node_id: "test-node-1".to_string(),
            network: crate::config::NetworkConfig {
                listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
                bootstrap_peers: vec![],
                enable_mdns: false,
            },
            consensus: crate::config::ConsensusConfig {
                consensus_type: "proof-of-authority".to_string(),
                validator_key_path: Some("./test-validator-key".to_string()),
                block_time_secs: 1,
                max_transactions_per_block: 100,
                min_transaction_fee: 0,
            },
            api: crate::config::ApiConfig {
                listen_address: "127.0.0.1:0".to_string(),
                enable_tls: false,
                enable_auth: true,
                cors_origins: vec!["*".to_string()],
                max_request_size: 1048576,
                rate_limit_per_minute: 100,
            },
            security: crate::config::SecurityConfig {
                enable_input_validation: true,
                max_payload_size: 1048576,
                enable_audit_logging: true,
                jwt_secret: Some("test-secret".to_string()),
                credentials_path: None,
                tls_cert_path: None,
                tls_key_path: None,
                enable_key_pinning: false,
                pinned_public_keys: vec![],
            },
        };

        let node = AuraNode::new(config, data_dir, is_validator).await.unwrap();
        (node, temp_dir)
    }

    fn create_test_transaction(tx_type: TransactionType) -> Transaction {
        let keypair = KeyPair::generate().unwrap();
        let tx = Transaction {
            id: aura_common::TransactionId(uuid::Uuid::new_v4().to_string()),
            transaction_type: tx_type,
            timestamp: Timestamp::now(),
            sender: keypair.public_key().clone(),
            signature: aura_crypto::Signature(vec![0; 64]), // Dummy signature
            nonce: 1,
            chain_id: "test-chain".to_string(),
            expires_at: Some(Timestamp::from_unix(Timestamp::now().as_unix() + 3600)),
        };
        
        // Create transaction for signing
        let tx_for_signing = aura_ledger::transaction::TransactionForSigning {
            id: tx.id.clone(),
            transaction_type: tx.transaction_type.clone(),
            timestamp: tx.timestamp,
            sender: tx.sender.clone(),
            nonce: tx.nonce,
            chain_id: tx.chain_id.clone(),
            expires_at: tx.expires_at,
        };
        
        // Sign the transaction
        let signature = aura_crypto::sign_json(keypair.private_key(), &tx_for_signing).unwrap();
        
        Transaction {
            signature,
            ..tx
        }
    }

    #[tokio::test]
    async fn test_node_creation_query() {
        let (node, _temp_dir) = create_test_node(false).await;
        assert!(!node.is_validator);
        assert!(node.validator_key.is_none());
    }

    #[tokio::test]
    async fn test_node_creation_validator() {
        let (node, _temp_dir) = create_test_node(true).await;
        assert!(node.is_validator);
        assert!(node.validator_key.is_some());
    }

    #[tokio::test]
    async fn test_submit_transaction_valid() {
        let (node, _temp_dir) = create_test_node(false).await;
        
        let did = AuraDid::new("test");
        let mut doc = DidDocument::new(did.clone());
        doc.authentication = vec![VerificationRelationship::Embedded(VerificationMethod {
            id: format!("{}#key-1", did.to_string()),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            controller: did.clone(),
            public_key_multibase: "zEd25519...".to_string(),
        })];
        
        let tx = create_test_transaction(TransactionType::RegisterDid {
            did_document: doc,
        });
        
        let result = node.submit_transaction(tx).await;
        assert!(result.is_ok());
        
        // Verify transaction was added to pool
        let tx_pool = node.transaction_pool.read().await;
        assert_eq!(tx_pool.len(), 1);
    }

    #[tokio::test]
    async fn test_submit_transaction_invalid_signature() {
        let (node, _temp_dir) = create_test_node(false).await;
        
        let did = AuraDid::new("test");
        let doc = DidDocument::new(did.clone());
        
        let mut tx = Transaction {
            id: aura_common::TransactionId(uuid::Uuid::new_v4().to_string()),
            transaction_type: TransactionType::RegisterDid { did_document: doc },
            timestamp: Timestamp::now(),
            sender: PublicKey::from_bytes(&[0u8; 32]).unwrap(),
            signature: aura_crypto::Signature(vec![0; 64]),
            nonce: 0,
            chain_id: "test-chain".to_string(),
            expires_at: None,
        };
        
        // Invalid signature
        tx.signature = aura_crypto::Signature(vec![0u8; 64]);
        
        let result = node.submit_transaction(tx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuraError::InvalidSignature));
    }

    #[tokio::test]
    async fn test_process_transaction_register_did() {
        let (node, _temp_dir) = create_test_node(false).await;
        
        let did = AuraDid::new("test");
        let doc = DidDocument::new(did.clone());
        
        let tx = create_test_transaction(TransactionType::RegisterDid {
            did_document: doc.clone(),
        });
        
        let result = node.process_transaction(&tx, BlockNumber(1)).await;
        assert!(result.is_ok());
        
        // Verify DID was registered
        let registry = node.did_registry.read().await;
        let stored_did = registry.resolve_did(&did).unwrap();
        assert!(stored_did.is_some());
    }

    #[tokio::test]
    async fn test_process_transaction_update_did() {
        let (node, _temp_dir) = create_test_node(false).await;
        
        let did = AuraDid::new("test");
        let doc = DidDocument::new(did.clone());
        
        // First register the DID
        let register_tx = create_test_transaction(TransactionType::RegisterDid {
            did_document: doc.clone(),
        });
        node.process_transaction(&register_tx, BlockNumber(1)).await.unwrap();
        
        // Now update it
        let mut updated_doc = doc.clone();
        updated_doc.updated = Timestamp::now();
        
        let update_tx = create_test_transaction(TransactionType::UpdateDid {
            did: did.clone(),
            did_document: updated_doc,
        });
        
        let result = node.process_transaction(&update_tx, BlockNumber(2)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_process_transaction_deactivate_did() {
        let (node, _temp_dir) = create_test_node(false).await;
        
        let did = AuraDid::new("test");
        let doc = DidDocument::new(did.clone());
        
        // First register the DID
        let register_tx = create_test_transaction(TransactionType::RegisterDid {
            did_document: doc,
        });
        node.process_transaction(&register_tx, BlockNumber(1)).await.unwrap();
        
        // Now deactivate it
        let deactivate_tx = create_test_transaction(TransactionType::DeactivateDid {
            did: did.clone(),
        });
        
        let result = node.process_transaction(&deactivate_tx, BlockNumber(2)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_process_transaction_register_schema() {
        let (node, _temp_dir) = create_test_node(false).await;
        
        let author_did = AuraDid::new("author");
        let schema = CredentialSchema {
            id: "test-schema".to_string(),
            schema_type: "CredentialSchema2023".to_string(),
            name: "Test Schema".to_string(),
            version: "1.0.0".to_string(),
            author: author_did,
            created: Timestamp::now(),
            schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        };
        
        let tx = create_test_transaction(TransactionType::RegisterSchema {
            schema: schema.clone(),
        });
        
        let result = node.process_transaction(&tx, BlockNumber(1)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_process_transaction_update_revocation_list() {
        let (node, _temp_dir) = create_test_node(false).await;
        
        let revoked_indices = vec![1, 5, 10];
        let tx = create_test_transaction(TransactionType::UpdateRevocationList {
            list_id: "test-list".to_string(),
            revoked_indices: revoked_indices.clone(),
        });
        
        let result = node.process_transaction(&tx, BlockNumber(1)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_process_transaction_invalid_signature() {
        let (node, _temp_dir) = create_test_node(false).await;
        
        let did = AuraDid::new("test");
        let doc = DidDocument::new(did.clone());
        
        let mut tx = Transaction {
            id: aura_common::TransactionId(uuid::Uuid::new_v4().to_string()),
            transaction_type: TransactionType::RegisterDid { did_document: doc },
            timestamp: Timestamp::now(),
            sender: PublicKey::from_bytes(&[0u8; 32]).unwrap(),
            signature: aura_crypto::Signature(vec![0; 64]),
            nonce: 0,
            chain_id: "test-chain".to_string(),
            expires_at: None,
        };
        
        // Invalid signature
        tx.signature = aura_crypto::Signature(vec![0u8; 64]);
        
        let result = node.process_transaction(&tx, BlockNumber(1)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_produce_block_static() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path().to_path_buf()).unwrap());
        let consensus = Arc::new(RwLock::new(ProofOfAuthority::new(vec![])));
        let transaction_pool = Arc::new(RwLock::new(Vec::new()));
        let did_registry = Arc::new(RwLock::new(DidRegistry::new(storage.clone())));
        let network = Arc::new(Mutex::new(NetworkManager::new(crate::config::NetworkConfig {
            listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
            bootstrap_peers: vec![],
            enable_mdns: false,
        }).await.unwrap()));
        
        let validator_key = KeyPair::generate().unwrap();
        
        // Add some transactions
        let tx1 = create_test_transaction(TransactionType::RegisterDid {
            did_document: DidDocument {
                id: AuraDid::new("test1"),
                authentication: vec![],
                assertion_method: vec![],
                created: chrono::Utc::now(),
                updated: chrono::Utc::now(),
            },
        });
        
        let tx2 = create_test_transaction(TransactionType::RegisterDid {
            did_document: DidDocument {
                id: AuraDid::new("test2"),
                authentication: vec![],
                assertion_method: vec![],
                created: chrono::Utc::now(),
                updated: chrono::Utc::now(),
            },
        });
        
        {
            let mut pool = transaction_pool.write().await;
            pool.push(tx1);
            pool.push(tx2);
        }
        
        let params = BlockProductionParams {
            storage: storage.clone(),
            transaction_pool: transaction_pool.clone(),
            _did_registry: did_registry,
            network,
            consensus,
            validator_key,
            block_number: BlockNumber(1),
            max_transactions: 10,
        };
        
        let result = AuraNode::produce_block_static(params).await;
        assert!(result.is_ok());
        
        // Verify block was stored
        let block = storage.get_block(&BlockNumber(1)).unwrap();
        assert!(block.is_some());
        let block = block.unwrap();
        assert_eq!(block.transactions.len(), 2);
        
        // Verify transaction pool was drained
        let pool = transaction_pool.read().await;
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test]
    async fn test_produce_block_empty_pool() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path().to_path_buf()).unwrap());
        let consensus = Arc::new(RwLock::new(ProofOfAuthority::new(vec![])));
        let transaction_pool = Arc::new(RwLock::new(Vec::new()));
        let did_registry = Arc::new(RwLock::new(DidRegistry::new(storage.clone())));
        let network = Arc::new(Mutex::new(NetworkManager::new(crate::config::NetworkConfig {
            listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
            bootstrap_peers: vec![],
            enable_mdns: false,
        }).await.unwrap()));
        
        let validator_key = KeyPair::generate().unwrap();
        
        let params = BlockProductionParams {
            storage: storage.clone(),
            transaction_pool,
            _did_registry: did_registry,
            network,
            consensus,
            validator_key,
            block_number: BlockNumber(1),
            max_transactions: 10,
        };
        
        let result = AuraNode::produce_block_static(params).await;
        assert!(result.is_ok());
        
        // Verify empty block was stored
        let block = storage.get_block(&BlockNumber(1)).unwrap();
        assert!(block.is_some());
        assert_eq!(block.unwrap().transactions.len(), 0);
    }

    #[tokio::test]
    async fn test_produce_block_with_previous() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path().to_path_buf()).unwrap());
        let consensus = Arc::new(RwLock::new(ProofOfAuthority::new(vec![])));
        let transaction_pool = Arc::new(RwLock::new(Vec::new()));
        let did_registry = Arc::new(RwLock::new(DidRegistry::new(storage.clone())));
        let network = Arc::new(Mutex::new(NetworkManager::new(crate::config::NetworkConfig {
            listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
            bootstrap_peers: vec![],
            enable_mdns: false,
        }).await.unwrap()));
        
        let validator_key = KeyPair::generate().unwrap();
        
        // Create and store first block
        let first_block = Block::new(
            BlockNumber(1),
            [0u8; 32],
            vec![],
            validator_key.public_key().clone(),
        );
        storage.put_block(&first_block).unwrap();
        storage.set_latest_block_number(&BlockNumber(1)).unwrap();
        
        // Produce second block
        let params = BlockProductionParams {
            storage: storage.clone(),
            transaction_pool,
            _did_registry: did_registry,
            network,
            consensus,
            validator_key,
            block_number: BlockNumber(2),
            max_transactions: 10,
        };
        
        let result = AuraNode::produce_block_static(params).await;
        assert!(result.is_ok());
        
        // Verify second block references first
        let block = storage.get_block(&BlockNumber(2)).unwrap().unwrap();
        assert_eq!(block.previous_hash, first_block.hash());
    }

    #[tokio::test]
    async fn test_node_storage_initialization() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        
        // Create initial block in storage
        let storage_path = data_dir.join("ledger");
        std::fs::create_dir_all(&storage_path).unwrap();
        let storage = Storage::new(storage_path).unwrap();
        
        let keypair = KeyPair::generate().unwrap();
        let block = Block::new(
            BlockNumber(1),
            [0u8; 32],
            vec![],
            keypair.public_key().clone(),
        );
        storage.put_block(&block).unwrap();
        storage.set_latest_block_number(&BlockNumber(1)).unwrap();
        drop(storage);
        
        // Create node and verify it loads existing data
        let config = NodeConfig {
            node_id: "test-node".to_string(),
            network: crate::config::NetworkConfig {
                listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
                bootstrap_peers: vec![],
                enable_mdns: false,
            },
            consensus: crate::config::ConsensusConfig {
                consensus_type: "proof-of-authority".to_string(),
                validator_key_path: None,
                block_time_secs: 5,
                max_transactions_per_block: 100,
                min_transaction_fee: 0,
            },
            api: crate::config::ApiConfig {
                listen_address: "127.0.0.1:0".to_string(),
                enable_tls: false,
                enable_auth: true,
                cors_origins: vec![],
                max_request_size: 1048576,
                rate_limit_per_minute: 100,
            },
            security: crate::config::SecurityConfig {
                enable_input_validation: true,
                max_payload_size: 1048576,
                enable_audit_logging: true,
                jwt_secret: None,
                credentials_path: None,
                tls_cert_path: None,
                tls_key_path: None,
                enable_key_pinning: false,
                pinned_public_keys: vec![],
            },
        };
        
        let node = AuraNode::new(config, data_dir, false).await.unwrap();
        
        // Verify storage was loaded correctly
        let latest = node.storage.get_latest_block_number().unwrap();
        assert_eq!(latest, Some(BlockNumber(1)));
    }

    #[tokio::test]
    async fn test_multiple_transactions_in_pool() {
        let (node, _temp_dir) = create_test_node(false).await;
        
        // Submit multiple transactions
        let mut transactions = vec![];
        for i in 0..5 {
            let did = AuraDid::new(&format!("test{}", i));
            let doc = DidDocument {
                id: did.clone(),
                authentication: vec![],
                assertion_method: vec![],
                created: chrono::Utc::now(),
                updated: chrono::Utc::now(),
            };
            
            let tx = create_test_transaction(TransactionType::RegisterDid {
                did_document: doc,
            });
            transactions.push(tx.clone());
            node.submit_transaction(tx).await.unwrap();
        }
        
        // Verify all transactions are in pool
        let tx_pool = node.transaction_pool.read().await;
        assert_eq!(tx_pool.len(), 5);
        
        // Verify transactions are the same
        for (i, tx) in tx_pool.iter().enumerate() {
            assert_eq!(tx.hash(), transactions[i].hash());
        }
    }

    #[tokio::test]
    async fn test_transaction_pool_drain_limit() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path().to_path_buf()).unwrap());
        let consensus = Arc::new(RwLock::new(ProofOfAuthority::new(vec![])));
        let transaction_pool = Arc::new(RwLock::new(Vec::new()));
        let did_registry = Arc::new(RwLock::new(DidRegistry::new(storage.clone())));
        let network = Arc::new(Mutex::new(NetworkManager::new(crate::config::NetworkConfig {
            listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
            bootstrap_peers: vec![],
            enable_mdns: false,
        }).await.unwrap()));
        
        // Add more transactions than max_transactions
        {
            let mut pool = transaction_pool.write().await;
            for i in 0..10 {
                let tx = create_test_transaction(TransactionType::RegisterDid {
                    did_document: DidDocument {
                        id: AuraDid::new(&format!("test{}", i)),
                        authentication: vec![],
                        assertion_method: vec![],
                        created: chrono::Utc::now(),
                        updated: chrono::Utc::now(),
                    },
                });
                pool.push(tx);
            }
        }
        
        let validator_key = KeyPair::generate().unwrap();
        
        let params = BlockProductionParams {
            storage: storage.clone(),
            transaction_pool: transaction_pool.clone(),
            _did_registry: did_registry,
            network,
            consensus,
            validator_key,
            block_number: BlockNumber(1),
            max_transactions: 5, // Limit to 5
        };
        
        let result = AuraNode::produce_block_static(params).await;
        assert!(result.is_ok());
        
        // Verify only 5 transactions were included
        let block = storage.get_block(&BlockNumber(1)).unwrap().unwrap();
        assert_eq!(block.transactions.len(), 5);
        
        // Verify 5 transactions remain in pool
        let pool = transaction_pool.read().await;
        assert_eq!(pool.len(), 5);
    }
}
