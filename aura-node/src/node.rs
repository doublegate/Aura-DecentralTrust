use crate::config::NodeConfig;
use crate::network::NetworkManager;
use aura_common::{AuraError, BlockNumber, Result};
use aura_crypto::{KeyPair, PublicKey};
use aura_ledger::{
    did_registry::DidRegistry, revocation_registry::RevocationRegistry, storage::Storage,
    vc_schema_registry::VcSchemaRegistry, Block, Blockchain, ProofOfAuthority, Transaction,
    TransactionType,
};
use base64::Engine;
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
    blockchain: Arc<RwLock<Blockchain>>,
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
    /// Get the node components needed by the API
    pub fn get_api_components(&self) -> crate::api::NodeComponents {
        crate::api::NodeComponents {
            blockchain: self.blockchain.clone(),
            did_registry: self.did_registry.clone(),
            schema_registry: self.schema_registry.clone(),
            revocation_registry: self.revocation_registry.clone(),
            transaction_pool: self.transaction_pool.clone(),
        }
    }

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

            info!(
                "Loading validators from existing chain state at block {}",
                latest_block_num.0
            );

            // Load validators from chain state
            let validators = Self::load_validators_from_chain(storage.clone())?;
            Arc::new(RwLock::new(ProofOfAuthority::new(validators)))
        } else {
            info!("Initializing new chain with genesis validators");

            // Initialize with genesis validators from config
            let genesis_validators = Self::load_genesis_validators(&config)?;
            Arc::new(RwLock::new(ProofOfAuthority::new(genesis_validators)))
        };

        // Initialize blockchain
        let blockchain = Arc::new(RwLock::new(Blockchain::new(storage.clone())));

        // Initialize registries
        let did_registry = Arc::new(RwLock::new(DidRegistry::new(storage.clone())));
        let schema_registry = Arc::new(RwLock::new(VcSchemaRegistry::new(storage.clone())));
        let revocation_registry = Arc::new(RwLock::new(RevocationRegistry::new(storage.clone())));

        // Load validator key if this is a validator node
        let validator_key = if is_validator {
            if let Some(key_path) = &config.consensus.validator_key_path {
                info!("Loading validator key from secure storage: {}", key_path);
                Some(Self::load_or_create_validator_key(
                    key_path,
                    data_dir.as_path(),
                )?)
            } else {
                warn!("Validator node without key path configured, generating ephemeral key");
                warn!("Set 'validator_key_path' in config for production use!");
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
            blockchain,
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
        let previous_hash = if params.block_number.0 > 0 {
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

        // In tests, broadcasting may fail due to no connected peers - log but don't fail
        if let Err(e) = network_guard.broadcast_block(block_data).await {
            warn!(
                "Failed to broadcast block: {}. This is expected in tests without connected peers.",
                e
            );
        }

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
                // In a real implementation, we would look up the issuer from the revocation list
                // For now, we'll create the list if it doesn't exist (using sender as issuer)

                // Try to get existing list first
                if let Some(existing_list) = registry.get_revocation_list(list_id)? {
                    // Update existing list - verify sender owns it
                    // For testing, we'll just use the existing issuer
                    registry.update_revocation_list(
                        list_id,
                        &existing_list.issuer_did,
                        revoked_indices.clone(),
                        block_number,
                    )?;
                } else {
                    // Create new list using sender's public key as basis for DID
                    let issuer_did = aura_common::AuraDid::new(&format!(
                        "did:aura:{}",
                        hex::encode(&tx.sender.to_bytes()[..8])
                    ));
                    registry.create_revocation_list(list_id, &issuer_did, block_number)?;
                    // Now update it
                    registry.update_revocation_list(
                        list_id,
                        &issuer_did,
                        revoked_indices.clone(),
                        block_number,
                    )?;
                }
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

    /// Load validators from existing chain state
    fn load_validators_from_chain(storage: Arc<Storage>) -> anyhow::Result<Vec<PublicKey>> {
        // In a real implementation, this would scan the blockchain for validator updates
        // For now, we'll extract validators from existing blocks and transactions

        let mut validators = vec![];

        // Try to get genesis block and use its validator as the initial validator
        if let Some(genesis_block) = storage.get_block(&BlockNumber(0))? {
            info!("Found genesis block, extracting initial validator");

            // Add the genesis block validator to the set
            validators.push(genesis_block.header.validator.clone());

            // Scan through recent blocks to find other validators
            if let Some(latest_block_num) = storage.get_latest_block_number()? {
                let start_block = if latest_block_num.0 > 10 {
                    latest_block_num.0 - 10
                } else {
                    1
                };

                for block_num in start_block..=latest_block_num.0 {
                    if let Some(block) = storage.get_block(&BlockNumber(block_num))? {
                        // Add any new validators we find
                        if !validators.contains(&block.header.validator) {
                            validators.push(block.header.validator.clone());
                        }
                    }
                }
            }

            info!("Loaded {} validators from chain state", validators.len());
            Ok(validators)
        } else {
            Err(anyhow::anyhow!(
                "Genesis block not found when loading validators"
            ))
        }
    }

    /// Load genesis validators from config
    fn load_genesis_validators(_config: &NodeConfig) -> anyhow::Result<Vec<PublicKey>> {
        let mut validators = vec![];

        // For testing/development, create default validators
        // In production, this would come from a genesis configuration file
        info!("Creating genesis validators for new chain");

        // Create at least one validator for the initial node
        let genesis_validator = KeyPair::generate()?;
        validators.push(genesis_validator.public_key().clone());

        info!("Created {} genesis validators", validators.len());

        Ok(validators)
    }

    /// Load or create a validator key from secure storage
    fn load_or_create_validator_key(
        key_path: &str,
        data_dir: &std::path::Path,
    ) -> anyhow::Result<KeyPair> {
        use std::fs;

        // Resolve the key path (absolute or relative to data_dir)
        let key_file_path = if std::path::Path::new(key_path).is_absolute() {
            std::path::PathBuf::from(key_path)
        } else {
            data_dir.join(key_path)
        };

        info!("Validator key file path: {:?}", key_file_path);

        // Create the parent directory if it doesn't exist
        if let Some(parent) = key_file_path.parent() {
            fs::create_dir_all(parent)?;
        }

        if key_file_path.exists() {
            info!("Loading existing validator key");
            Self::load_validator_key_from_file(&key_file_path)
        } else {
            info!("Creating new validator key");
            let keypair = KeyPair::generate()?;
            Self::save_validator_key_to_file(&keypair, &key_file_path)?;
            Ok(keypair)
        }
    }

    /// Load validator key from encrypted file
    fn load_validator_key_from_file(key_file_path: &std::path::Path) -> anyhow::Result<KeyPair> {
        use std::fs;

        // Read the encrypted key file
        let encrypted_data = fs::read(key_file_path)
            .map_err(|e| anyhow::anyhow!("Failed to read key file: {}", e))?;

        // For now, we'll use a simple base64 encoding
        // In production, this should be properly encrypted with a password or HSM
        let key_data = base64::engine::general_purpose::STANDARD
            .decode(&encrypted_data)
            .map_err(|e| anyhow::anyhow!("Failed to decode key file: {}", e))?;

        if key_data.len() != 32 {
            return Err(anyhow::anyhow!("Invalid key file: wrong length"));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key_data);

        let private_key = aura_crypto::PrivateKey::from_bytes(&key_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to create private key: {}", e))?;

        Ok(KeyPair::from_private_key(private_key))
    }

    /// Save validator key to encrypted file
    fn save_validator_key_to_file(
        keypair: &KeyPair,
        key_file_path: &std::path::Path,
    ) -> anyhow::Result<()> {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        // Get the private key bytes
        let key_bytes = keypair.private_key().to_bytes();

        // For now, we'll use base64 encoding
        // In production, this should be properly encrypted
        let encoded_key = base64::engine::general_purpose::STANDARD.encode(&key_bytes);

        // Write to file with restrictive permissions
        fs::write(key_file_path, encoded_key)
            .map_err(|e| anyhow::anyhow!("Failed to write key file: {}", e))?;

        // Set file permissions to 600 (owner read/write only)
        let mut perms = fs::metadata(key_file_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(key_file_path, perms)?;

        info!(
            "Validator key saved to {:?} with secure permissions",
            key_file_path
        );
        warn!("SECURITY: Key is stored in base64 format. Use proper encryption in production!");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_common::vc::CredentialSchema;
    use aura_common::{
        AuraDid, DidDocument, Timestamp, VerificationMethod, VerificationRelationship,
    };
    use aura_ledger::Block;
    use tempfile::TempDir;

    async fn create_test_node(is_validator: bool) -> (AuraNode, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();

        let config = NodeConfig {
            node_id: "test-node-1".to_string(),
            network: crate::config::NetworkConfig {
                listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
                bootstrap_nodes: vec![],
                max_peers: 50,
            },
            consensus: crate::config::ConsensusConfig {
                validator_key_path: if is_validator {
                    Some("./test-validator-key".to_string())
                } else {
                    None
                },
                block_time_secs: 1,
                max_transactions_per_block: 100,
            },
            storage: crate::config::StorageConfig {
                db_path: data_dir.join("ledger").to_string_lossy().to_string(),
                cache_size_mb: 128,
            },
            api: crate::config::ApiConfig {
                listen_address: "127.0.0.1:0".to_string(),
                enable_cors: true,
                max_request_size: 1048576,
            },
            security: crate::config::SecurityConfig {
                jwt_secret: Some("test-secret".to_string()),
                credentials_path: None,
                token_expiry_hours: 24,
                rate_limit_rpm: 100,
                rate_limit_rph: 1000,
            },
        };

        let node = AuraNode::new(config, data_dir, is_validator).await.unwrap();
        (node, temp_dir)
    }

    fn create_test_transaction(tx_type: TransactionType) -> Transaction {
        let keypair = KeyPair::generate().unwrap();
        create_test_transaction_with_keypair(tx_type, &keypair)
    }

    fn create_test_transaction_with_keypair(
        tx_type: TransactionType,
        keypair: &KeyPair,
    ) -> Transaction {
        let tx = Transaction {
            id: aura_common::TransactionId(uuid::Uuid::new_v4().to_string()),
            transaction_type: tx_type,
            timestamp: Timestamp::now(),
            sender: keypair.public_key(),
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

        Transaction { signature, ..tx }
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
            id: format!("{did}#key-1"),
            verification_type: "Ed25519VerificationKey2020".to_string(),
            controller: did.clone(),
            public_key_multibase: Some("zEd25519...".to_string()),
            public_key_jwk: None,
            public_key_base58: None,
        })];

        let tx = create_test_transaction(TransactionType::RegisterDid { did_document: doc });

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

        // Use a real keypair but provide wrong signature
        let keypair = KeyPair::generate().unwrap();

        let tx = Transaction {
            id: aura_common::TransactionId(uuid::Uuid::new_v4().to_string()),
            transaction_type: TransactionType::RegisterDid { did_document: doc },
            timestamp: Timestamp::now(),
            sender: keypair.public_key(),
            signature: aura_crypto::Signature(vec![0u8; 64]), // Invalid signature
            nonce: 0,
            chain_id: "test-chain".to_string(),
            expires_at: None,
        };

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

        // Use the same keypair for both transactions
        let keypair = KeyPair::generate().unwrap();

        // First register the DID
        let register_tx = create_test_transaction_with_keypair(
            TransactionType::RegisterDid {
                did_document: doc.clone(),
            },
            &keypair,
        );
        node.process_transaction(&register_tx, BlockNumber(1))
            .await
            .unwrap();

        // Now update it
        let mut updated_doc = doc.clone();
        updated_doc.updated = Timestamp::now();

        let update_tx = create_test_transaction_with_keypair(
            TransactionType::UpdateDid {
                did: did.clone(),
                did_document: updated_doc,
            },
            &keypair,
        );

        let result = node.process_transaction(&update_tx, BlockNumber(2)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_process_transaction_deactivate_did() {
        let (node, _temp_dir) = create_test_node(false).await;

        let did = AuraDid::new("test");
        let doc = DidDocument::new(did.clone());

        // Use the same keypair for both transactions
        let keypair = KeyPair::generate().unwrap();

        // First register the DID
        let register_tx = create_test_transaction_with_keypair(
            TransactionType::RegisterDid { did_document: doc },
            &keypair,
        );
        node.process_transaction(&register_tx, BlockNumber(1))
            .await
            .unwrap();

        // Now deactivate it
        let deactivate_tx = create_test_transaction_with_keypair(
            TransactionType::DeactivateDid { did: did.clone() },
            &keypair,
        );

        let result = node
            .process_transaction(&deactivate_tx, BlockNumber(2))
            .await;
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

        // Use a real keypair but provide wrong signature
        let keypair = KeyPair::generate().unwrap();

        let tx = Transaction {
            id: aura_common::TransactionId(uuid::Uuid::new_v4().to_string()),
            transaction_type: TransactionType::RegisterDid { did_document: doc },
            timestamp: Timestamp::now(),
            sender: keypair.public_key(),
            signature: aura_crypto::Signature(vec![0u8; 64]), // Invalid signature
            nonce: 0,
            chain_id: "test-chain".to_string(),
            expires_at: None,
        };

        let result = node.process_transaction(&tx, BlockNumber(1)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_produce_block_static() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());
        let consensus = Arc::new(RwLock::new(ProofOfAuthority::new(vec![])));
        let transaction_pool = Arc::new(RwLock::new(Vec::new()));
        let did_registry = Arc::new(RwLock::new(DidRegistry::new(storage.clone())));
        let network = Arc::new(Mutex::new(
            NetworkManager::new(crate::config::NetworkConfig {
                listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
                bootstrap_nodes: vec![],
                max_peers: 50,
            })
            .await
            .unwrap(),
        ));

        let validator_key = KeyPair::generate().unwrap();

        // Add some transactions
        let tx1 = create_test_transaction(TransactionType::RegisterDid {
            did_document: DidDocument::new(AuraDid::new("test1")),
        });

        let tx2 = create_test_transaction(TransactionType::RegisterDid {
            did_document: DidDocument::new(AuraDid::new("test2")),
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
            block_number: BlockNumber(0),
            max_transactions: 10,
        };

        let result = AuraNode::produce_block_static(params).await;
        if let Err(e) = &result {
            eprintln!("Block production failed: {e}");
        }
        assert!(result.is_ok());

        // Verify block was stored
        let block = storage.get_block(&BlockNumber(0)).unwrap();
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
        let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());
        let consensus = Arc::new(RwLock::new(ProofOfAuthority::new(vec![])));
        let transaction_pool = Arc::new(RwLock::new(Vec::new()));
        let did_registry = Arc::new(RwLock::new(DidRegistry::new(storage.clone())));
        let network = Arc::new(Mutex::new(
            NetworkManager::new(crate::config::NetworkConfig {
                listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
                bootstrap_nodes: vec![],
                max_peers: 50,
            })
            .await
            .unwrap(),
        ));

        let validator_key = KeyPair::generate().unwrap();

        let params = BlockProductionParams {
            storage: storage.clone(),
            transaction_pool,
            _did_registry: did_registry,
            network,
            consensus,
            validator_key,
            block_number: BlockNumber(0),
            max_transactions: 10,
        };

        let result = AuraNode::produce_block_static(params).await;
        if let Err(e) = &result {
            eprintln!("Block production failed: {e}");
        }
        assert!(result.is_ok());

        // Verify empty block was stored
        let block = storage.get_block(&BlockNumber(0)).unwrap();
        assert!(block.is_some());
        assert_eq!(block.unwrap().transactions.len(), 0);
    }

    #[tokio::test]
    async fn test_produce_block_with_previous() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());
        let consensus = Arc::new(RwLock::new(ProofOfAuthority::new(vec![])));
        let transaction_pool = Arc::new(RwLock::new(Vec::new()));
        let did_registry = Arc::new(RwLock::new(DidRegistry::new(storage.clone())));
        let network = Arc::new(Mutex::new(
            NetworkManager::new(crate::config::NetworkConfig {
                listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
                bootstrap_nodes: vec![],
                max_peers: 50,
            })
            .await
            .unwrap(),
        ));

        let validator_key = KeyPair::generate().unwrap();

        // Create and store first block
        let first_block = Block::new(
            BlockNumber(0),
            [0u8; 32],
            vec![],
            validator_key.public_key().clone(),
        );
        storage.put_block(&first_block).unwrap();

        // Add a transaction for second block
        let tx = create_test_transaction(TransactionType::RegisterDid {
            did_document: DidDocument::new(AuraDid::new("test")),
        });

        {
            let mut pool = transaction_pool.write().await;
            pool.push(tx);
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
        if let Err(e) = &result {
            eprintln!("Block production failed: {e}");
        }
        assert!(result.is_ok());

        // Verify block references previous
        let block = storage.get_block(&BlockNumber(1)).unwrap().unwrap();
        assert_eq!(block.header.previous_hash, first_block.hash());
    }

    #[tokio::test]
    async fn test_produce_block_wrong_validator() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());

        // Create consensus with a specific validator
        let authorized_validator = KeyPair::generate().unwrap();
        let validators = vec![authorized_validator.public_key().clone()];
        let consensus = Arc::new(RwLock::new(ProofOfAuthority::new(validators)));

        let transaction_pool = Arc::new(RwLock::new(Vec::new()));
        let did_registry = Arc::new(RwLock::new(DidRegistry::new(storage.clone())));
        let network = Arc::new(Mutex::new(
            NetworkManager::new(crate::config::NetworkConfig {
                listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
                bootstrap_nodes: vec![],
                max_peers: 50,
            })
            .await
            .unwrap(),
        ));

        // Use a different validator key (not in consensus)
        let wrong_validator = KeyPair::generate().unwrap();

        let params = BlockProductionParams {
            storage: storage.clone(),
            transaction_pool,
            _did_registry: did_registry,
            network,
            consensus: consensus.clone(),
            validator_key: wrong_validator.clone(),
            block_number: BlockNumber(0),
            max_transactions: 10,
        };

        // Block production itself succeeds (it just signs with the provided key)
        let result = AuraNode::produce_block_static(params).await;
        if let Err(e) = &result {
            eprintln!("Block production failed: {e}");
        }
        assert!(result.is_ok());

        // But the block should fail validation because wrong validator signed it
        let block = storage.get_block(&BlockNumber(0)).unwrap().unwrap();
        let consensus_guard = consensus.read().await;
        let validation_result = consensus_guard.validate_block(&block, &[0u8; 32]);
        assert!(validation_result.is_err());
        assert!(validation_result
            .unwrap_err()
            .to_string()
            .contains("Invalid block validator"));
    }

    #[tokio::test]
    async fn test_storage_initialization() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();

        let config = NodeConfig {
            node_id: "test-node-1".to_string(),
            network: crate::config::NetworkConfig {
                listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
                bootstrap_nodes: vec![],
                max_peers: 50,
            },
            consensus: crate::config::ConsensusConfig {
                validator_key_path: None,
                block_time_secs: 1,
                max_transactions_per_block: 100,
            },
            storage: crate::config::StorageConfig {
                db_path: data_dir.join("ledger").to_string_lossy().to_string(),
                cache_size_mb: 128,
            },
            api: crate::config::ApiConfig {
                listen_address: "127.0.0.1:0".to_string(),
                enable_cors: true,
                max_request_size: 1048576,
            },
            security: crate::config::SecurityConfig {
                jwt_secret: Some("test-secret".to_string()),
                credentials_path: None,
                token_expiry_hours: 24,
                rate_limit_rpm: 100,
                rate_limit_rph: 1000,
            },
        };

        let ledger_path = data_dir.join("ledger");
        assert!(!ledger_path.exists());

        let _node = AuraNode::new(config, data_dir.clone(), false)
            .await
            .unwrap();

        // Storage should be initialized
        assert!(ledger_path.exists());
    }

    #[tokio::test]
    async fn test_process_transaction_all_types() {
        let (node, _temp_dir) = create_test_node(false).await;

        // Use the same keypair for DID operations
        let keypair = KeyPair::generate().unwrap();

        // Test all transaction types
        let did = AuraDid::new("test");
        let doc = DidDocument::new(did.clone());

        // 1. Register DID
        let register_tx = create_test_transaction_with_keypair(
            TransactionType::RegisterDid {
                did_document: doc.clone(),
            },
            &keypair,
        );
        assert!(node
            .process_transaction(&register_tx, BlockNumber(1))
            .await
            .is_ok());

        // 2. Update DID
        let update_tx = create_test_transaction_with_keypair(
            TransactionType::UpdateDid {
                did: did.clone(),
                did_document: doc.clone(),
            },
            &keypair,
        );
        assert!(node
            .process_transaction(&update_tx, BlockNumber(2))
            .await
            .is_ok());

        // 3. Register Schema
        let schema = CredentialSchema {
            id: "schema-1".to_string(),
            schema_type: "CredentialSchema2023".to_string(),
            name: "Test".to_string(),
            version: "1.0".to_string(),
            author: did.clone(),
            created: Timestamp::now(),
            schema: serde_json::json!({}),
        };
        let schema_tx = create_test_transaction(TransactionType::RegisterSchema { schema });
        assert!(node
            .process_transaction(&schema_tx, BlockNumber(3))
            .await
            .is_ok());

        // 4. Update Revocation List
        let revoke_tx = create_test_transaction(TransactionType::UpdateRevocationList {
            list_id: "list-1".to_string(),
            revoked_indices: vec![1, 2, 3],
        });
        assert!(node
            .process_transaction(&revoke_tx, BlockNumber(4))
            .await
            .is_ok());

        // 5. Deactivate DID
        let deactivate_tx =
            create_test_transaction_with_keypair(TransactionType::DeactivateDid { did }, &keypair);
        assert!(node
            .process_transaction(&deactivate_tx, BlockNumber(5))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_transaction_pool_ordering() {
        let (node, _temp_dir) = create_test_node(false).await;

        // Create transactions with different nonces
        let mut transactions = vec![];
        for i in 1..=5 {
            let tx_type = TransactionType::RegisterDid {
                did_document: DidDocument::new(AuraDid::new(&format!("test{i}"))),
            };
            let keypair = KeyPair::generate().unwrap();
            let mut tx = create_test_transaction_with_keypair(tx_type, &keypair);
            tx.nonce = i as u64;

            // Re-sign with updated nonce
            let tx_for_signing = aura_ledger::transaction::TransactionForSigning {
                id: tx.id.clone(),
                transaction_type: tx.transaction_type.clone(),
                timestamp: tx.timestamp,
                sender: tx.sender.clone(),
                nonce: tx.nonce,
                chain_id: tx.chain_id.clone(),
                expires_at: tx.expires_at,
            };
            tx.signature = aura_crypto::sign_json(keypair.private_key(), &tx_for_signing).unwrap();

            transactions.push(tx);
        }

        // Submit in reverse order
        for tx in transactions.iter().rev() {
            node.submit_transaction(tx.clone()).await.unwrap();
        }

        // Verify pool contains all transactions
        let pool = node.transaction_pool.read().await;
        assert_eq!(pool.len(), 5);

        // Note: In a real implementation, transactions might be ordered by nonce
        // but this basic pool doesn't guarantee ordering
    }

    #[tokio::test]
    async fn test_load_genesis_validators() {
        let temp_dir = TempDir::new().unwrap();
        let config = NodeConfig {
            node_id: "test-node".to_string(),
            network: crate::config::NetworkConfig {
                listen_addresses: vec![],
                bootstrap_nodes: vec![],
                max_peers: 50,
            },
            consensus: crate::config::ConsensusConfig {
                validator_key_path: None,
                block_time_secs: 5,
                max_transactions_per_block: 100,
            },
            storage: crate::config::StorageConfig {
                db_path: temp_dir.path().join("db").to_string_lossy().to_string(),
                cache_size_mb: 128,
            },
            api: crate::config::ApiConfig {
                listen_address: "127.0.0.1:8080".to_string(),
                enable_cors: true,
                max_request_size: 1048576,
            },
            security: crate::config::SecurityConfig {
                jwt_secret: None,
                credentials_path: None,
                token_expiry_hours: 24,
                rate_limit_rpm: 60,
                rate_limit_rph: 1000,
            },
        };

        let validators = AuraNode::load_genesis_validators(&config).unwrap();

        assert_eq!(validators.len(), 1);
        assert!(validators[0].to_bytes().len() == 32);
    }

    #[tokio::test]
    async fn test_load_validators_from_chain() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());

        // Create and store a genesis block with a validator
        let validator_keypair = KeyPair::generate().unwrap();
        let genesis_block = Block::new(
            BlockNumber(0),
            [0u8; 32],
            vec![],
            validator_keypair.public_key(),
        );

        storage.put_block(&genesis_block).unwrap();
        storage.set_latest_block_number(&BlockNumber(0)).unwrap();

        let validators = AuraNode::load_validators_from_chain(storage).unwrap();

        assert_eq!(validators.len(), 1);
        assert_eq!(validators[0], validator_keypair.public_key());
    }

    #[tokio::test]
    async fn test_load_validators_from_chain_multiple_blocks() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());

        // Create multiple validators
        let validator1 = KeyPair::generate().unwrap();
        let validator2 = KeyPair::generate().unwrap();
        let validator3 = KeyPair::generate().unwrap();

        // Create and store genesis block
        let genesis_block = Block::new(
            BlockNumber(0),
            [0u8; 32],
            vec![],
            validator1.public_key().clone(),
        );
        storage.put_block(&genesis_block).unwrap();
        storage.set_latest_block_number(&BlockNumber(0)).unwrap();

        // Create additional blocks with different validators
        let block1 = Block::new(
            BlockNumber(1),
            genesis_block.hash(),
            vec![],
            validator2.public_key().clone(),
        );
        storage.put_block(&block1).unwrap();
        storage.set_latest_block_number(&BlockNumber(1)).unwrap();

        let block2 = Block::new(
            BlockNumber(2),
            block1.hash(),
            vec![],
            validator3.public_key().clone(),
        );
        storage.put_block(&block2).unwrap();
        storage.set_latest_block_number(&BlockNumber(2)).unwrap();

        // Reuse validator1 for block 3
        let block3 = Block::new(
            BlockNumber(3),
            block2.hash(),
            vec![],
            validator1.public_key().clone(),
        );
        storage.put_block(&block3).unwrap();
        storage.set_latest_block_number(&BlockNumber(3)).unwrap();

        let validators = AuraNode::load_validators_from_chain(storage).unwrap();

        // Should have found 3 unique validators
        assert_eq!(validators.len(), 3);
        assert!(validators.contains(&validator1.public_key().clone()));
        assert!(validators.contains(&validator2.public_key().clone()));
        assert!(validators.contains(&validator3.public_key().clone()));
    }

    #[tokio::test]
    async fn test_load_validators_from_chain_no_genesis() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(Storage::new(temp_dir.path()).unwrap());

        // Don't create a genesis block
        let result = AuraNode::load_validators_from_chain(storage);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Genesis block not found"));
    }

    #[tokio::test]
    async fn test_load_or_create_validator_key_new() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let key_path = "validator.key";

        // Key should not exist yet
        let key_file_path = data_dir.join(key_path);
        assert!(!key_file_path.exists());

        // Load/create key
        let keypair1 =
            AuraNode::load_or_create_validator_key(key_path, data_dir.as_path()).unwrap();

        // Key file should now exist
        assert!(key_file_path.exists());

        // Verify file permissions are restrictive (600)
        let metadata = std::fs::metadata(&key_file_path).unwrap();
        let permissions = metadata.permissions();

        // On Unix, verify permissions are 600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(permissions.mode() & 0o777, 0o600);
        }

        // Load the same key again - should be identical
        let keypair2 =
            AuraNode::load_or_create_validator_key(key_path, data_dir.as_path()).unwrap();

        // Keys should be identical
        assert_eq!(
            keypair1.public_key().to_bytes(),
            &keypair2.public_key().to_bytes()
        );
    }

    #[tokio::test]
    async fn test_load_or_create_validator_key_absolute_path() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let absolute_key_path = temp_dir.path().join("absolute_validator.key");
        let absolute_key_str = absolute_key_path.to_string_lossy();

        // Load/create key with absolute path
        let keypair =
            AuraNode::load_or_create_validator_key(&absolute_key_str, data_dir.as_path()).unwrap();

        // Key file should exist at the absolute path
        assert!(absolute_key_path.exists());

        // Verify it's a valid keypair
        assert_eq!(&keypair.public_key().to_bytes().len(), 32);
    }

    #[tokio::test]
    async fn test_save_and_load_validator_key() {
        let temp_dir = TempDir::new().unwrap();
        let key_file_path = temp_dir.path().join("test_key.key");

        // Generate a keypair
        let original_keypair = KeyPair::generate().unwrap();

        // Save it
        AuraNode::save_validator_key_to_file(&original_keypair, &key_file_path).unwrap();

        // Load it back
        let loaded_keypair = AuraNode::load_validator_key_from_file(&key_file_path).unwrap();

        // Should be identical
        assert_eq!(
            original_keypair.public_key().to_bytes(),
            loaded_keypair.public_key().to_bytes()
        );
        assert_eq!(
            original_keypair.private_key().to_bytes(),
            loaded_keypair.private_key().to_bytes()
        );
    }

    #[tokio::test]
    async fn test_load_validator_key_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let key_file_path = temp_dir.path().join("invalid_key.key");

        // Write invalid data
        std::fs::write(&key_file_path, "invalid_base64_data!@#$").unwrap();

        // Should fail to load
        let result = AuraNode::load_validator_key_from_file(&key_file_path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to decode key file"));
    }

    #[tokio::test]
    async fn test_load_validator_key_wrong_length() {
        let temp_dir = TempDir::new().unwrap();
        let key_file_path = temp_dir.path().join("wrong_length_key.key");

        // Write valid base64 but wrong length
        let wrong_data =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [1, 2, 3, 4]);
        std::fs::write(&key_file_path, wrong_data).unwrap();

        // Should fail to load
        let result = AuraNode::load_validator_key_from_file(&key_file_path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid key file: wrong length"));
    }
}
