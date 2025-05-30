use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use tracing::{info, warn, error};
use aura_common::{AuraError, Result, BlockNumber};
use aura_crypto::KeyPair;
use aura_ledger::{
    Block, Transaction, TransactionType, ProofOfAuthority,
    storage::Storage,
    did_registry::DidRegistry,
    vc_schema_registry::VcSchemaRegistry,
    revocation_registry::RevocationRegistry,
};
use crate::config::NodeConfig;
use crate::network::NetworkManager;

pub struct AuraNode {
    config: NodeConfig,
    is_validator: bool,
    storage: Arc<Storage>,
    consensus: Arc<RwLock<ProofOfAuthority>>,
    did_registry: Arc<RwLock<DidRegistry>>,
    schema_registry: Arc<RwLock<VcSchemaRegistry>>,
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
            let _latest_block = storage.get_block(&latest_block_num)?
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
                Some(KeyPair::generate().map_err(|e| anyhow::anyhow!("Failed to generate key: {}", e))?)
            } else {
                warn!("Validator node without key path configured, generating ephemeral key");
                Some(KeyPair::generate().map_err(|e| anyhow::anyhow!("Failed to generate key: {}", e))?)
            }
        } else {
            None
        };
        
        // Initialize network
        let network = Arc::new(Mutex::new(NetworkManager::new(config.network.clone()).await?));
        
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
                let expected_validator = match consensus_guard.get_block_validator(&next_block_num) {
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
                        if let Err(e) = Self::produce_block_static(
                            storage.clone(),
                            transaction_pool.clone(),
                            did_registry.clone(),
                            network.clone(),
                            consensus.clone(),
                            validator_key_ref.clone(),
                            next_block_num,
                            max_tx_per_block
                        ).await {
                            error!("Failed to produce block: {}", e);
                        }
                    }
                }
            }
        });
        
        Ok(handle)
    }
    
    async fn produce_block_static(
        storage: Arc<Storage>,
        transaction_pool: Arc<RwLock<Vec<Transaction>>>,
        _did_registry: Arc<RwLock<DidRegistry>>,
        network: Arc<Mutex<NetworkManager>>,
        consensus: Arc<RwLock<ProofOfAuthority>>,
        validator_key: KeyPair,
        block_number: BlockNumber,
        max_transactions: usize,
    ) -> anyhow::Result<()> {
        info!("Producing block {}", block_number.0);
        
        // Get transactions from the pool
        let mut tx_pool = transaction_pool.write().await;
        let drain_count = max_transactions.min(tx_pool.len());
        let transactions: Vec<Transaction> = tx_pool.drain(..drain_count).collect();
        drop(tx_pool);
        
        // Get previous block hash
        let previous_hash = if block_number.0 > 1 {
            let prev_block = storage.get_block(&BlockNumber(block_number.0 - 1))?
                .ok_or_else(|| anyhow::anyhow!("Previous block not found"))?;
            prev_block.hash()
        } else {
            [0u8; 32] // Genesis block has zero hash as previous
        };
        
        // Create new block
        let mut block = Block::new(
            block_number,
            previous_hash,
            transactions,
            validator_key.public_key().clone(),
        );
        
        // Sign the block
        let consensus_guard = consensus.write().await;
        consensus_guard.sign_block(&mut block, validator_key.private_key())
            .map_err(|e| anyhow::anyhow!("Failed to sign block: {}", e))?;
        drop(consensus_guard);
        
        // Process transactions
        for _tx in &block.transactions {
            // TODO: Implement transaction processing in static context
            // For now, skip processing to allow compilation
        }
        
        // Store the block
        storage.put_block(&block)?;
        storage.set_latest_block_number(&block_number)?;
        
        info!("Block {} produced with {} transactions", block_number.0, block.transactions.len());
        
        // Broadcast block to network
        let block_data = serde_json::to_vec(&block)
            .map_err(|e| anyhow::anyhow!("Failed to serialize block: {}", e))?;
        let mut network_guard = network.lock().await;
        network_guard.broadcast_block(block_data).await?;
        
        Ok(())
    }
    
    async fn process_transaction(&self, tx: &Transaction, block_number: BlockNumber) -> anyhow::Result<()> {
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
            TransactionType::UpdateRevocationList { list_id, revoked_indices } => {
                let mut registry = self.revocation_registry.write().await;
                // For revocation updates, we need to determine the issuer from the transaction sender
                // In a real implementation, this would be more sophisticated
                let issuer_did = aura_common::AuraDid::new("temp"); // Placeholder
                registry.update_revocation_list(list_id, &issuer_did, revoked_indices.clone(), block_number)?;
            }
        }
        
        Ok(())
    }
    
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