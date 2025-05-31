use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: String,
    pub network: NetworkConfig,
    pub consensus: ConsensusConfig,
    pub storage: StorageConfig,
    pub api: ApiConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen_addresses: Vec<String>,
    pub bootstrap_nodes: Vec<String>,
    pub max_peers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub validator_key_path: Option<String>,
    pub block_time_secs: u64,
    pub max_transactions_per_block: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub db_path: String,
    pub cache_size_mb: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub listen_address: String,
    pub enable_cors: bool,
    pub max_request_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// JWT secret key - should be loaded from environment in production
    #[serde(skip_serializing)]
    pub jwt_secret: Option<String>,
    /// Path to credentials file (JSON format)
    pub credentials_path: Option<String>,
    /// Token expiration time in hours
    pub token_expiry_hours: u64,
    /// Rate limiting - requests per minute
    pub rate_limit_rpm: u32,
    /// Rate limiting - requests per hour
    pub rate_limit_rph: u32,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_id: uuid::Uuid::new_v4().to_string(),
            network: NetworkConfig {
                listen_addresses: vec!["/ip4/0.0.0.0/tcp/9000".to_string()],
                bootstrap_nodes: vec![],
                max_peers: 50,
            },
            consensus: ConsensusConfig {
                validator_key_path: None,
                block_time_secs: 5,
                max_transactions_per_block: 1000,
            },
            storage: StorageConfig {
                db_path: "./data/ledger".to_string(),
                cache_size_mb: 128,
            },
            api: ApiConfig {
                listen_address: "127.0.0.1:8080".to_string(),
                enable_cors: true,
                max_request_size: 10 * 1024 * 1024, // 10MB
            },
            security: SecurityConfig {
                jwt_secret: None, // Must be set via environment variable
                credentials_path: Some("./config/credentials.json".to_string()),
                token_expiry_hours: 24,
                rate_limit_rpm: 60,
                rate_limit_rph: 1000,
            },
        }
    }
}

impl NodeConfig {
    pub fn load_or_create<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref();

        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let config: Self = toml::from_str(&content)?;
            Ok(config)
        } else {
            let config = Self::default();
            let content = toml::to_string_pretty(&config)?;

            // Create parent directory if it doesn't exist
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            std::fs::write(path, content)?;
            Ok(config)
        }
    }

    #[allow(dead_code)]
    pub fn save<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
