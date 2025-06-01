use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeConfig {
    pub node_id: String,
    pub network: NetworkConfig,
    pub consensus: ConsensusConfig,
    pub storage: StorageConfig,
    pub api: ApiConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkConfig {
    pub listen_addresses: Vec<String>,
    pub bootstrap_nodes: Vec<String>,
    pub max_peers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsensusConfig {
    pub validator_key_path: Option<String>,
    pub block_time_secs: u64,
    pub max_transactions_per_block: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StorageConfig {
    pub db_path: String,
    pub cache_size_mb: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiConfig {
    pub listen_address: String,
    pub enable_cors: bool,
    pub max_request_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();

        // Check node_id is a valid UUID
        assert!(!config.node_id.is_empty());
        assert_eq!(config.node_id.len(), 36); // UUID v4 length

        // Check network defaults
        assert_eq!(
            config.network.listen_addresses,
            vec!["/ip4/0.0.0.0/tcp/9000".to_string()]
        );
        assert!(config.network.bootstrap_nodes.is_empty());
        assert_eq!(config.network.max_peers, 50);

        // Check consensus defaults
        assert!(config.consensus.validator_key_path.is_none());
        assert_eq!(config.consensus.block_time_secs, 5);
        assert_eq!(config.consensus.max_transactions_per_block, 1000);

        // Check storage defaults
        assert_eq!(config.storage.db_path, "./data/ledger");
        assert_eq!(config.storage.cache_size_mb, 128);

        // Check API defaults
        assert_eq!(config.api.listen_address, "127.0.0.1:8080");
        assert!(config.api.enable_cors);
        assert_eq!(config.api.max_request_size, 10 * 1024 * 1024);

        // Check security defaults
        assert!(config.security.jwt_secret.is_none());
        assert_eq!(
            config.security.credentials_path,
            Some("./config/credentials.json".to_string())
        );
        assert_eq!(config.security.token_expiry_hours, 24);
        assert_eq!(config.security.rate_limit_rpm, 60);
        assert_eq!(config.security.rate_limit_rph, 1000);
    }

    #[test]
    fn test_load_non_existent_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        // Load should create default config
        let config = NodeConfig::load_or_create(&config_path).unwrap();

        // File should be created
        assert!(config_path.exists());

        // Config should be default
        assert_eq!(config.network.max_peers, 50);
        assert_eq!(config.consensus.block_time_secs, 5);
    }

    #[test]
    fn test_load_existing_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        // Create custom config
        let custom_config = NodeConfig {
            node_id: "custom-node-123".to_string(),
            network: NetworkConfig {
                listen_addresses: vec!["/ip4/127.0.0.1/tcp/9999".to_string()],
                bootstrap_nodes: vec!["/ip4/10.0.0.1/tcp/9000".to_string()],
                max_peers: 100,
            },
            consensus: ConsensusConfig {
                validator_key_path: Some("./keys/validator.key".to_string()),
                block_time_secs: 10,
                max_transactions_per_block: 500,
            },
            storage: StorageConfig {
                db_path: "./custom/db".to_string(),
                cache_size_mb: 256,
            },
            api: ApiConfig {
                listen_address: "0.0.0.0:8080".to_string(),
                enable_cors: false,
                max_request_size: 5 * 1024 * 1024,
            },
            security: SecurityConfig {
                jwt_secret: Some("secret123".to_string()),
                credentials_path: Some("./custom/creds.json".to_string()),
                token_expiry_hours: 48,
                rate_limit_rpm: 30,
                rate_limit_rph: 500,
            },
        };

        // Save custom config
        custom_config.save(&config_path).unwrap();

        // Load and verify
        let loaded = NodeConfig::load_or_create(&config_path).unwrap();
        assert_eq!(loaded.node_id, "custom-node-123");
        assert_eq!(loaded.network.max_peers, 100);
        assert_eq!(loaded.consensus.block_time_secs, 10);
        assert_eq!(loaded.storage.cache_size_mb, 256);
        assert!(!loaded.api.enable_cors);
        assert_eq!(loaded.security.rate_limit_rpm, 30);
    }

    #[test]
    fn test_save_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("save_test.toml");

        let config = NodeConfig::default();
        config.save(&config_path).unwrap();

        assert!(config_path.exists());

        // Read back and verify
        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("node_id"));
        assert!(content.contains("[network]"));
        assert!(content.contains("[consensus]"));
        assert!(content.contains("[storage]"));
        assert!(content.contains("[api]"));
        assert!(content.contains("[security]"));
    }

    #[test]
    fn test_config_serialization() {
        let config = NodeConfig::default();

        // Serialize to TOML
        let toml_str = toml::to_string(&config).unwrap();

        // Deserialize back
        let deserialized: NodeConfig = toml::from_str(&toml_str).unwrap();

        // JWT secret should not be serialized
        assert!(!toml_str.contains("jwt_secret"));

        // Other fields should match
        assert_eq!(config.node_id, deserialized.node_id);
        assert_eq!(config.network.max_peers, deserialized.network.max_peers);
    }

    #[test]
    fn test_security_config_jwt_secret_not_serialized() {
        let config = SecurityConfig {
            jwt_secret: Some("super_secret_key".to_string()),
            credentials_path: Some("./creds.json".to_string()),
            token_expiry_hours: 24,
            rate_limit_rpm: 60,
            rate_limit_rph: 1000,
        };

        let serialized = toml::to_string(&config).unwrap();
        assert!(!serialized.contains("super_secret_key"));
        assert!(!serialized.contains("jwt_secret"));
    }

    #[test]
    fn test_create_parent_directory() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("subdir/config.toml");

        // Parent doesn't exist yet
        assert!(!config_path.parent().unwrap().exists());

        // Load should create parent directory
        NodeConfig::load_or_create(&config_path).unwrap();

        assert!(config_path.exists());
        assert!(config_path.parent().unwrap().exists());
    }

    #[test]
    fn test_custom_network_config() {
        let config = NetworkConfig {
            listen_addresses: vec![
                "/ip4/0.0.0.0/tcp/9000".to_string(),
                "/ip6/::/tcp/9000".to_string(),
            ],
            bootstrap_nodes: vec![
                "/ip4/192.168.1.100/tcp/9000".to_string(),
                "/ip4/10.0.0.5/tcp/9000".to_string(),
            ],
            max_peers: 200,
        };

        assert_eq!(config.listen_addresses.len(), 2);
        assert_eq!(config.bootstrap_nodes.len(), 2);
        assert_eq!(config.max_peers, 200);
    }

    #[test]
    fn test_consensus_config_with_validator() {
        let config = ConsensusConfig {
            validator_key_path: Some("./secrets/validator.key".to_string()),
            block_time_secs: 3,
            max_transactions_per_block: 2000,
        };

        assert!(config.validator_key_path.is_some());
        assert_eq!(config.block_time_secs, 3);
        assert_eq!(config.max_transactions_per_block, 2000);
    }

    #[test]
    fn test_api_config_cors_disabled() {
        let config = ApiConfig {
            listen_address: "0.0.0.0:8080".to_string(),
            enable_cors: false,
            max_request_size: 1024 * 1024, // 1MB
        };

        assert!(!config.enable_cors);
        assert_eq!(config.max_request_size, 1024 * 1024);
    }

    #[test]
    fn test_config_roundtrip() {
        let original = NodeConfig {
            node_id: "test-node-456".to_string(),
            network: NetworkConfig {
                listen_addresses: vec!["/dns/localhost/tcp/9000".to_string()],
                bootstrap_nodes: vec![],
                max_peers: 25,
            },
            consensus: ConsensusConfig {
                validator_key_path: None,
                block_time_secs: 15,
                max_transactions_per_block: 100,
            },
            storage: StorageConfig {
                db_path: "./test/db".to_string(),
                cache_size_mb: 64,
            },
            api: ApiConfig {
                listen_address: "127.0.0.1:3000".to_string(),
                enable_cors: true,
                max_request_size: 2 * 1024 * 1024,
            },
            security: SecurityConfig {
                jwt_secret: Some("test_secret".to_string()),
                credentials_path: None,
                token_expiry_hours: 12,
                rate_limit_rpm: 120,
                rate_limit_rph: 2000,
            },
        };

        // Serialize and deserialize
        let serialized = toml::to_string(&original).unwrap();
        let deserialized: NodeConfig = toml::from_str(&serialized).unwrap();

        // Compare (jwt_secret won't match due to skip_serializing)
        assert_eq!(original.node_id, deserialized.node_id);
        assert_eq!(original.network, deserialized.network);
        assert_eq!(original.consensus, deserialized.consensus);
        assert_eq!(original.storage, deserialized.storage);
        assert_eq!(original.api, deserialized.api);
        assert!(deserialized.security.jwt_secret.is_none()); // Should be None after deserialization
        assert_eq!(
            original.security.credentials_path,
            deserialized.security.credentials_path
        );
        assert_eq!(
            original.security.token_expiry_hours,
            deserialized.security.token_expiry_hours
        );
    }

    #[test]
    fn test_load_invalid_toml() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("invalid.toml");

        // Write invalid TOML
        std::fs::write(&config_path, "invalid = toml content [").unwrap();

        // Should fail to load
        let result = NodeConfig::load_or_create(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_fields_in_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("partial.toml");

        // Write partial config (missing some required fields)
        let partial_config = r#"
            node_id = "partial-node"
            
            [network]
            max_peers = 75
        "#;
        std::fs::write(&config_path, partial_config).unwrap();

        // Should fail to load due to missing fields
        let result = NodeConfig::load_or_create(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_node_id_generation() {
        // Create multiple configs and ensure unique node_ids
        let config1 = NodeConfig::default();
        let config2 = NodeConfig::default();
        let config3 = NodeConfig::default();

        assert_ne!(config1.node_id, config2.node_id);
        assert_ne!(config2.node_id, config3.node_id);
        assert_ne!(config1.node_id, config3.node_id);

        // All should be valid UUIDs
        for config in &[config1, config2, config3] {
            assert_eq!(config.node_id.len(), 36);
            assert!(config.node_id.contains('-'));
        }
    }
}
