mod api;
mod audit;
mod auth;
mod cert_pinning;
mod config;
mod error_sanitizer;
mod network;
mod node;
mod rate_limit;
mod tls;
mod validation;

use clap::Parser;
use std::path::PathBuf;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[clap(name = "aura-node")]
#[clap(about = "Aura Network Node", version)]
struct Args {
    /// Path to configuration file
    #[clap(short, long, default_value = "config/config.toml")]
    config: PathBuf,

    /// Node type (validator or query)
    #[clap(short, long, default_value = "query")]
    node_type: String,

    /// Data directory
    #[clap(short, long, default_value = "./data")]
    data_dir: PathBuf,

    /// P2P listen address
    #[clap(short, long, default_value = "/ip4/0.0.0.0/tcp/9000")]
    listen: String,

    /// API server address
    #[clap(short, long, default_value = "127.0.0.1:8080")]
    api_addr: String,

    /// Bootstrap nodes
    #[clap(short, long)]
    bootstrap: Vec<String>,

    /// Enable TLS for API server
    #[clap(long)]
    enable_tls: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("aura_node=info".parse()?))
        .init();

    let args = Args::parse();

    info!("Starting Aura Node...");
    info!("Node type: {}", args.node_type);
    info!("Data directory: {:?}", args.data_dir);
    info!("P2P listen address: {}", args.listen);
    info!("API server address: {}", args.api_addr);

    // Create data directory if it doesn't exist
    std::fs::create_dir_all(&args.data_dir)?;

    // Load or create configuration
    let mut config = config::NodeConfig::load_or_create(&args.config)?;

    // Initialize authentication system
    initialize_auth(&mut config)?;
    
    // Initialize audit logging
    audit::init_audit_logger(10000); // Keep last 10k events in memory
    
    // Log system startup
    if let Some(logger) = audit::audit_logger() {
        logger.log_event(
            audit::SecurityEvent::SystemLifecycle {
                action: "startup".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            None,
        ).await;
    }

    // Create and start the node
    let node =
        node::AuraNode::new(config.clone(), args.data_dir.clone(), args.node_type == "validator").await?;

    // Start P2P network
    let network_handle = tokio::spawn(async move {
        if let Err(e) = node.run().await {
            error!("Node error: {}", e);
        }
    });

    // Start API server
    let api_addr = args.api_addr.clone();
    let enable_tls = args.enable_tls;
    let api_data_dir = args.data_dir.clone();
    let api_config = Some(config.clone());
    let api_handle = tokio::spawn(async move {
        if let Err(e) = api::start_api_server(&api_addr, enable_tls, api_data_dir, api_config).await {
            error!("API server error: {}", e);
        }
    });

    // Wait for both tasks
    tokio::select! {
        _ = network_handle => {
            info!("Network task ended");
        }
        _ = api_handle => {
            info!("API server ended");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    info!("Aura Node shutting down...");
    Ok(())
}

fn initialize_auth(config: &mut config::NodeConfig) -> anyhow::Result<()> {
    // Get JWT secret from environment or generate a secure one
    let jwt_secret = if let Ok(secret) = std::env::var("AURA_JWT_SECRET") {
        info!("Using JWT secret from environment variable");
        secret.into_bytes()
    } else if let Some(ref secret) = config.security.jwt_secret {
        info!("Using JWT secret from config file");
        secret.clone().into_bytes()
    } else {
        warn!("No JWT secret found in environment or config, generating a random one");
        warn!("Set AURA_JWT_SECRET environment variable for production!");
        
        // Generate a secure random key
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let secret: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        
        // Save to config for consistency during this run
        use base64::Engine;
        let secret_str = base64::engine::general_purpose::STANDARD.encode(&secret);
        config.security.jwt_secret = Some(secret_str.clone());
        
        secret
    };

    // Initialize auth system
    auth::initialize_auth(
        jwt_secret,
        config.security.credentials_path.as_deref(),
    )?;

    info!("Authentication system initialized");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    
    #[test]
    fn test_initialize_auth_with_env_secret() {
        // Set environment variable
        env::set_var("AURA_JWT_SECRET", "test-env-secret");
        
        let mut config = config::NodeConfig {
            node_id: "test-node".to_string(),
            network: config::NetworkConfig {
                listen_addresses: vec![],
                bootstrap_nodes: vec![],
                max_peers: 50,
            },
            consensus: config::ConsensusConfig {
                validator_key_path: None,
                block_time_secs: 5,
                max_transactions_per_block: 100,
            },
            storage: config::StorageConfig {
                db_path: "./test/db".to_string(),
                cache_size_mb: 128,
            },
            api: config::ApiConfig {
                listen_address: "127.0.0.1:8080".to_string(),
                enable_cors: true,
                max_request_size: 1048576,
            },
            security: config::SecurityConfig {
                jwt_secret: None,
                credentials_path: None,
                token_expiry_hours: 24,
                rate_limit_rpm: 60,
                rate_limit_rph: 1000,
            },
        };
        
        let result = initialize_auth(&mut config);
        assert!(result.is_ok());
        
        // Clean up
        env::remove_var("AURA_JWT_SECRET");
    }
    
    #[test]
    fn test_initialize_auth_with_config_secret() {
        // Make sure env var is not set
        env::remove_var("AURA_JWT_SECRET");
        
        let mut config = config::NodeConfig {
            node_id: "test-node".to_string(),
            network: config::NetworkConfig {
                listen_addresses: vec![],
                bootstrap_nodes: vec![],
                max_peers: 50,
            },
            consensus: config::ConsensusConfig {
                validator_key_path: None,
                block_time_secs: 5,
                max_transactions_per_block: 100,
            },
            storage: config::StorageConfig {
                db_path: "./test/db".to_string(),
                cache_size_mb: 128,
            },
            api: config::ApiConfig {
                listen_address: "127.0.0.1:8080".to_string(),
                enable_cors: true,
                max_request_size: 1048576,
            },
            security: config::SecurityConfig {
                jwt_secret: Some("config-secret".to_string()),
                credentials_path: None,
                token_expiry_hours: 24,
                rate_limit_rpm: 60,
                rate_limit_rph: 1000,
            },
        };
        
        let result = initialize_auth(&mut config);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_initialize_auth_generates_secret() {
        // Make sure env var is not set
        env::remove_var("AURA_JWT_SECRET");
        
        let mut config = config::NodeConfig {
            node_id: "test-node".to_string(),
            network: config::NetworkConfig {
                listen_addresses: vec![],
                bootstrap_nodes: vec![],
                max_peers: 50,
            },
            consensus: config::ConsensusConfig {
                validator_key_path: None,
                block_time_secs: 5,
                max_transactions_per_block: 100,
            },
            storage: config::StorageConfig {
                db_path: "./test/db".to_string(),
                cache_size_mb: 128,
            },
            api: config::ApiConfig {
                listen_address: "127.0.0.1:8080".to_string(),
                enable_cors: true,
                max_request_size: 1048576,
            },
            security: config::SecurityConfig {
                jwt_secret: None,
                credentials_path: None,
                token_expiry_hours: 24,
                rate_limit_rpm: 60,
                rate_limit_rph: 1000,
            },
        };
        
        let result = initialize_auth(&mut config);
        assert!(result.is_ok());
        
        // Verify a secret was generated and saved to config
        assert!(config.security.jwt_secret.is_some());
        let generated_secret = config.security.jwt_secret.as_ref().unwrap();
        
        // Verify it's a base64 encoded string
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD.decode(generated_secret);
        assert!(decoded.is_ok());
        
        // Verify it's 32 bytes (256 bits)
        assert_eq!(decoded.unwrap().len(), 32);
    }
    
    #[test]
    fn test_initialize_auth_priority_env_over_config() {
        // Set both env var and config
        env::set_var("AURA_JWT_SECRET", "env-secret");
        
        let mut config = config::NodeConfig {
            node_id: "test-node".to_string(),
            network: config::NetworkConfig {
                listen_addresses: vec![],
                bootstrap_nodes: vec![],
                max_peers: 50,
            },
            consensus: config::ConsensusConfig {
                validator_key_path: None,
                block_time_secs: 5,
                max_transactions_per_block: 100,
            },
            storage: config::StorageConfig {
                db_path: "./test/db".to_string(),
                cache_size_mb: 128,
            },
            api: config::ApiConfig {
                listen_address: "127.0.0.1:8080".to_string(),
                enable_cors: true,
                max_request_size: 1048576,
            },
            security: config::SecurityConfig {
                jwt_secret: Some("config-secret".to_string()),
                credentials_path: Some("./creds.json".to_string()),
                token_expiry_hours: 24,
                rate_limit_rpm: 60,
                rate_limit_rph: 1000,
            },
        };
        
        let result = initialize_auth(&mut config);
        assert!(result.is_ok());
        
        // Config should remain unchanged (env var takes precedence)
        assert_eq!(config.security.jwt_secret, Some("config-secret".to_string()));
        
        // Clean up
        env::remove_var("AURA_JWT_SECRET");
    }
}
