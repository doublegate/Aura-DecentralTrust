mod api;
mod auth;
mod config;
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
