use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;

#[test]
fn test_help_flag() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "aura-node", "--", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Aura Network Node"));
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--node-type"));
    assert!(stdout.contains("--data-dir"));
    assert!(stdout.contains("--listen"));
    assert!(stdout.contains("--api-addr"));
}

#[test]
fn test_version_flag() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "aura-node", "--", "--version"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("aura-node"));
}

#[test]
fn test_invalid_config_path() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "aura-node", "--", "--config", "/nonexistent/config.toml"])
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());
}

#[tokio::test]
async fn test_node_startup_and_shutdown() {
    let temp_dir = TempDir::new().unwrap();
    let data_dir = temp_dir.path().to_path_buf();
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir).unwrap();
    
    // Create a minimal config file
    let config_content = r#"
node_id = "test-node-1"

[network]
listen_addresses = ["/ip4/127.0.0.1/tcp/19001"]
bootstrap_peers = []
enable_mdns = false

[consensus]
consensus_type = "proof-of-authority"
validator_key_path = ""
block_time_secs = 5
max_transactions_per_block = 100
min_transaction_fee = 0

[api]
listen_address = "127.0.0.1:18081"
enable_tls = false
enable_auth = true
cors_origins = ["*"]
max_request_size = 1048576
rate_limit_per_minute = 60

[security]
enable_input_validation = true
max_payload_size = 1048576
enable_audit_logging = true
jwt_secret = "test-secret-key"
credentials_path = ""
tls_cert_path = ""
tls_key_path = ""
enable_key_pinning = false
pinned_public_keys = []
"#;
    
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config_content).unwrap();
    
    // Start the node in a separate thread
    let config_path_clone = config_path.clone();
    let data_dir_clone = data_dir.clone();
    let mut child = Command::new("cargo")
        .args([
            "run", "--bin", "aura-node", "--",
            "--config", config_path_clone.to_str().unwrap(),
            "--data-dir", data_dir_clone.to_str().unwrap(),
            "--node-type", "query",
            "--api-addr", "127.0.0.1:18081",
            "--listen", "/ip4/127.0.0.1/tcp/19001"
        ])
        .spawn()
        .expect("Failed to start node");
    
    // Give the node time to start
    thread::sleep(Duration::from_secs(3));
    
    // Check if the node is still running
    assert!(child.try_wait().unwrap().is_none(), "Node should still be running");
    
    // Test API endpoint is accessible
    let client = reqwest::Client::new();
    let health_check = timeout(Duration::from_secs(5), async {
        // Try to get auth token
        client.post("http://127.0.0.1:18081/auth/login")
            .json(&serde_json::json!({
                "node_id": "test-node",
                "password": "test-password"
            }))
            .send()
            .await
    }).await;
    
    // We expect the request to complete (even if it returns an auth error)
    assert!(health_check.is_ok(), "API should be reachable");
    
    // Gracefully terminate the node
    child.kill().expect("Failed to kill node");
    let _ = child.wait();
}

#[tokio::test]
async fn test_validator_node_startup() {
    let temp_dir = TempDir::new().unwrap();
    let data_dir = temp_dir.path().to_path_buf();
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir).unwrap();
    
    // Create a validator config
    let config_content = r#"
node_id = "validator-node-1"

[network]
listen_addresses = ["/ip4/127.0.0.1/tcp/19002"]
bootstrap_peers = []
enable_mdns = false

[consensus]
consensus_type = "proof-of-authority"
validator_key_path = "./validator.key"
block_time_secs = 5
max_transactions_per_block = 100
min_transaction_fee = 0

[api]
listen_address = "127.0.0.1:18082"
enable_tls = false
enable_auth = true
cors_origins = ["*"]
max_request_size = 1048576
rate_limit_per_minute = 60

[security]
enable_input_validation = true
max_payload_size = 1048576
enable_audit_logging = true
jwt_secret = "validator-secret-key"
credentials_path = ""
tls_cert_path = ""
tls_key_path = ""
enable_key_pinning = false
pinned_public_keys = []
"#;
    
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config_content).unwrap();
    
    // Start validator node
    let config_path_clone = config_path.clone();
    let data_dir_clone = data_dir.clone();
    let mut child = Command::new("cargo")
        .args([
            "run", "--bin", "aura-node", "--",
            "--config", config_path_clone.to_str().unwrap(),
            "--data-dir", data_dir_clone.to_str().unwrap(),
            "--node-type", "validator",
            "--api-addr", "127.0.0.1:18082",
            "--listen", "/ip4/127.0.0.1/tcp/19002"
        ])
        .spawn()
        .expect("Failed to start validator node");
    
    // Give the node time to start
    thread::sleep(Duration::from_secs(3));
    
    // Check if the node is still running
    assert!(child.try_wait().unwrap().is_none(), "Validator node should still be running");
    
    // Clean up
    child.kill().expect("Failed to kill validator node");
    let _ = child.wait();
}

#[tokio::test]
async fn test_tls_enabled_startup() {
    let temp_dir = TempDir::new().unwrap();
    let data_dir = temp_dir.path().to_path_buf();
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir).unwrap();
    
    // Create config with TLS settings
    let config_content = r#"
node_id = "tls-test-node"

[network]
listen_addresses = ["/ip4/127.0.0.1/tcp/19003"]
bootstrap_peers = []
enable_mdns = false

[consensus]
consensus_type = "proof-of-authority"
validator_key_path = ""
block_time_secs = 5
max_transactions_per_block = 100
min_transaction_fee = 0

[api]
listen_address = "127.0.0.1:18083"
enable_tls = true
enable_auth = true
cors_origins = ["*"]
max_request_size = 1048576
rate_limit_per_minute = 60

[security]
enable_input_validation = true
max_payload_size = 1048576
enable_audit_logging = true
jwt_secret = "tls-test-secret"
credentials_path = ""
tls_cert_path = ""
tls_key_path = ""
enable_key_pinning = false
pinned_public_keys = []
"#;
    
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config_content).unwrap();
    
    // Start node with TLS enabled
    let config_path_clone = config_path.clone();
    let data_dir_clone = data_dir.clone();
    let mut child = Command::new("cargo")
        .args([
            "run", "--bin", "aura-node", "--",
            "--config", config_path_clone.to_str().unwrap(),
            "--data-dir", data_dir_clone.to_str().unwrap(),
            "--enable-tls",
            "--api-addr", "127.0.0.1:18083",
            "--listen", "/ip4/127.0.0.1/tcp/19003"
        ])
        .spawn()
        .expect("Failed to start node with TLS");
    
    // Give the node time to start and generate certificates
    thread::sleep(Duration::from_secs(5));
    
    // Check if the node is still running
    assert!(child.try_wait().unwrap().is_none(), "TLS node should still be running");
    
    // Verify TLS files were created
    let cert_path = data_dir.join("tls").join("cert.pem");
    let key_path = data_dir.join("tls").join("key.pem");
    assert!(cert_path.exists(), "TLS certificate should be created");
    assert!(key_path.exists(), "TLS key should be created");
    
    // Clean up
    child.kill().expect("Failed to kill TLS node");
    let _ = child.wait();
}

#[test]
fn test_jwt_secret_from_env() {
    let temp_dir = TempDir::new().unwrap();
    let data_dir = temp_dir.path().to_path_buf();
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir).unwrap();
    
    // Create config without JWT secret
    let config_content = r#"
node_id = "env-test-node"

[network]
listen_addresses = ["/ip4/127.0.0.1/tcp/19004"]
bootstrap_peers = []
enable_mdns = false

[consensus]
consensus_type = "proof-of-authority"
validator_key_path = ""
block_time_secs = 5
max_transactions_per_block = 100
min_transaction_fee = 0

[api]
listen_address = "127.0.0.1:18084"
enable_tls = false
enable_auth = true
cors_origins = ["*"]
max_request_size = 1048576
rate_limit_per_minute = 60

[security]
enable_input_validation = true
max_payload_size = 1048576
enable_audit_logging = true
credentials_path = ""
tls_cert_path = ""
tls_key_path = ""
enable_key_pinning = false
pinned_public_keys = []
"#;
    
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config_content).unwrap();
    
    // Start node with JWT secret in environment
    let config_path_clone = config_path.clone();
    let data_dir_clone = data_dir.clone();
    let mut child = Command::new("cargo")
        .env("AURA_JWT_SECRET", "secret-from-env")
        .args([
            "run", "--bin", "aura-node", "--",
            "--config", config_path_clone.to_str().unwrap(),
            "--data-dir", data_dir_clone.to_str().unwrap(),
            "--api-addr", "127.0.0.1:18084",
            "--listen", "/ip4/127.0.0.1/tcp/19004"
        ])
        .spawn()
        .expect("Failed to start node with env JWT secret");
    
    // Give the node time to start
    thread::sleep(Duration::from_secs(3));
    
    // Check if the node is still running
    assert!(child.try_wait().unwrap().is_none(), "Node with env JWT should still be running");
    
    // Clean up
    child.kill().expect("Failed to kill node");
    let _ = child.wait();
}

#[test]
fn test_bootstrap_peers_argument() {
    let temp_dir = TempDir::new().unwrap();
    let data_dir = temp_dir.path().to_path_buf();
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir).unwrap();
    
    // Create minimal config
    let config_content = r#"
node_id = "bootstrap-test-node"

[network]
listen_addresses = ["/ip4/127.0.0.1/tcp/19005"]
bootstrap_peers = []
enable_mdns = false

[consensus]
consensus_type = "proof-of-authority"
validator_key_path = ""
block_time_secs = 5
max_transactions_per_block = 100
min_transaction_fee = 0

[api]
listen_address = "127.0.0.1:18085"
enable_tls = false
enable_auth = true
cors_origins = ["*"]
max_request_size = 1048576
rate_limit_per_minute = 60

[security]
enable_input_validation = true
max_payload_size = 1048576
enable_audit_logging = true
jwt_secret = "test-secret"
credentials_path = ""
tls_cert_path = ""
tls_key_path = ""
enable_key_pinning = false
pinned_public_keys = []
"#;
    
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config_content).unwrap();
    
    // Start node with bootstrap peers
    let config_path_clone = config_path.clone();
    let data_dir_clone = data_dir.clone();
    let mut child = Command::new("cargo")
        .args([
            "run", "--bin", "aura-node", "--",
            "--config", config_path_clone.to_str().unwrap(),
            "--data-dir", data_dir_clone.to_str().unwrap(),
            "--bootstrap", "/ip4/127.0.0.1/tcp/9000/p2p/12D3KooWExample1",
            "--bootstrap", "/ip4/127.0.0.1/tcp/9001/p2p/12D3KooWExample2",
            "--api-addr", "127.0.0.1:18085",
            "--listen", "/ip4/127.0.0.1/tcp/19005"
        ])
        .spawn()
        .expect("Failed to start node with bootstrap peers");
    
    // Give the node time to start
    thread::sleep(Duration::from_secs(3));
    
    // Check if the node is still running
    assert!(child.try_wait().unwrap().is_none(), "Node with bootstrap peers should still be running");
    
    // Clean up
    child.kill().expect("Failed to kill node");
    let _ = child.wait();
}

#[test]
fn test_data_dir_creation() {
    let temp_dir = TempDir::new().unwrap();
    let data_dir = temp_dir.path().join("new_data_dir");
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir).unwrap();
    
    // Ensure data dir doesn't exist yet
    assert!(!data_dir.exists());
    
    // Create minimal config
    let config_content = r#"
node_id = "data-dir-test"

[network]
listen_addresses = ["/ip4/127.0.0.1/tcp/19006"]
bootstrap_peers = []
enable_mdns = false

[consensus]
consensus_type = "proof-of-authority"
validator_key_path = ""
block_time_secs = 5
max_transactions_per_block = 100
min_transaction_fee = 0

[api]
listen_address = "127.0.0.1:18086"
enable_tls = false
enable_auth = true
cors_origins = ["*"]
max_request_size = 1048576
rate_limit_per_minute = 60

[security]
enable_input_validation = true
max_payload_size = 1048576
enable_audit_logging = true
jwt_secret = "test-secret"
credentials_path = ""
tls_cert_path = ""
tls_key_path = ""
enable_key_pinning = false
pinned_public_keys = []
"#;
    
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config_content).unwrap();
    
    // Start node with non-existent data dir
    let config_path_clone = config_path.clone();
    let data_dir_clone = data_dir.clone();
    let mut child = Command::new("cargo")
        .args([
            "run", "--bin", "aura-node", "--",
            "--config", config_path_clone.to_str().unwrap(),
            "--data-dir", data_dir_clone.to_str().unwrap(),
            "--api-addr", "127.0.0.1:18086",
            "--listen", "/ip4/127.0.0.1/tcp/19006"
        ])
        .spawn()
        .expect("Failed to start node");
    
    // Give the node time to start
    thread::sleep(Duration::from_secs(3));
    
    // Check if data dir was created
    assert!(data_dir.exists(), "Data directory should be created");
    
    // Clean up
    child.kill().expect("Failed to kill node");
    let _ = child.wait();
}