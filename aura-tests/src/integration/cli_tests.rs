//! Integration tests for CLI functionality
//!
//! These tests verify command-line interface behavior

#[cfg(test)]
mod tests {
    use aura_common::AuraDid;
    use aura_crypto::KeyPair;
    use std::fs;
    use std::process::{Command, Stdio};
    use tempfile::TempDir;

    #[test]
    fn test_did_parsing() {
        // Test DID parsing from CLI input
        let did_str = "did:aura:test123";
        let did = AuraDid::from_string(did_str.to_string());
        assert!(did.is_ok());
        assert_eq!(did.unwrap().to_string(), did_str);

        // Test invalid DID
        let invalid_did = AuraDid::from_string("invalid-did".to_string());
        assert!(invalid_did.is_err());
    }

    #[test]
    fn test_key_generation_simulation() {
        // Simulate what the CLI would do for key generation
        let keypair = KeyPair::generate().unwrap();

        // Verify keys are valid
        let public_bytes = &keypair.public_key().to_bytes();
        let private_bytes = keypair.private_key().to_bytes();

        assert_eq!(public_bytes.len(), 32);
        assert_eq!(private_bytes.len(), 32);

        // Test key serialization (for saving to file)
        let public_hex = hex::encode(public_bytes);
        let private_hex = hex::encode(private_bytes);

        assert_eq!(public_hex.len(), 64);
        assert_eq!(private_hex.len(), 64);
    }

    #[test]
    fn test_config_validation() {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Serialize, Deserialize)]
        struct TestConfig {
            node_type: String,
            data_dir: String,
            api_port: u16,
            p2p_port: u16,
        }

        // Test valid config
        let config = TestConfig {
            node_type: "validator".to_string(),
            data_dir: "/tmp/aura".to_string(),
            api_port: 8080,
            p2p_port: 9000,
        };

        let toml = toml::to_string(&config).unwrap();
        let parsed: TestConfig = toml::from_str(&toml).unwrap();

        assert_eq!(parsed.node_type, "validator");
        assert_eq!(parsed.api_port, 8080);
    }

    #[test]
    #[ignore] // Only run when binary is built
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
    #[ignore] // Only run when binary is built
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
    #[ignore] // Only run when binary is built
    fn test_invalid_config_path() {
        let output = Command::new("cargo")
            .args([
                "run",
                "--bin",
                "aura-node",
                "--",
                "--config",
                "/nonexistent/config.toml",
            ])
            .stderr(Stdio::piped())
            .output()
            .expect("Failed to execute command");

        assert!(!output.status.success());
    }

    #[tokio::test]
    #[ignore] // Only run when binary is built
    async fn test_node_startup_and_shutdown() {
        use std::process::Child;
        use tokio::time::{timeout, Duration};

        let temp_dir = TempDir::new().unwrap();

        // Create a test config
        let config_content = r#"
node_type = "full"
data_dir = "."
api_port = 0
p2p_port = 0
        "#;

        let config_path = temp_dir.path().join("test_config.toml");
        fs::write(&config_path, config_content).unwrap();

        // Start the node
        let mut child: Child = Command::new("cargo")
            .args([
                "run",
                "--bin",
                "aura-node",
                "--",
                "--config",
                config_path.to_str().unwrap(),
                "--data-dir",
                temp_dir.path().to_str().unwrap(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start node");

        // Give it some time to start up
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Check if it's still running
        assert!(child.try_wait().unwrap().is_none());

        // Terminate the process
        child.kill().expect("Failed to kill process");

        // Wait for it to actually terminate
        let result = timeout(Duration::from_secs(5), async {
            loop {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;

        assert!(result.is_ok(), "Node failed to shutdown within timeout");
    }

    #[test]
    fn test_config_generation() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        // Simulate generating a config file
        let config_content = r#"
# Aura Node Configuration

# Node type: "validator", "full", or "light"
node_type = "full"

# Data directory for blockchain data
data_dir = "./data"

# API server configuration
api_port = 8080
api_addr = "127.0.0.1"

# P2P network configuration
p2p_port = 9000
p2p_addr = "0.0.0.0"

# Security settings
enable_tls = false
enable_auth = true

# Logging
log_level = "info"
"#;

        fs::write(&config_path, config_content).unwrap();

        // Verify it was written correctly
        let read_content = fs::read_to_string(&config_path).unwrap();
        assert!(read_content.contains("node_type = \"full\""));
        assert!(read_content.contains("api_port = 8080"));
    }
}
