use anyhow::{Context, Result};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCredentials {
    pub node_id: String,
    pub password: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupConfig {
    pub credentials: Vec<NodeCredentials>,
}

/// Generate a secure random password
pub fn generate_secure_password(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Setup initial credentials on first run
pub fn setup_initial_credentials(config_path: &Path) -> Result<SetupConfig> {
    let setup_file = config_path.join("credentials.toml");

    // Check if credentials already exist
    if setup_file.exists() {
        let content = fs::read_to_string(&setup_file).context("Failed to read credentials file")?;
        let config: SetupConfig =
            toml::from_str(&content).context("Failed to parse credentials file")?;
        return Ok(config);
    }

    // Generate new credentials
    let mut credentials = Vec::new();

    // Create validator node credentials
    for i in 1..=3 {
        credentials.push(NodeCredentials {
            node_id: format!("validator-node-{}", i),
            password: generate_secure_password(32),
            role: "validator".to_string(),
        });
    }

    // Create query node credentials
    for i in 1..=2 {
        credentials.push(NodeCredentials {
            node_id: format!("query-node-{}", i),
            password: generate_secure_password(32),
            role: "query".to_string(),
        });
    }

    // Create admin credentials
    credentials.push(NodeCredentials {
        node_id: "admin".to_string(),
        password: generate_secure_password(32),
        role: "admin".to_string(),
    });

    let config = SetupConfig { credentials };

    // Save credentials to file
    let toml_content =
        toml::to_string_pretty(&config).context("Failed to serialize credentials")?;

    // Ensure directory exists
    if let Some(parent) = setup_file.parent() {
        fs::create_dir_all(parent).context("Failed to create config directory")?;
    }

    fs::write(&setup_file, toml_content).context("Failed to write credentials file")?;

    // Set file permissions to 600 (owner read/write only) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(&setup_file, permissions).context("Failed to set file permissions")?;
    }

    println!("Generated initial credentials at: {}", setup_file.display());
    println!("Please save these credentials securely:");
    for cred in &config.credentials {
        println!("  {} ({}): {}", cred.node_id, cred.role, cred.password);
    }

    Ok(config)
}

/// Validate password strength
#[allow(dead_code)]
pub fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < 16 {
        return Err("Password must be at least 16 characters long".to_string());
    }

    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let _has_special = password.chars().any(|c| !c.is_alphanumeric());

    if !has_uppercase || !has_lowercase || !has_digit {
        return Err("Password must contain uppercase, lowercase, and digits".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_secure_password() {
        let password = generate_secure_password(32);
        assert_eq!(password.len(), 32);
        assert!(password.chars().all(|c| c.is_alphanumeric()));

        // Test that passwords are unique
        let password2 = generate_secure_password(32);
        assert_ne!(password, password2);
    }

    #[test]
    fn test_password_strength_validation() {
        // Too short
        assert!(validate_password_strength("short").is_err());

        // Missing uppercase
        assert!(validate_password_strength("lowercase123only").is_err());

        // Missing lowercase
        assert!(validate_password_strength("UPPERCASE123ONLY").is_err());

        // Missing digits
        assert!(validate_password_strength("NoDigitsHereAtAll").is_err());

        // Valid password
        assert!(validate_password_strength("ValidPassword123!").is_ok());
    }

    #[test]
    fn test_setup_initial_credentials() {
        let temp_dir = TempDir::new().unwrap();
        let config = setup_initial_credentials(temp_dir.path()).unwrap();

        // Check credentials were generated
        assert_eq!(config.credentials.len(), 6); // 3 validators + 2 query + 1 admin

        // Check validators
        let validators: Vec<_> = config
            .credentials
            .iter()
            .filter(|c| c.role == "validator")
            .collect();
        assert_eq!(validators.len(), 3);

        // Check query nodes
        let query_nodes: Vec<_> = config
            .credentials
            .iter()
            .filter(|c| c.role == "query")
            .collect();
        assert_eq!(query_nodes.len(), 2);

        // Check admin
        let admin = config
            .credentials
            .iter()
            .find(|c| c.node_id == "admin")
            .unwrap();
        assert_eq!(admin.role, "admin");

        // Check all passwords are 32 chars
        for cred in &config.credentials {
            assert_eq!(cred.password.len(), 32);
        }

        // Check file was created
        let setup_file = temp_dir.path().join("credentials.toml");
        assert!(setup_file.exists());

        // Test loading existing credentials
        let config2 = setup_initial_credentials(temp_dir.path()).unwrap();
        assert_eq!(config.credentials.len(), config2.credentials.len());

        // Verify passwords match
        for (c1, c2) in config.credentials.iter().zip(config2.credentials.iter()) {
            assert_eq!(c1.node_id, c2.node_id);
            assert_eq!(c1.password, c2.password);
            assert_eq!(c1.role, c2.role);
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_credentials_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        setup_initial_credentials(temp_dir.path()).unwrap();

        let setup_file = temp_dir.path().join("credentials.toml");
        let metadata = fs::metadata(&setup_file).unwrap();
        let permissions = metadata.permissions();

        // Check that file has 600 permissions (owner read/write only)
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }
}
