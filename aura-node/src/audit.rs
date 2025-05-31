use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

/// Security event types for audit logging
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum SecurityEvent {
    /// Authentication attempt
    AuthenticationAttempt {
        node_id: String,
        success: bool,
        ip_address: String,
        reason: Option<String>,
    },
    /// Authorization check
    AuthorizationCheck {
        user: String,
        resource: String,
        action: String,
        allowed: bool,
    },
    /// Transaction submission
    TransactionSubmitted {
        signer_did: String,
        transaction_type: String,
        transaction_id: String,
        signature_valid: bool,
    },
    /// Rate limit triggered
    RateLimitExceeded {
        ip_address: String,
        endpoint: String,
        requests_count: u32,
    },
    /// TLS connection
    TlsConnection {
        remote_addr: String,
        client_cert_present: bool,
        cipher_suite: Option<String>,
    },
    /// Configuration change
    ConfigurationChange {
        setting: String,
        old_value: Option<String>,
        new_value: String,
        changed_by: String,
    },
    /// Data access
    DataAccess {
        user: String,
        resource_type: String,
        resource_id: String,
        action: String,
    },
    /// System startup/shutdown
    SystemLifecycle {
        action: String, // "startup" or "shutdown"
        version: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Unique ID for this log entry
    pub id: String,
    /// When the event occurred
    pub timestamp: DateTime<Utc>,
    /// The security event
    pub event: SecurityEvent,
    /// Additional context
    pub context: Option<serde_json::Value>,
}

/// Audit logger for security events
#[derive(Clone)]
pub struct AuditLogger {
    /// In-memory buffer of recent events (in production, would write to persistent storage)
    buffer: Arc<Mutex<Vec<AuditLogEntry>>>,
    /// Maximum number of entries to keep in memory
    max_buffer_size: usize,
}

impl AuditLogger {
    pub fn new(max_buffer_size: usize) -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Vec::with_capacity(max_buffer_size))),
            max_buffer_size,
        }
    }

    /// Log a security event
    pub async fn log_event(&self, event: SecurityEvent, context: Option<serde_json::Value>) {
        let entry = AuditLogEntry {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event: event.clone(),
            context,
        };

        // Log to tracing
        match &event {
            SecurityEvent::AuthenticationAttempt { success: false, .. } => {
                tracing::warn!("Security audit: {:?}", entry);
            }
            SecurityEvent::RateLimitExceeded { .. } => {
                tracing::warn!("Security audit: {:?}", entry);
            }
            _ => {
                info!("Security audit: {:?}", entry);
            }
        }

        // Store in buffer
        let mut buffer = self.buffer.lock().await;
        buffer.push(entry);
        
        // Trim buffer if too large
        if buffer.len() > self.max_buffer_size {
            let drain_count = buffer.len() - self.max_buffer_size;
            buffer.drain(0..drain_count);
        }

        // TODO: In production, also write to:
        // - Persistent database
        // - SIEM system
        // - Log aggregation service
    }

    /// Get recent audit entries (for monitoring/debugging)
    pub async fn get_recent_entries(&self, limit: usize) -> Vec<AuditLogEntry> {
        let buffer = self.buffer.lock().await;
        let start = if buffer.len() > limit {
            buffer.len() - limit
        } else {
            0
        };
        buffer[start..].to_vec()
    }

    /// Search audit entries by event type
    pub async fn search_by_event_type(&self, event_type: &str) -> Vec<AuditLogEntry> {
        let buffer = self.buffer.lock().await;
        buffer
            .iter()
            .filter(|entry| {
                let type_str = match &entry.event {
                    SecurityEvent::AuthenticationAttempt { .. } => "authentication_attempt",
                    SecurityEvent::AuthorizationCheck { .. } => "authorization_check",
                    SecurityEvent::TransactionSubmitted { .. } => "transaction_submitted",
                    SecurityEvent::RateLimitExceeded { .. } => "rate_limit_exceeded",
                    SecurityEvent::TlsConnection { .. } => "tls_connection",
                    SecurityEvent::ConfigurationChange { .. } => "configuration_change",
                    SecurityEvent::DataAccess { .. } => "data_access",
                    SecurityEvent::SystemLifecycle { .. } => "system_lifecycle",
                };
                type_str == event_type
            })
            .cloned()
            .collect()
    }

    /// Export audit logs to JSON
    pub async fn export_to_json(&self) -> String {
        let buffer = self.buffer.lock().await;
        serde_json::to_string_pretty(&*buffer).unwrap_or_else(|_| "[]".to_string())
    }
}

/// Global audit logger instance
static AUDIT_LOGGER: once_cell::sync::OnceCell<AuditLogger> = once_cell::sync::OnceCell::new();

/// Initialize the global audit logger
pub fn init_audit_logger(max_buffer_size: usize) {
    let logger = AuditLogger::new(max_buffer_size);
    let _ = AUDIT_LOGGER.set(logger);
}

/// Get the global audit logger
pub fn audit_logger() -> Option<&'static AuditLogger> {
    AUDIT_LOGGER.get()
}

/// Convenience function to log an event
pub async fn log_security_event(event: SecurityEvent, context: Option<serde_json::Value>) {
    if let Some(logger) = audit_logger() {
        logger.log_event(event, context).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    
    #[tokio::test]
    async fn test_audit_logger_new() {
        let logger = AuditLogger::new(100);
        assert_eq!(logger.max_buffer_size, 100);
        
        let entries = logger.get_recent_entries(10).await;
        assert!(entries.is_empty());
    }
    
    #[tokio::test]
    async fn test_log_authentication_attempt() {
        let logger = AuditLogger::new(100);
        
        let event = SecurityEvent::AuthenticationAttempt {
            node_id: "node-123".to_string(),
            success: true,
            ip_address: "192.168.1.1".to_string(),
            reason: None,
        };
        
        logger.log_event(event.clone(), None).await;
        
        let entries = logger.get_recent_entries(10).await;
        assert_eq!(entries.len(), 1);
        
        match &entries[0].event {
            SecurityEvent::AuthenticationAttempt { node_id, success, .. } => {
                assert_eq!(node_id, "node-123");
                assert_eq!(*success, true);
            }
            _ => panic!("Wrong event type"),
        }
    }
    
    #[tokio::test]
    async fn test_log_authorization_check() {
        let logger = AuditLogger::new(100);
        
        let event = SecurityEvent::AuthorizationCheck {
            user: "did:aura:user123".to_string(),
            resource: "/api/transaction".to_string(),
            action: "POST".to_string(),
            allowed: true,
        };
        
        logger.log_event(event, Some(json!({"role": "validator"}))).await;
        
        let entries = logger.get_recent_entries(1).await;
        assert_eq!(entries.len(), 1);
        assert!(entries[0].context.is_some());
    }
    
    #[tokio::test]
    async fn test_log_transaction_submitted() {
        let logger = AuditLogger::new(100);
        
        let event = SecurityEvent::TransactionSubmitted {
            signer_did: "did:aura:signer123".to_string(),
            transaction_type: "RegisterDid".to_string(),
            transaction_id: "tx-123".to_string(),
            signature_valid: true,
        };
        
        logger.log_event(event, None).await;
        
        let entries = logger.get_recent_entries(1).await;
        match &entries[0].event {
            SecurityEvent::TransactionSubmitted { transaction_id, .. } => {
                assert_eq!(transaction_id, "tx-123");
            }
            _ => panic!("Wrong event type"),
        }
    }
    
    #[tokio::test]
    async fn test_log_rate_limit_exceeded() {
        let logger = AuditLogger::new(100);
        
        let event = SecurityEvent::RateLimitExceeded {
            ip_address: "10.0.0.1".to_string(),
            endpoint: "/api/transaction".to_string(),
            requests_count: 100,
        };
        
        logger.log_event(event, None).await;
        
        let entries = logger.get_recent_entries(1).await;
        match &entries[0].event {
            SecurityEvent::RateLimitExceeded { requests_count, .. } => {
                assert_eq!(*requests_count, 100);
            }
            _ => panic!("Wrong event type"),
        }
    }
    
    #[tokio::test]
    async fn test_log_tls_connection() {
        let logger = AuditLogger::new(100);
        
        let event = SecurityEvent::TlsConnection {
            remote_addr: "192.168.1.100:45678".to_string(),
            client_cert_present: true,
            cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
        };
        
        logger.log_event(event, None).await;
        
        let entries = logger.get_recent_entries(1).await;
        match &entries[0].event {
            SecurityEvent::TlsConnection { cipher_suite, .. } => {
                assert_eq!(cipher_suite.as_ref().unwrap(), "TLS_AES_256_GCM_SHA384");
            }
            _ => panic!("Wrong event type"),
        }
    }
    
    #[tokio::test]
    async fn test_log_configuration_change() {
        let logger = AuditLogger::new(100);
        
        let event = SecurityEvent::ConfigurationChange {
            setting: "max_peers".to_string(),
            old_value: Some("50".to_string()),
            new_value: "100".to_string(),
            changed_by: "admin".to_string(),
        };
        
        logger.log_event(event, None).await;
        
        let entries = logger.get_recent_entries(1).await;
        match &entries[0].event {
            SecurityEvent::ConfigurationChange { setting, .. } => {
                assert_eq!(setting, "max_peers");
            }
            _ => panic!("Wrong event type"),
        }
    }
    
    #[tokio::test]
    async fn test_log_data_access() {
        let logger = AuditLogger::new(100);
        
        let event = SecurityEvent::DataAccess {
            user: "did:aura:user123".to_string(),
            resource_type: "DID".to_string(),
            resource_id: "did:aura:resource456".to_string(),
            action: "READ".to_string(),
        };
        
        logger.log_event(event, None).await;
        
        let entries = logger.get_recent_entries(1).await;
        match &entries[0].event {
            SecurityEvent::DataAccess { resource_type, .. } => {
                assert_eq!(resource_type, "DID");
            }
            _ => panic!("Wrong event type"),
        }
    }
    
    #[tokio::test]
    async fn test_log_system_lifecycle() {
        let logger = AuditLogger::new(100);
        
        let event = SecurityEvent::SystemLifecycle {
            action: "startup".to_string(),
            version: "1.0.0".to_string(),
        };
        
        logger.log_event(event, None).await;
        
        let entries = logger.get_recent_entries(1).await;
        match &entries[0].event {
            SecurityEvent::SystemLifecycle { action, version } => {
                assert_eq!(action, "startup");
                assert_eq!(version, "1.0.0");
            }
            _ => panic!("Wrong event type"),
        }
    }
    
    #[tokio::test]
    async fn test_buffer_size_limit() {
        let logger = AuditLogger::new(5); // Small buffer
        
        // Log 10 events
        for i in 0..10 {
            let event = SecurityEvent::AuthenticationAttempt {
                node_id: format!("node-{}", i),
                success: true,
                ip_address: "127.0.0.1".to_string(),
                reason: None,
            };
            logger.log_event(event, None).await;
        }
        
        // Should only keep the last 5
        let entries = logger.get_recent_entries(100).await;
        assert_eq!(entries.len(), 5);
        
        // Check that we have the last 5 events (node-5 through node-9)
        match &entries[0].event {
            SecurityEvent::AuthenticationAttempt { node_id, .. } => {
                assert_eq!(node_id, "node-5");
            }
            _ => panic!("Wrong event type"),
        }
    }
    
    #[tokio::test]
    async fn test_get_recent_entries_limit() {
        let logger = AuditLogger::new(100);
        
        // Log 10 events
        for i in 0..10 {
            let event = SecurityEvent::DataAccess {
                user: format!("user-{}", i),
                resource_type: "Schema".to_string(),
                resource_id: format!("schema-{}", i),
                action: "READ".to_string(),
            };
            logger.log_event(event, None).await;
        }
        
        // Get only 3 recent entries
        let entries = logger.get_recent_entries(3).await;
        assert_eq!(entries.len(), 3);
        
        // Should get the last 3 (user-7, user-8, user-9)
        match &entries[0].event {
            SecurityEvent::DataAccess { user, .. } => {
                assert_eq!(user, "user-7");
            }
            _ => panic!("Wrong event type"),
        }
    }
    
    #[tokio::test]
    async fn test_search_by_event_type() {
        let logger = AuditLogger::new(100);
        
        // Log different types of events
        logger.log_event(SecurityEvent::AuthenticationAttempt {
            node_id: "node-1".to_string(),
            success: true,
            ip_address: "127.0.0.1".to_string(),
            reason: None,
        }, None).await;
        
        logger.log_event(SecurityEvent::RateLimitExceeded {
            ip_address: "10.0.0.1".to_string(),
            endpoint: "/api/test".to_string(),
            requests_count: 60,
        }, None).await;
        
        logger.log_event(SecurityEvent::AuthenticationAttempt {
            node_id: "node-2".to_string(),
            success: false,
            ip_address: "127.0.0.1".to_string(),
            reason: Some("Invalid password".to_string()),
        }, None).await;
        
        // Search for authentication attempts
        let auth_events = logger.search_by_event_type("authentication_attempt").await;
        assert_eq!(auth_events.len(), 2);
        
        // Search for rate limit events
        let rate_limit_events = logger.search_by_event_type("rate_limit_exceeded").await;
        assert_eq!(rate_limit_events.len(), 1);
        
        // Search for non-existent type
        let no_events = logger.search_by_event_type("nonexistent").await;
        assert_eq!(no_events.len(), 0);
    }
    
    #[tokio::test]
    async fn test_export_to_json() {
        let logger = AuditLogger::new(100);
        
        // Log some events
        logger.log_event(SecurityEvent::SystemLifecycle {
            action: "startup".to_string(),
            version: "1.0.0".to_string(),
        }, None).await;
        
        logger.log_event(SecurityEvent::DataAccess {
            user: "test-user".to_string(),
            resource_type: "VC".to_string(),
            resource_id: "vc-123".to_string(),
            action: "CREATE".to_string(),
        }, Some(json!({"credential_type": "TestCredential"}))).await;
        
        let json_export = logger.export_to_json().await;
        
        // Parse and verify
        let entries: Vec<AuditLogEntry> = serde_json::from_str(&json_export).unwrap();
        assert_eq!(entries.len(), 2);
        
        // Verify first event
        match &entries[0].event {
            SecurityEvent::SystemLifecycle { action, .. } => {
                assert_eq!(action, "startup");
            }
            _ => panic!("Wrong event type"),
        }
        
        // Verify second event has context
        assert!(entries[1].context.is_some());
    }
    
    #[tokio::test]
    async fn test_audit_log_entry_serialization() {
        let entry = AuditLogEntry {
            id: "test-123".to_string(),
            timestamp: Utc::now(),
            event: SecurityEvent::TransactionSubmitted {
                signer_did: "did:aura:signer".to_string(),
                transaction_type: "IssueCredential".to_string(),
                transaction_id: "tx-456".to_string(),
                signature_valid: true,
            },
            context: Some(json!({"extra": "data"})),
        };
        
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditLogEntry = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.id, entry.id);
        match deserialized.event {
            SecurityEvent::TransactionSubmitted { transaction_id, .. } => {
                assert_eq!(transaction_id, "tx-456");
            }
            _ => panic!("Wrong event type"),
        }
    }
    
    #[test]
    fn test_init_audit_logger() {
        init_audit_logger(1000);
        assert!(audit_logger().is_some());
    }
    
    #[tokio::test]
    async fn test_log_security_event_convenience() {
        init_audit_logger(100);
        
        let event = SecurityEvent::ConfigurationChange {
            setting: "rate_limit".to_string(),
            old_value: Some("60".to_string()),
            new_value: "120".to_string(),
            changed_by: "admin".to_string(),
        };
        
        log_security_event(event, Some(json!({"reason": "performance tuning"}))).await;
        
        // Verify it was logged
        if let Some(logger) = audit_logger() {
            let entries = logger.get_recent_entries(1).await;
            assert_eq!(entries.len(), 1);
            match &entries[0].event {
                SecurityEvent::ConfigurationChange { new_value, .. } => {
                    assert_eq!(new_value, "120");
                }
                _ => panic!("Wrong event type"),
            }
        }
    }
}