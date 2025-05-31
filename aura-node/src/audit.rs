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