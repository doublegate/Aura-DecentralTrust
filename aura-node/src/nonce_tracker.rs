use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Nonce expiry time (5 minutes)
const NONCE_EXPIRY_SECONDS: u64 = 300;

/// Structure to track transaction nonces and prevent replay attacks
pub struct NonceTracker {
    /// In-memory cache of recent nonces
    recent_nonces: Arc<RwLock<HashSet<String>>>,
    /// Persistent storage for nonces
    db: Arc<rocksdb::DB>,
    /// Maximum age for nonces
    max_age: Duration,
}

impl NonceTracker {
    /// Create a new nonce tracker with persistent storage
    pub fn new(db_path: &Path) -> Result<Self> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);

        let db_path = db_path.join("nonces");
        std::fs::create_dir_all(&db_path)?;

        let db = rocksdb::DB::open(&opts, db_path).context("Failed to open nonce database")?;

        Ok(NonceTracker {
            recent_nonces: Arc::new(RwLock::new(HashSet::new())),
            db: Arc::new(db),
            max_age: Duration::from_secs(NONCE_EXPIRY_SECONDS),
        })
    }

    /// Check if a nonce has been used within the expiry window
    pub async fn is_nonce_used(&self, nonce: u64, timestamp: i64) -> Result<bool> {
        // Check timestamp is within valid window
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let age = (now - timestamp).abs();
        if age > self.max_age.as_secs() as i64 {
            // Nonce is too old or too far in the future
            return Ok(false);
        }

        // Check memory cache first
        let nonce_str = nonce.to_string();
        {
            let nonces = self.recent_nonces.read().await;
            if nonces.contains(&nonce_str) {
                return Ok(true);
            }
        }

        // Check persistent storage
        let key = self.make_key(nonce, timestamp);
        match self.db.get(&key) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(anyhow::anyhow!("Database error: {e}")),
        }
    }

    /// Record a nonce as used
    pub async fn record_nonce(&self, nonce: u64, timestamp: i64) -> Result<()> {
        // Add to memory cache
        let nonce_str = nonce.to_string();
        {
            let mut nonces = self.recent_nonces.write().await;
            nonces.insert(nonce_str);
        }

        // Add to persistent storage with timestamp
        let key = self.make_key(nonce, timestamp);
        let value = timestamp.to_be_bytes();

        self.db.put(&key, value).context("Failed to store nonce")?;

        Ok(())
    }

    /// Clean up expired nonces (should be called periodically)
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let cutoff = now - self.max_age.as_secs() as i64;
        let mut removed = 0;

        // Clean persistent storage
        let iter = self.db.iterator(rocksdb::IteratorMode::Start);
        let mut keys_to_delete = Vec::new();

        for (key, value) in iter.flatten() {
            if value.len() == 8 {
                let timestamp = i64::from_be_bytes(value.as_ref().try_into().unwrap());
                if timestamp < cutoff {
                    keys_to_delete.push(key.to_vec());
                }
            }
        }

        for key in keys_to_delete {
            self.db.delete(&key)?;
            removed += 1;
        }

        // Clear memory cache periodically
        if removed > 0 {
            let mut nonces = self.recent_nonces.write().await;
            nonces.clear();
        }

        Ok(removed)
    }

    /// Make a storage key from nonce and timestamp
    fn make_key(&self, nonce: u64, timestamp: i64) -> Vec<u8> {
        format!("{timestamp}:{nonce}").into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_nonce_tracking() {
        let temp_dir = TempDir::new().unwrap();
        let tracker = NonceTracker::new(temp_dir.path()).unwrap();

        let nonce = 123456789u64;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Nonce should not be used initially
        assert!(!tracker.is_nonce_used(nonce, timestamp).await.unwrap());

        // Record the nonce
        tracker.record_nonce(nonce, timestamp).await.unwrap();

        // Now it should be marked as used
        assert!(tracker.is_nonce_used(nonce, timestamp).await.unwrap());
    }

    #[tokio::test]
    async fn test_nonce_expiry() {
        let temp_dir = TempDir::new().unwrap();
        let tracker = NonceTracker::new(temp_dir.path()).unwrap();

        let nonce = 987654321u64;
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 400; // 400 seconds ago

        // Old nonce with old timestamp should not be considered used (too old)
        assert!(!tracker.is_nonce_used(nonce, old_timestamp).await.unwrap());

        // Record with current timestamp
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        tracker
            .record_nonce(nonce, current_timestamp)
            .await
            .unwrap();

        // Check with old timestamp - should be false (timestamp too old)
        assert!(!tracker.is_nonce_used(nonce, old_timestamp).await.unwrap());

        // But with current timestamp it should be true
        assert!(tracker
            .is_nonce_used(nonce, current_timestamp)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_nonce_cleanup() {
        let temp_dir = TempDir::new().unwrap();
        let tracker = NonceTracker::new(temp_dir.path()).unwrap();

        // Add some nonces
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Old nonce
        tracker.record_nonce(111111u64, now - 400).await.unwrap();

        // Recent nonce
        tracker.record_nonce(222222u64, now).await.unwrap();

        // Run cleanup
        let removed = tracker.cleanup_expired().await.unwrap();
        assert_eq!(removed, 1);

        // Recent nonce should still exist
        assert!(tracker.is_nonce_used(222222u64, now).await.unwrap());
    }

    #[tokio::test]
    async fn test_duplicate_nonce_prevention() {
        let temp_dir = TempDir::new().unwrap();
        let tracker = NonceTracker::new(temp_dir.path()).unwrap();

        let nonce = 555555u64;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // First use should succeed
        assert!(!tracker.is_nonce_used(nonce, timestamp).await.unwrap());
        tracker.record_nonce(nonce, timestamp).await.unwrap();

        // Second use should fail
        assert!(tracker.is_nonce_used(nonce, timestamp).await.unwrap());

        // Even with slightly different timestamp (within window)
        assert!(tracker.is_nonce_used(nonce, timestamp + 1).await.unwrap());
    }

    #[tokio::test]
    async fn test_persistence_across_restart() {
        let temp_dir = TempDir::new().unwrap();

        // Create tracker and add nonce
        let nonce = 777777u64;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        {
            let tracker = NonceTracker::new(temp_dir.path()).unwrap();
            tracker.record_nonce(nonce, timestamp).await.unwrap();
            assert!(tracker.is_nonce_used(nonce, timestamp).await.unwrap());
        }

        // Create new tracker instance
        {
            let tracker = NonceTracker::new(temp_dir.path()).unwrap();

            // Nonce should still be marked as used
            assert!(tracker.is_nonce_used(nonce, timestamp).await.unwrap());
        }
    }
}
