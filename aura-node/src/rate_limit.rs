use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tracing::warn;

/// Rate limiter state
#[derive(Clone)]
pub struct RateLimiter {
    /// Map of IP addresses to their request counts
    requests: Arc<Mutex<HashMap<String, RequestInfo>>>,
    /// Maximum requests per minute
    max_rpm: u32,
    /// Maximum requests per hour
    max_rph: u32,
}

#[derive(Debug)]
struct RequestInfo {
    /// Requests in current minute
    minute_count: u32,
    /// Requests in current hour
    hour_count: u32,
    /// When the minute window started
    minute_window_start: Instant,
    /// When the hour window started
    hour_window_start: Instant,
}

impl RateLimiter {
    pub fn new(max_rpm: u32, max_rph: u32) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_rpm,
            max_rph,
        }
    }

    /// Check if the IP is rate limited
    async fn check_rate_limit(&self, ip: String) -> Result<(), StatusCode> {
        let mut requests = self.requests.lock().await;
        let now = Instant::now();

        let info = requests.entry(ip.clone()).or_insert_with(|| RequestInfo {
            minute_count: 0,
            hour_count: 0,
            minute_window_start: now,
            hour_window_start: now,
        });

        // Reset minute window if needed
        if now.duration_since(info.minute_window_start) >= Duration::from_secs(60) {
            info.minute_count = 0;
            info.minute_window_start = now;
        }

        // Reset hour window if needed
        if now.duration_since(info.hour_window_start) >= Duration::from_secs(3600) {
            info.hour_count = 0;
            info.hour_window_start = now;
        }

        // Check limits
        if info.minute_count >= self.max_rpm {
            warn!("Rate limit exceeded for IP {}: {} requests/minute", ip, info.minute_count);
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        if info.hour_count >= self.max_rph {
            warn!("Rate limit exceeded for IP {}: {} requests/hour", ip, info.hour_count);
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        // Increment counters
        info.minute_count += 1;
        info.hour_count += 1;

        Ok(())
    }

    /// Clean up old entries periodically
    pub async fn cleanup_old_entries(&self) {
        let mut requests = self.requests.lock().await;
        let now = Instant::now();
        
        // Remove entries older than 2 hours
        requests.retain(|_, info| {
            now.duration_since(info.hour_window_start) < Duration::from_secs(7200)
        });
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract IP address
    let ip = addr.ip().to_string();

    // Check rate limit
    limiter.check_rate_limit(ip).await?;

    // Continue to next middleware/handler
    Ok(next.run(req).await)
}

/// Create a cleanup task that runs periodically
pub fn spawn_cleanup_task(limiter: RateLimiter) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
        loop {
            interval.tick().await;
            limiter.cleanup_old_entries().await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[tokio::test]
    async fn test_rate_limiter_new() {
        let limiter = RateLimiter::new(60, 1000);
        assert_eq!(limiter.max_rpm, 60);
        assert_eq!(limiter.max_rph, 1000);
        
        let requests = limiter.requests.lock().await;
        assert!(requests.is_empty());
    }
    
    #[tokio::test]
    async fn test_rate_limit_under_limit() {
        let limiter = RateLimiter::new(10, 100);
        let ip = "192.168.1.1".to_string();
        
        // Should allow requests under the limit
        for _ in 0..5 {
            let result = limiter.check_rate_limit(ip.clone()).await;
            assert!(result.is_ok());
        }
        
        // Check request count
        let requests = limiter.requests.lock().await;
        let info = requests.get(&ip).unwrap();
        assert_eq!(info.minute_count, 5);
        assert_eq!(info.hour_count, 5);
    }
    
    #[tokio::test]
    async fn test_rate_limit_minute_exceeded() {
        let limiter = RateLimiter::new(5, 100);
        let ip = "192.168.1.2".to_string();
        
        // Make requests up to the limit
        for _ in 0..5 {
            let result = limiter.check_rate_limit(ip.clone()).await;
            assert!(result.is_ok());
        }
        
        // Next request should be rate limited
        let result = limiter.check_rate_limit(ip.clone()).await;
        assert_eq!(result, Err(StatusCode::TOO_MANY_REQUESTS));
    }
    
    #[tokio::test]
    async fn test_rate_limit_hour_exceeded() {
        let limiter = RateLimiter::new(100, 10);
        let ip = "192.168.1.3".to_string();
        
        // Make requests up to the hour limit
        for _ in 0..10 {
            let result = limiter.check_rate_limit(ip.clone()).await;
            assert!(result.is_ok());
        }
        
        // Next request should be rate limited
        let result = limiter.check_rate_limit(ip.clone()).await;
        assert_eq!(result, Err(StatusCode::TOO_MANY_REQUESTS));
    }
    
    #[tokio::test]
    async fn test_multiple_ips() {
        let limiter = RateLimiter::new(5, 100);
        let ip1 = "192.168.1.10".to_string();
        let ip2 = "192.168.1.11".to_string();
        
        // Each IP should have its own limit
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(ip1.clone()).await.is_ok());
            assert!(limiter.check_rate_limit(ip2.clone()).await.is_ok());
        }
        
        // Both should be rate limited now
        assert_eq!(limiter.check_rate_limit(ip1.clone()).await, Err(StatusCode::TOO_MANY_REQUESTS));
        assert_eq!(limiter.check_rate_limit(ip2.clone()).await, Err(StatusCode::TOO_MANY_REQUESTS));
    }
    
    #[tokio::test]
    async fn test_minute_window_reset() {
        // Use a custom limiter with manual window control for testing
        let limiter = RateLimiter::new(2, 100);
        let ip = "192.168.1.20".to_string();
        
        // Make 2 requests
        assert!(limiter.check_rate_limit(ip.clone()).await.is_ok());
        assert!(limiter.check_rate_limit(ip.clone()).await.is_ok());
        
        // Should be rate limited
        assert_eq!(limiter.check_rate_limit(ip.clone()).await, Err(StatusCode::TOO_MANY_REQUESTS));
        
        // Manually update the window start time to simulate time passing
        {
            let mut requests = limiter.requests.lock().await;
            if let Some(info) = requests.get_mut(&ip) {
                info.minute_window_start = Instant::now() - Duration::from_secs(61);
            }
        }
        
        // Should be allowed again after window reset
        assert!(limiter.check_rate_limit(ip.clone()).await.is_ok());
    }
    
    #[tokio::test]
    async fn test_hour_window_reset() {
        let limiter = RateLimiter::new(100, 2);
        let ip = "192.168.1.21".to_string();
        
        // Make 2 requests
        assert!(limiter.check_rate_limit(ip.clone()).await.is_ok());
        assert!(limiter.check_rate_limit(ip.clone()).await.is_ok());
        
        // Should be rate limited
        assert_eq!(limiter.check_rate_limit(ip.clone()).await, Err(StatusCode::TOO_MANY_REQUESTS));
        
        // Manually update the window start time to simulate time passing
        {
            let mut requests = limiter.requests.lock().await;
            if let Some(info) = requests.get_mut(&ip) {
                info.hour_window_start = Instant::now() - Duration::from_secs(3601);
            }
        }
        
        // Should be allowed again after window reset
        assert!(limiter.check_rate_limit(ip.clone()).await.is_ok());
    }
    
    #[tokio::test]
    async fn test_cleanup_old_entries() {
        let limiter = RateLimiter::new(10, 100);
        
        // Add some entries
        let ips = vec!["192.168.1.30", "192.168.1.31", "192.168.1.32"];
        for ip in &ips {
            limiter.check_rate_limit(ip.to_string()).await.unwrap();
        }
        
        // Verify all entries exist
        {
            let requests = limiter.requests.lock().await;
            assert_eq!(requests.len(), 3);
        }
        
        // Make one entry old
        {
            let mut requests = limiter.requests.lock().await;
            if let Some(info) = requests.get_mut("192.168.1.30") {
                info.hour_window_start = Instant::now() - Duration::from_secs(7201);
            }
        }
        
        // Run cleanup
        limiter.cleanup_old_entries().await;
        
        // Should have removed the old entry
        {
            let requests = limiter.requests.lock().await;
            assert_eq!(requests.len(), 2);
            assert!(!requests.contains_key("192.168.1.30"));
            assert!(requests.contains_key("192.168.1.31"));
            assert!(requests.contains_key("192.168.1.32"));
        }
    }
    
    #[tokio::test]
    async fn test_concurrent_requests() {
        let limiter = Arc::new(RateLimiter::new(20, 200));
        let ip = "192.168.1.40".to_string();
        
        // Spawn multiple concurrent tasks
        let mut handles = vec![];
        for _ in 0..10 {
            let limiter_clone = limiter.clone();
            let ip_clone = ip.clone();
            let handle = tokio::spawn(async move {
                limiter_clone.check_rate_limit(ip_clone).await
            });
            handles.push(handle);
        }
        
        // Wait for all tasks to complete
        let mut success_count = 0;
        for handle in handles {
            if handle.await.unwrap().is_ok() {
                success_count += 1;
            }
        }
        
        // All should succeed since we're under the limit
        assert_eq!(success_count, 10);
        
        // Verify count
        let requests = limiter.requests.lock().await;
        let info = requests.get(&ip).unwrap();
        assert_eq!(info.minute_count, 10);
        assert_eq!(info.hour_count, 10);
    }
    
    #[tokio::test]
    async fn test_request_info_initialization() {
        let limiter = RateLimiter::new(10, 100);
        let ip = "192.168.1.50".to_string();
        
        // First request should create new RequestInfo
        let before = Instant::now();
        limiter.check_rate_limit(ip.clone()).await.unwrap();
        let after = Instant::now();
        
        let requests = limiter.requests.lock().await;
        let info = requests.get(&ip).unwrap();
        
        assert_eq!(info.minute_count, 1);
        assert_eq!(info.hour_count, 1);
        assert!(info.minute_window_start >= before);
        assert!(info.minute_window_start <= after);
        assert!(info.hour_window_start >= before);
        assert!(info.hour_window_start <= after);
    }
    
    #[tokio::test]
    async fn test_spawn_cleanup_task() {
        // Just verify it compiles and doesn't panic
        let limiter = RateLimiter::new(60, 1000);
        spawn_cleanup_task(limiter);
        // Task will be cleaned up when test ends
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    
    #[tokio::test]
    async fn test_edge_case_exact_limit() {
        let limiter = RateLimiter::new(3, 10);
        let ip = "192.168.1.60".to_string();
        
        // Make exactly the limit of requests
        for i in 0..3 {
            let result = limiter.check_rate_limit(ip.clone()).await;
            assert!(result.is_ok(), "Request {} should succeed", i + 1);
        }
        
        // The next one should fail
        let result = limiter.check_rate_limit(ip.clone()).await;
        assert_eq!(result, Err(StatusCode::TOO_MANY_REQUESTS));
        
        // Verify counts
        let requests = limiter.requests.lock().await;
        let info = requests.get(&ip).unwrap();
        assert_eq!(info.minute_count, 3);
        assert_eq!(info.hour_count, 3);
    }
}