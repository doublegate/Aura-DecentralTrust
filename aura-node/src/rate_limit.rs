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