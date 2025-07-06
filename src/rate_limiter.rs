use crate::types::{Config, RateLimitError};
use dashmap::DashMap;
use governor::{Quota, RateLimiter};
use log::warn;
use std::num::NonZeroU32;
use uuid::Uuid;

/// Rate limiter manager for handling various types of rate limiting
pub struct RateLimiterManager {
    message_limiters: DashMap<Uuid, RateLimiter<governor::state::direct::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>,
    join_limiters: DashMap<Uuid, RateLimiter<governor::state::direct::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>,
    config: Config,
}

impl RateLimiterManager {
    pub fn new() -> Self {
        Self {
            message_limiters: DashMap::new(),
            join_limiters: DashMap::new(),
            config: Config::default(),
        }
    }

    /// Check if a connection can send a message
    pub fn can_send_message(&self, connection_id: Uuid) -> Result<(), RateLimitError> {
        let limiter = self.message_limiters.entry(connection_id).or_insert_with(|| {
            RateLimiter::direct(Quota::per_minute(
                NonZeroU32::new(self.config.message_rate_limit).unwrap()
            ))
        });

        match limiter.check() {
            Ok(_) => Ok(()),
            Err(_) => {
                warn!("Message rate limit exceeded for connection: {}", connection_id);
                Err(RateLimitError::MessageLimit)
            }
        }
    }

    /// Check if a connection can join a room
    pub fn can_join_room(&self, connection_id: Uuid) -> Result<(), RateLimitError> {
        let limiter = self.join_limiters.entry(connection_id).or_insert_with(|| {
            RateLimiter::direct(Quota::per_minute(
                NonZeroU32::new(self.config.join_rate_limit).unwrap()
            ))
        });

        match limiter.check() {
            Ok(_) => Ok(()),
            Err(_) => {
                warn!("Join rate limit exceeded for connection: {}", connection_id);
                Err(RateLimitError::JoinLimit)
            }
        }
    }

    /// Check if message size is within limits
    pub fn validate_message_size(&self, content: &str) -> Result<(), RateLimitError> {
        if content.len() > self.config.max_message_size {
            warn!("Message too large: {} bytes", content.len());
            return Err(RateLimitError::MessageTooLarge);
        }
        Ok(())
    }

    /// Remove rate limiters for a disconnected connection
    pub fn cleanup_connection(&self, connection_id: Uuid) {
        self.message_limiters.remove(&connection_id);
        self.join_limiters.remove(&connection_id);
    }

    /// Get rate limiting statistics
    pub fn get_stats(&self) -> RateLimiterStats {
        RateLimiterStats {
            active_message_limiters: self.message_limiters.len(),
            active_join_limiters: self.join_limiters.len(),
            message_rate_limit: self.config.message_rate_limit,
            join_rate_limit: self.config.join_rate_limit,
            max_message_size: self.config.max_message_size,
        }
    }

    /// Cleanup expired rate limiters (should be called periodically)
    pub fn cleanup_expired_limiters(&self) {
        // Rate limiters automatically clean up their internal state
        // This method can be used for additional cleanup if needed
    }
}

#[derive(Debug)]
pub struct RateLimiterStats {
    pub active_message_limiters: usize,
    pub active_join_limiters: usize,
    pub message_rate_limit: u32,
    pub join_rate_limit: u32,
    pub max_message_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_message_size_validation() {
        let rate_limiter = RateLimiterManager::new();
        
        // Valid message size
        let small_message = "a".repeat(100);
        assert!(rate_limiter.validate_message_size(&small_message).is_ok());
        
        // Invalid message size
        let large_message = "a".repeat(20000);
        assert!(rate_limiter.validate_message_size(&large_message).is_err());
    }

    #[test]
    fn test_rate_limiting() {
        let rate_limiter = RateLimiterManager::new();
        let connection_id = Uuid::new_v4();
        
        // Should allow initial messages within rate limit
        for _ in 0..5 {
            assert!(rate_limiter.can_send_message(connection_id).is_ok());
        }
        
        // Should allow initial room joins within rate limit
        for _ in 0..3 {
            assert!(rate_limiter.can_join_room(connection_id).is_ok());
        }
    }

    #[test]
    fn test_cleanup() {
        let rate_limiter = RateLimiterManager::new();
        let connection_id = Uuid::new_v4();
        
        // Create some rate limiters
        let _ = rate_limiter.can_send_message(connection_id);
        let _ = rate_limiter.can_join_room(connection_id);
        
        assert!(rate_limiter.message_limiters.contains_key(&connection_id));
        assert!(rate_limiter.join_limiters.contains_key(&connection_id));
        
        // Cleanup
        rate_limiter.cleanup_connection(connection_id);
        
        assert!(!rate_limiter.message_limiters.contains_key(&connection_id));
        assert!(!rate_limiter.join_limiters.contains_key(&connection_id));
    }
}
