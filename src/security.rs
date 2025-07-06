use crate::types::{Config, SecurityError};
use dashmap::DashMap;
use log::{info, warn};
use regex::Regex;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Security manager for handling IP blocking, suspicious activity detection, and input validation
pub struct SecurityManager {
    blocked_ips: DashMap<IpAddr, BlockInfo>,
    connection_counts: DashMap<IpAddr, u32>,
    config: Config,
    room_id_regex: Regex,
    user_id_regex: Regex,
    username_regex: Regex,
    encrypted_message_regex: Regex,
}

#[derive(Debug, Clone)]
struct BlockInfo {
    blocked_at: Instant,
    duration: Duration,
    reason: String,
}

impl SecurityManager {
    pub fn new() -> Self {
        Self {
            blocked_ips: DashMap::new(),
            connection_counts: DashMap::new(),
            config: Config::default(),
            room_id_regex: Regex::new(r"^[a-zA-Z0-9\-_]{1,64}$").unwrap(),
            user_id_regex: Regex::new(r"^[a-zA-Z0-9\-_]{1,64}$").unwrap(),
            username_regex: Regex::new(r"^[a-zA-Z0-9\s\-_]{1,32}$").unwrap(),
            encrypted_message_regex: Regex::new(r"^[A-Za-z0-9+/]+=*\.[A-Za-z0-9+/]+=*$").unwrap(),
        }
    }

    /// Check if an IP can establish a new connection
    pub async fn can_connect(&self, ip: IpAddr) -> bool {
        // Check if IP is blocked
        if self.is_ip_blocked(ip) {
            return false;
        }

        // Check connection count limit
        let count = self.connection_counts.get(&ip).map(|c| *c).unwrap_or(0);
        if count >= self.config.connection_limit_per_ip {
            warn!("Connection limit exceeded for IP: {}", ip);
            return false;
        }

        true
    }

    /// Register a new connection from an IP
    pub fn register_connection(&self, ip: IpAddr) {
        self.connection_counts
            .entry(ip)
            .and_modify(|e| *e += 1)
            .or_insert(1);
    }

    /// Unregister a connection from an IP
    pub fn unregister_connection(&self, ip: IpAddr) {
        if let Some(mut entry) = self.connection_counts.get_mut(&ip) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 {
                drop(entry);
                self.connection_counts.remove(&ip);
            }
        }
    }

    /// Check if an IP is currently blocked
    pub fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        if let Some(block_info) = self.blocked_ips.get(&ip) {
            if block_info.blocked_at.elapsed() < block_info.duration {
                return true;
            } else {
                // Block has expired, remove it
                drop(block_info);
                self.blocked_ips.remove(&ip);
            }
        }
        false
    }

    /// Block an IP address for a specified duration
    pub fn block_ip(&self, ip: IpAddr, duration: Duration, reason: String) {
        info!("Blocking IP {} for {:?}: {}", ip, duration, reason);
        self.blocked_ips.insert(
            ip,
            BlockInfo {
                blocked_at: Instant::now(),
                duration,
                reason,
            },
        );
    }

    /// Validate room ID format
    pub fn validate_room_id(&self, room_id: &str) -> Result<(), SecurityError> {
        if room_id.is_empty() || room_id.len() > self.config.max_room_id_length {
            return Err(SecurityError::InvalidRoomId);
        }

        if !self.room_id_regex.is_match(room_id) {
            return Err(SecurityError::InvalidRoomId);
        }

        Ok(())
    }

    /// Validate user ID format
    pub fn validate_user_id(&self, user_id: &str) -> Result<(), SecurityError> {
        if user_id.is_empty() || user_id.len() > self.config.max_user_id_length {
            return Err(SecurityError::InvalidUserId);
        }

        if !self.user_id_regex.is_match(user_id) {
            return Err(SecurityError::InvalidUserId);
        }

        Ok(())
    }

    /// Validate username format
    pub fn validate_username(&self, username: &str) -> Result<(), SecurityError> {
        if username.is_empty() || username.len() > self.config.max_username_length {
            return Err(SecurityError::InvalidUsername);
        }

        if !self.username_regex.is_match(username) {
            return Err(SecurityError::InvalidUsername);
        }

        Ok(())
    }

    /// Validate encrypted message format
    pub fn validate_encrypted_message(&self, content: &str) -> Result<(), SecurityError> {
        if content.len() > self.config.max_message_size {
            return Err(SecurityError::InvalidEncryptedMessage);
        }

        // Check if it matches the expected encrypted format (base64.base64)
        if !self.encrypted_message_regex.is_match(content) {
            return Err(SecurityError::InvalidEncryptedMessage);
        }

        // Additional validation: try to decode base64 parts
        let parts: Vec<&str> = content.split('.').collect();
        if parts.len() != 2 {
            return Err(SecurityError::InvalidEncryptedMessage);
        }

        // Validate both parts are valid base64
        for part in parts {
            if base64::Engine::decode(&base64::engine::general_purpose::STANDARD, part).is_err() {
                return Err(SecurityError::InvalidEncryptedMessage);
            }
        }

        Ok(())
    }

    /// Detect and handle suspicious activity
    pub fn handle_suspicious_activity(&self, ip: IpAddr, reason: &str) {
        warn!("Suspicious activity from {}: {}", ip, reason);
        
        // Block the IP for 15 minutes for suspicious activity
        self.block_ip(
            ip,
            Duration::from_secs(15 * 60),
            format!("Suspicious activity: {}", reason),
        );
    }

    /// Clean up expired blocks (should be called periodically)
    pub fn cleanup_expired_blocks(&self) {
        self.blocked_ips.retain(|_, block_info| {
            block_info.blocked_at.elapsed() < block_info.duration
        });
    }

    /// Get security statistics
    pub fn get_stats(&self) -> SecurityStats {
        SecurityStats {
            blocked_ips: self.blocked_ips.len(),
            active_connections_by_ip: self.connection_counts.len(),
            total_connections: self.connection_counts.iter().map(|entry| *entry.value()).sum(),
        }
    }
}

#[derive(Debug)]
pub struct SecurityStats {
    pub blocked_ips: usize,
    pub active_connections_by_ip: usize,
    pub total_connections: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_room_id_validation() {
        let security = SecurityManager::new();
        
        // Valid room IDs
        assert!(security.validate_room_id("room123").is_ok());
        assert!(security.validate_room_id("test-room_01").is_ok());
        
        // Invalid room IDs
        assert!(security.validate_room_id("").is_err());
        assert!(security.validate_room_id("room with spaces").is_err());
        assert!(security.validate_room_id("room@invalid").is_err());
        assert!(security.validate_room_id(&"a".repeat(65)).is_err());
    }

    #[test]
    fn test_encrypted_message_validation() {
        let security = SecurityManager::new();
        
        // Valid encrypted message (base64.base64)
        assert!(security.validate_encrypted_message("SGVsbG8=.V29ybGQ=").is_ok());
        
        // Invalid encrypted messages
        assert!(security.validate_encrypted_message("notbase64").is_err());
        assert!(security.validate_encrypted_message("SGVsbG8=").is_err()); // Missing second part
        assert!(security.validate_encrypted_message("SGVsbG8=.invalid").is_err()); // Invalid base64
    }

    #[tokio::test]
    async fn test_connection_limits() {
        let security = SecurityManager::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        
        // Should allow initial connections
        assert!(security.can_connect(ip).await);
        
        // Register maximum connections
        for _ in 0..security.config.connection_limit_per_ip {
            security.register_connection(ip);
        }
        
        // Should reject new connection
        assert!(!security.can_connect(ip).await);
        
        // Unregister one connection
        security.unregister_connection(ip);
        
        // Should allow connection again
        assert!(security.can_connect(ip).await);
    }
}
