use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

/// WebSocket message types from client to server
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "join")]
    Join { 
        payload: JoinPayload
    },
    #[serde(rename = "leave")]
    Leave,
    #[serde(rename = "message")]
    Message { 
        payload: MessagePayload 
    },
    #[serde(rename = "typing")]
    Typing { 
        payload: TypingPayload 
    },
    #[serde(rename = "reaction")]
    Reaction { 
        payload: ReactionPayload 
    },
}

/// WebSocket message types from server to client
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    #[serde(rename = "pong")]
    Pong,
    #[serde(rename = "userJoined")]
    UserJoined { payload: UserJoinedPayload },
    #[serde(rename = "userLeft")]
    UserLeft { payload: UserLeftPayload },
    #[serde(rename = "userList")]
    UserList { payload: UserListPayload },
    #[serde(rename = "message")]
    Message {
        payload: String,
    },
    #[serde(rename = "userTyping")]
    UserTyping { payload: TypingStatusPayload },
    #[serde(rename = "reaction")]
    Reaction {
        messageId: String,
        user: UserInfo,
        emoji: String,
    },
    #[serde(rename = "error")]
    Error { code: String, message: String },
}

/// User information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
    pub avatar: Option<String>,
}

/// Message payload structure for encrypted messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePayload {
    pub encrypted: String,
}

/// Join payload structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinPayload {
    #[serde(rename = "roomId")]
    pub room_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub username: String,
}

/// Typing payload structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypingPayload {
    #[serde(rename = "isTyping")]
    pub is_typing: bool,
    #[serde(rename = "roomId")]
    pub room_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub username: String,
}

/// Reaction payload structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionPayload {
    #[serde(rename = "messageId")]
    pub message_id: String,
    pub emoji: String,
}

/// User joined payload structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserJoinedPayload {
    #[serde(rename = "userId")]
    pub user_id: String,
    pub username: String,
}

/// User left payload structure  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserLeftPayload {
    #[serde(rename = "userId")]
    pub user_id: String,
}

/// User list payload structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserListPayload {
    pub users: Vec<UserInfo>,
}

/// Typing status payload structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypingStatusPayload {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "isTyping")]
    pub is_typing: bool,
}

/// Room information
#[derive(Debug, Clone)]
pub struct Room {
    pub id: String,
    pub users: HashMap<Uuid, UserInfo>,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
}

impl Room {
    pub fn new(id: String) -> Self {
        let now = Utc::now();
        Self {
            id,
            users: HashMap::new(),
            created_at: now,
            last_activity: now,
        }
    }

    pub fn add_user(&mut self, connection_id: Uuid, user: UserInfo) {
        self.users.insert(connection_id, user);
        self.last_activity = Utc::now();
    }

    pub fn remove_user(&mut self, connection_id: &Uuid) -> Option<UserInfo> {
        let user = self.users.remove(connection_id);
        self.last_activity = Utc::now();
        user
    }

    pub fn get_user_list(&self) -> Vec<UserInfo> {
        self.users.values().cloned().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }
}

/// Connection information
#[derive(Debug, Clone)]
pub struct Connection {
    pub id: Uuid,
    pub ip: IpAddr,
    pub user: Option<UserInfo>,
    pub room_id: Option<String>,
    pub connected_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub message_count: u32,
    pub join_count: u32,
}

impl Connection {
    pub fn new(id: Uuid, ip: IpAddr) -> Self {
        let now = Utc::now();
        Self {
            id,
            ip,
            user: None,
            room_id: None,
            connected_at: now,
            last_activity: now,
            message_count: 0,
            join_count: 0,
        }
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }

    pub fn join_room(&mut self, room_id: String, user: UserInfo) {
        self.room_id = Some(room_id);
        self.user = Some(user);
        self.join_count += 1;
        self.update_activity();
    }

    pub fn leave_room(&mut self) {
        self.room_id = None;
        self.user = None;
        self.update_activity();
    }

    pub fn increment_message_count(&mut self) {
        self.message_count += 1;
        self.update_activity();
    }
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub stats: ServerStats,
}

/// Server statistics
#[derive(Debug, Serialize)]
pub struct ServerStats {
    pub uptime_seconds: i64,
    pub active_connections: usize,
    pub active_rooms: usize,
    pub total_users: usize,
}

/// Rate limiting error
#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Message rate limit exceeded")]
    MessageLimit,
    #[error("Join rate limit exceeded")]
    JoinLimit,
    #[error("Message too large")]
    MessageTooLarge,
    #[error("Connection limit exceeded")]
    ConnectionLimit,
}

/// Security validation error
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Invalid room ID format")]
    InvalidRoomId,
    #[error("Invalid user ID format")]
    InvalidUserId,
    #[error("Invalid username format")]
    InvalidUsername,
    #[error("Invalid encrypted message format")]
    InvalidEncryptedMessage,
    #[error("Suspicious activity detected")]
    SuspiciousActivity,
    #[error("IP address blocked")]
    BlockedIp,
}

/// Configuration constants
pub struct Config {
    pub max_message_size: usize,
    pub max_room_id_length: usize,
    pub max_username_length: usize,
    pub max_user_id_length: usize,
    pub heartbeat_interval: Duration,
    pub room_cleanup_interval: Duration,
    pub max_room_idle_time: Duration,
    pub message_rate_limit: u32,
    pub join_rate_limit: u32,
    pub connection_limit_per_ip: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_message_size: 10 * 1024, // 10KB
            max_room_id_length: 64,
            max_username_length: 32,
            max_user_id_length: 64,
            heartbeat_interval: std::time::Duration::from_secs(30),
            room_cleanup_interval: std::time::Duration::from_secs(300), // 5 minutes
            max_room_idle_time: std::time::Duration::from_secs(3600), // 1 hour
            message_rate_limit: 30, // messages per minute
            join_rate_limit: 5, // joins per minute
            connection_limit_per_ip: 10,
        }
    }
}

use std::time::Duration;
