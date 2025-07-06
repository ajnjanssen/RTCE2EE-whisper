use crate::types::{Config, Room, UserInfo};
use dashmap::DashMap;
use log::info;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Room manager for handling chat rooms and user management
pub struct RoomManager {
    rooms: DashMap<String, Room>,
    room_count: Arc<AtomicUsize>,
    config: Config,
}

impl RoomManager {
    pub fn new() -> Self {
        let manager = Self {
            rooms: DashMap::new(),
            room_count: Arc::new(AtomicUsize::new(0)),
            config: Config::default(),
        };

        // Start cleanup task
        manager.start_cleanup_task();
        manager
    }

    /// Join a user to a room
    pub fn join_room(&self, room_id: String, connection_id: Uuid, user: UserInfo) -> Vec<UserInfo> {
        let mut room = self.rooms.entry(room_id.clone()).or_insert_with(|| {
            info!("Creating new room: {}", room_id);
            self.room_count.fetch_add(1, Ordering::Relaxed);
            Room::new(room_id.clone())
        });

        let user_list = room.get_user_list();
        room.add_user(connection_id, user);
        
        info!("User {} joined room {}", connection_id, room_id);
        user_list
    }

    /// Remove a user from their current room
    pub fn leave_room(&self, room_id: &str, connection_id: Uuid) -> Option<UserInfo> {
        if let Some(mut room) = self.rooms.get_mut(room_id) {
            let user = room.remove_user(&connection_id);
            
            if let Some(ref user_info) = user {
                info!("User {} ({}) left room {}", connection_id, user_info.name, room_id);
            }

            // Check if room is empty and should be removed
            if room.is_empty() {
                drop(room);
                self.rooms.remove(room_id);
                self.room_count.fetch_sub(1, Ordering::Relaxed);
                info!("Removed empty room: {}", room_id);
            }

            user
        } else {
            None
        }
    }

    /// Get all users in a room
    pub fn get_room_users(&self, room_id: &str) -> Vec<UserInfo> {
        self.rooms
            .get(room_id)
            .map(|room| room.get_user_list())
            .unwrap_or_default()
    }

    /// Get all connection IDs in a room (excluding the sender)
    pub fn get_room_connections(&self, room_id: &str, exclude_connection: Option<Uuid>) -> Vec<Uuid> {
        if let Some(room) = self.rooms.get(room_id) {
            room.users
                .keys()
                .filter(|&&id| Some(id) != exclude_connection)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Check if a room exists
    pub fn room_exists(&self, room_id: &str) -> bool {
        self.rooms.contains_key(room_id)
    }

    /// Get the number of active rooms
    pub fn get_room_count(&self) -> usize {
        self.room_count.load(Ordering::Relaxed)
    }

    /// Get the total number of users across all rooms
    pub fn get_total_user_count(&self) -> usize {
        self.rooms.iter().map(|room| room.users.len()).sum()
    }

    /// Get user info for a specific connection in a room
    pub fn get_user_info(&self, room_id: &str, connection_id: Uuid) -> Option<UserInfo> {
        self.rooms
            .get(room_id)
            .and_then(|room| room.users.get(&connection_id).cloned())
    }

    /// Start the periodic cleanup task for idle rooms
    fn start_cleanup_task(&self) {
        let rooms = self.rooms.clone();
        let room_count = self.room_count.clone();
        let cleanup_interval = self.config.room_cleanup_interval;
        let max_idle_time = self.config.max_room_idle_time;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                Self::cleanup_idle_rooms(&rooms, &room_count, max_idle_time);
            }
        });
    }

    /// Clean up idle rooms
    fn cleanup_idle_rooms(
        rooms: &DashMap<String, Room>,
        room_count: &Arc<AtomicUsize>,
        max_idle_time: Duration,
    ) {
        let now = chrono::Utc::now();
        let mut rooms_to_remove = Vec::new();

        for room in rooms.iter() {
            let idle_duration = now - room.last_activity;
            if idle_duration.to_std().unwrap_or(Duration::ZERO) > max_idle_time && room.is_empty() {
                rooms_to_remove.push(room.id.clone());
            }
        }

        for room_id in rooms_to_remove {
            if rooms.remove(&room_id).is_some() {
                room_count.fetch_sub(1, Ordering::Relaxed);
                info!("Cleaned up idle room: {}", room_id);
            }
        }
    }

    /// Get room manager statistics
    pub fn get_stats(&self) -> RoomManagerStats {
        let room_stats: Vec<RoomStats> = self
            .rooms
            .iter()
            .map(|room| RoomStats {
                id: room.id.clone(),
                user_count: room.users.len(),
                created_at: room.created_at,
                last_activity: room.last_activity,
            })
            .collect();

        RoomManagerStats {
            total_rooms: self.get_room_count(),
            total_users: self.get_total_user_count(),
            room_details: room_stats,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoomStats {
    pub id: String,
    pub user_count: usize,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug)]
pub struct RoomManagerStats {
    pub total_rooms: usize,
    pub total_users: usize,
    pub room_details: Vec<RoomStats>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::UserInfo;

    #[test]
    fn test_room_creation_and_joining() {
        let manager = RoomManager::new();
        let connection_id = Uuid::new_v4();
        let user = UserInfo {
            id: "user1".to_string(),
            name: "Test User".to_string(),
            avatar: None,
        };

        // Join a room
        let users = manager.join_room("test-room".to_string(), connection_id, user.clone());
        assert_eq!(users.len(), 0); // Empty room initially

        // Check room exists
        assert!(manager.room_exists("test-room"));
        assert_eq!(manager.get_room_count(), 1);
        assert_eq!(manager.get_total_user_count(), 1);

        // Get room users
        let users = manager.get_room_users("test-room");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].id, "user1");
    }

    #[test]
    fn test_room_leaving() {
        let manager = RoomManager::new();
        let connection_id = Uuid::new_v4();
        let user = UserInfo {
            id: "user1".to_string(),
            name: "Test User".to_string(),
            avatar: None,
        };

        // Join and then leave a room
        manager.join_room("test-room".to_string(), connection_id, user.clone());
        let left_user = manager.leave_room("test-room", connection_id);

        assert!(left_user.is_some());
        assert_eq!(left_user.unwrap().id, "user1");
        assert_eq!(manager.get_room_count(), 0); // Room should be removed when empty
    }

    #[test]
    fn test_multiple_users_in_room() {
        let manager = RoomManager::new();
        let connection1 = Uuid::new_v4();
        let connection2 = Uuid::new_v4();
        
        let user1 = UserInfo {
            id: "user1".to_string(),
            name: "User 1".to_string(),
            avatar: None,
        };
        
        let user2 = UserInfo {
            id: "user2".to_string(),
            name: "User 2".to_string(),
            avatar: None,
        };

        // Both users join the same room
        manager.join_room("test-room".to_string(), connection1, user1);
        let users = manager.join_room("test-room".to_string(), connection2, user2);
        
        assert_eq!(users.len(), 1); // Should return existing users before joining
        assert_eq!(manager.get_total_user_count(), 2);

        // Get all users in room
        let all_users = manager.get_room_users("test-room");
        assert_eq!(all_users.len(), 2);

        // Get connections excluding one
        let connections = manager.get_room_connections("test-room", Some(connection1));
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0], connection2);
    }
}
