use crate::types::ServerMessage;
use dashmap::DashMap;
use log::{debug, warn};
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Connection manager for handling WebSocket connections and message broadcasting
pub struct ConnectionManager {
    /// Map of connection_id -> message sender
    connections: DashMap<Uuid, mpsc::UnboundedSender<ServerMessage>>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
        }
    }

    /// Register a new connection
    pub fn register_connection(&self, connection_id: Uuid, sender: mpsc::UnboundedSender<ServerMessage>) {
        self.connections.insert(connection_id, sender);
        debug!("Registered connection: {}", connection_id);
    }

    /// Unregister a connection
    pub fn unregister_connection(&self, connection_id: Uuid) {
        if self.connections.remove(&connection_id).is_some() {
            debug!("Unregistered connection: {}", connection_id);
        }
    }

    /// Send a message to a specific connection
    pub fn send_to_connection(&self, connection_id: Uuid, message: ServerMessage) -> bool {
        if let Some(sender) = self.connections.get(&connection_id) {
            match sender.send(message) {
                Ok(_) => true,
                Err(e) => {
                    warn!("Failed to send message to connection {}: {}", connection_id, e);
                    // Connection is likely closed, remove it
                    self.connections.remove(&connection_id);
                    false
                }
            }
        } else {
            warn!("Connection {} not found for message sending", connection_id);
            false
        }
    }

    /// Broadcast a message to multiple connections
    pub fn broadcast_to_connections(&self, connection_ids: &[Uuid], message: ServerMessage) {
        let mut successful_sends = 0;
        let mut failed_sends = 0;

        for &connection_id in connection_ids {
            if self.send_to_connection(connection_id, message.clone()) {
                successful_sends += 1;
            } else {
                failed_sends += 1;
            }
        }

        debug!(
            "Broadcast complete: {} successful, {} failed",
            successful_sends, failed_sends
        );
    }

    /// Get the number of active connections
    pub fn get_connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Check if a connection is registered
    pub fn is_connected(&self, connection_id: Uuid) -> bool {
        self.connections.contains_key(&connection_id)
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}
