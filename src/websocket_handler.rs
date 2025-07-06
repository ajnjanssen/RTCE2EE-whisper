use crate::types::{ClientMessage, Connection, RateLimitError, SecurityError, ServerMessage, UserInfo, UserJoinedPayload, UserLeftPayload, UserListPayload, TypingStatusPayload};
use crate::ServerState;
use anyhow::{anyhow, Result};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use serde_json;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use uuid::Uuid;
use warp::ws::{Message, WebSocket};

/// WebSocket connection handler
pub struct WebSocketHandler {
    connection_id: Uuid,
    client_ip: IpAddr,
    state: ServerState,
    connection: Connection,
}

impl WebSocketHandler {
    pub fn new(connection_id: Uuid, client_ip: IpAddr, state: ServerState) -> Self {
        Self {
            connection_id,
            client_ip,
            state,
            connection: Connection::new(connection_id, client_ip),
        }
    }

    /// Handle the WebSocket connection
    pub async fn handle(mut self, ws: WebSocket) -> Result<()> {
        info!("Starting WebSocket handler for connection: {}", self.connection_id);
        
        // Register the connection
        self.state.security.register_connection(self.client_ip);

        let (mut ws_tx, mut ws_rx) = ws.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();

        // Register connection with the connection manager
        self.state.connections.register_connection(self.connection_id, tx.clone());

        // Spawn heartbeat task
        let heartbeat_tx = tx.clone();
        let heartbeat_task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                if heartbeat_tx.send(ServerMessage::Pong).is_err() {
                    break;
                }
            }
        });

        // Spawn message sender task
        let sender_task = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                match serde_json::to_string(&message) {
                    Ok(json) => {
                        if let Err(e) = ws_tx.send(Message::text(json)).await {
                            error!("Failed to send message: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Failed to serialize message: {}", e);
                    }
                }
            }
        });

        // Handle incoming messages
        let message_handler_result = self.handle_messages(&mut ws_rx, tx).await;

        // Cleanup
        heartbeat_task.abort();
        sender_task.abort();
        
        // Unregister connection
        self.state.connections.unregister_connection(self.connection_id);
        
        // Leave room if joined
        if let Some(room_id) = &self.connection.room_id {
            self.leave_room(room_id.clone()).await;
        }

        // Unregister connection
        self.state.security.unregister_connection(self.client_ip);
        self.state.rate_limiter.cleanup_connection(self.connection_id);

        message_handler_result
    }

    /// Handle incoming WebSocket messages
    async fn handle_messages(
        &mut self,
        ws_rx: &mut futures_util::stream::SplitStream<WebSocket>,
        tx: mpsc::UnboundedSender<ServerMessage>,
    ) -> Result<()> {
        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(msg) if msg.is_text() => {
                    if let Ok(text) = msg.to_str() {
                        if let Err(e) = self.handle_text_message(text.to_string(), &tx).await {
                            error!("Error handling message from {}: {}", self.connection_id, e);
                            
                            let error_msg = match e.downcast_ref::<RateLimitError>() {
                                Some(RateLimitError::MessageLimit) => ServerMessage::Error {
                                    code: "RATE_LIMITED".to_string(),
                                    message: "Message rate limit exceeded".to_string(),
                                },
                                Some(RateLimitError::JoinLimit) => ServerMessage::Error {
                                    code: "RATE_LIMITED".to_string(),
                                    message: "Join rate limit exceeded".to_string(),
                                },
                                Some(RateLimitError::MessageTooLarge) => ServerMessage::Error {
                                    code: "MESSAGE_TOO_LARGE".to_string(),
                                    message: "Message too large".to_string(),
                                },
                                _ => match e.downcast_ref::<SecurityError>() {
                                    Some(SecurityError::InvalidRoomId) => ServerMessage::Error {
                                        code: "INVALID_ROOM_ID".to_string(),
                                        message: "Invalid room ID format".to_string(),
                                    },
                                    Some(SecurityError::InvalidUserId) => ServerMessage::Error {
                                        code: "INVALID_USER_ID".to_string(),
                                        message: "Invalid user ID format".to_string(),
                                    },
                                    Some(SecurityError::InvalidUsername) => ServerMessage::Error {
                                        code: "INVALID_USERNAME".to_string(),
                                        message: "Invalid username format".to_string(),
                                    },
                                    Some(SecurityError::InvalidEncryptedMessage) => ServerMessage::Error {
                                        code: "INVALID_MESSAGE".to_string(),
                                        message: "Invalid encrypted message format".to_string(),
                                    },
                                    _ => ServerMessage::Error {
                                        code: "INTERNAL_ERROR".to_string(),
                                        message: "Internal server error".to_string(),
                                    },
                                },
                            };

                            let _ = tx.send(error_msg);
                        }
                    }
                }
                Ok(msg) if msg.is_close() => {
                    info!("WebSocket connection closed: {}", self.connection_id);
                    break;
                }
                Ok(msg) if msg.is_ping() => {
                    debug!("Received ping from {}", self.connection_id);
                }
                Ok(msg) if msg.is_pong() => {
                    debug!("Received pong from {}", self.connection_id);
                }
                Ok(_) => {
                    warn!("Received unexpected message type from {}", self.connection_id);
                }
                Err(e) => {
                    error!("WebSocket error for {}: {}", self.connection_id, e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle text messages
    async fn handle_text_message(
        &mut self,
        text: String,
        tx: &mpsc::UnboundedSender<ServerMessage>,
    ) -> Result<()> {
        self.connection.update_activity();

        debug!("Received raw JSON: {}", text);
        let client_message: ClientMessage = serde_json::from_str(&text)
            .map_err(|e| anyhow!("Invalid JSON: {}", e))?;

        match client_message {
            ClientMessage::Ping => {
                tx.send(ServerMessage::Pong)?;
            }
            ClientMessage::Join { payload } => {
                let user = UserInfo {
                    id: payload.user_id,
                    name: payload.username,
                    avatar: None,
                };
                self.handle_join(payload.room_id, user, tx).await?;
            }
            ClientMessage::Leave => {
                self.handle_leave(tx).await?;
            }
            ClientMessage::Message { payload } => {
                self.handle_message(payload.encrypted, tx).await?;
            }
            ClientMessage::Typing { payload } => {
                self.handle_typing(payload.is_typing, tx).await?;
            }
            ClientMessage::Reaction { payload } => {
                self.handle_reaction(payload.message_id, payload.emoji, tx).await?;
            }
        }

        Ok(())
    }

    /// Handle join room message
    async fn handle_join(
        &mut self,
        room_id: String,
        user: UserInfo,
        tx: &mpsc::UnboundedSender<ServerMessage>,
    ) -> Result<()> {
        // Rate limiting
        self.state.rate_limiter.can_join_room(self.connection_id)?;

        // Security validation
        self.state.security.validate_room_id(&room_id)?;
        self.state.security.validate_user_id(&user.id)?;
        self.state.security.validate_username(&user.name)?;

        // Leave current room if any
        if let Some(current_room) = &self.connection.room_id {
            self.leave_room(current_room.clone()).await;
        }

        // Join new room
        let existing_users = self.state.rooms.join_room(room_id.clone(), self.connection_id, user.clone());
        self.connection.join_room(room_id.clone(), user.clone());

        // Send user list to the new user
        tx.send(ServerMessage::UserList { 
            payload: UserListPayload { users: existing_users }
        })?;

        // Notify other users in the room
        self.broadcast_to_room(
            &room_id,
            ServerMessage::UserJoined { 
                payload: UserJoinedPayload { 
                    user_id: user.id.clone(),
                    username: user.name.clone(),
                }
            },
            Some(self.connection_id),
        ).await;

        info!("Connection {} joined room {}", self.connection_id, room_id);
        Ok(())
    }

    /// Handle leave room message
    async fn handle_leave(&mut self, _tx: &mpsc::UnboundedSender<ServerMessage>) -> Result<()> {
        if let Some(room_id) = &self.connection.room_id {
            self.leave_room(room_id.clone()).await;
        }
        Ok(())
    }

    /// Handle chat message
    async fn handle_message(
        &mut self,
        content: String,
        _tx: &mpsc::UnboundedSender<ServerMessage>,
    ) -> Result<()> {
        // Rate limiting
        self.state.rate_limiter.can_send_message(self.connection_id)?;
        self.state.rate_limiter.validate_message_size(&content)?;

        // Security validation
        self.state.security.validate_encrypted_message(&content)?;

        // Check if user is in a room
        let room_id = match &self.connection.room_id {
            Some(room_id) => room_id.clone(),
            None => return Err(anyhow!("Not in a room")),
        };

        self.connection.increment_message_count();

        // Relay the encrypted message as-is to other users in the room
        let message = ServerMessage::Message {
            payload: content,
        };

        // Broadcast to all users in the room (excluding sender)
        self.broadcast_to_room(&room_id, message, Some(self.connection_id)).await;

        Ok(())
    }

    /// Handle typing indicator
    async fn handle_typing(
        &mut self,
        is_typing: bool,
        _tx: &mpsc::UnboundedSender<ServerMessage>,
    ) -> Result<()> {
        let (room_id, user) = match (&self.connection.room_id, &self.connection.user) {
            (Some(room_id), Some(user)) => (room_id.clone(), user.clone()),
            _ => return Ok(()), // Ignore if not in a room
        };

        let message = ServerMessage::UserTyping {
            payload: TypingStatusPayload {
                user_id: user.id,
                is_typing,
            }
        };

        // Broadcast to other users in the room
        self.broadcast_to_room(&room_id, message, Some(self.connection_id)).await;

        Ok(())
    }

    /// Handle message reaction
    async fn handle_reaction(
        &mut self,
        message_id: String,
        emoji: String,
        _tx: &mpsc::UnboundedSender<ServerMessage>,
    ) -> Result<()> {
        let (room_id, user) = match (&self.connection.room_id, &self.connection.user) {
            (Some(room_id), Some(user)) => (room_id.clone(), user.clone()),
            _ => return Err(anyhow!("Not in a room")),
        };

        let message = ServerMessage::Reaction {
            messageId: message_id,
            user,
            emoji,
        };

        // Broadcast to all users in the room
        self.broadcast_to_room(&room_id, message, None).await;

        Ok(())
    }

    /// Leave the current room
    async fn leave_room(&mut self, room_id: String) {
        if let Some(user) = self.state.rooms.leave_room(&room_id, self.connection_id) {
            // Notify other users
            self.broadcast_to_room(
                &room_id,
                ServerMessage::UserLeft { 
                    payload: UserLeftPayload { user_id: user.id }
                },
                Some(self.connection_id),
            ).await;

            self.connection.leave_room();
            info!("Connection {} left room {}", self.connection_id, room_id);
        }
    }

    /// Broadcast a message to all users in a room
    async fn broadcast_to_room(
        &self,
        room_id: &str,
        message: ServerMessage,
        exclude_connection: Option<Uuid>,
    ) {
        let connections = self.state.rooms.get_room_connections(room_id, exclude_connection);
        
        debug!(
            "Broadcasting message to {} connections in room {}: {:?}",
            connections.len(),
            room_id,
            message
        );

        if !connections.is_empty() {
            self.state.connections.broadcast_to_connections(&connections, message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::UserInfo;

    #[test]
    fn test_connection_creation() {
        let connection_id = Uuid::new_v4();
        let ip = "127.0.0.1".parse().unwrap();
        let state = ServerState::new();
        
        let handler = WebSocketHandler::new(connection_id, ip, state);
        
        assert_eq!(handler.connection_id, connection_id);
        assert_eq!(handler.client_ip, ip);
        assert!(handler.connection.user.is_none());
        assert!(handler.connection.room_id.is_none());
    }
}
