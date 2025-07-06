use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{error, info, warn};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;
use warp::Filter;

mod types;
mod security;
mod rate_limiter;
mod room;
mod websocket_handler;
mod connection_manager;

use crate::types::*;
use crate::security::SecurityManager;
use crate::rate_limiter::RateLimiterManager;
use crate::room::RoomManager;
use crate::websocket_handler::WebSocketHandler;
use crate::connection_manager::ConnectionManager;

/// Global server state
#[derive(Clone)]
pub struct ServerState {
    pub rooms: Arc<RoomManager>,
    pub security: Arc<SecurityManager>,
    pub rate_limiter: Arc<RateLimiterManager>,
    pub connections: Arc<ConnectionManager>,
    pub connection_count: Arc<AtomicUsize>,
    pub start_time: DateTime<Utc>,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            rooms: Arc::new(RoomManager::new()),
            security: Arc::new(SecurityManager::new()),
            rate_limiter: Arc::new(RateLimiterManager::new()),
            connections: Arc::new(ConnectionManager::new()),
            connection_count: Arc::new(AtomicUsize::new(0)),
            start_time: Utc::now(),
        }
    }

    pub fn get_stats(&self) -> ServerStats {
        ServerStats {
            uptime_seconds: (Utc::now() - self.start_time).num_seconds(),
            active_connections: self.connection_count.load(Ordering::Relaxed),
            active_rooms: self.rooms.get_room_count(),
            total_users: self.rooms.get_total_user_count(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    // Load environment variables
    dotenv::dotenv().ok();
    
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or(8080);
    
    info!("Starting Whisper WebSocket Relay Server v1.0.0");
    info!("Environment: {}", std::env::var("NODE_ENV").unwrap_or_else(|_| "development".to_string()));
    
    // Initialize server state
    let state = ServerState::new();
    
    // Health check endpoint
    let health = warp::path::end()
        .or(warp::path("health"))
        .and_then({
            let state = state.clone();
            move |_| {
                let state = state.clone();
                async move {
                    let stats = state.get_stats();
                    Ok::<_, warp::Rejection>(warp::reply::json(&HealthResponse {
                        status: "healthy".to_string(),
                        timestamp: Utc::now(),
                        stats,
                    }))
                }
            }
        });
    
    // WebSocket upgrade endpoint
    let websocket = warp::path("ws")
        .and(warp::ws())
        .and(warp::addr::remote())
        .and_then({
            let state = state.clone();
            move |ws: warp::ws::Ws, addr: Option<SocketAddr>| {
                let state = state.clone();
                async move {
                    let client_ip = addr.map(|a| a.ip()).unwrap_or_else(|| "unknown".parse().unwrap());
                    
                    // Check connection limits
                    if !state.security.can_connect(client_ip).await {
                        warn!("Connection refused from {}: too many connections", client_ip);
                        return Err(warp::reject::custom(ConnectionLimitExceeded));
                    }
                    
                    Ok(ws.on_upgrade(move |socket| {
                        handle_websocket(socket, state, client_ip)
                    }))
                }
            }
        });
    
    let routes = health.or(websocket);
    
    info!("Server listening on port {}", port);
    
    warp::serve(routes)
        .run(([0, 0, 0, 0], port))
        .await;
    
    Ok(())
}

async fn handle_websocket(
    ws: warp::ws::WebSocket,
    state: ServerState,
    client_ip: std::net::IpAddr,
) {
    let connection_id = Uuid::new_v4();
    state.connection_count.fetch_add(1, Ordering::Relaxed);
    
    info!("New WebSocket connection: {} from {}", connection_id, client_ip);
    
    let handler = WebSocketHandler::new(connection_id, client_ip, state.clone());
    
    if let Err(e) = handler.handle(ws).await {
        error!("WebSocket handler error for {}: {}", connection_id, e);
    }
    
    state.connection_count.fetch_sub(1, Ordering::Relaxed);
    info!("WebSocket connection closed: {}", connection_id);
}

#[derive(Debug)]
struct ConnectionLimitExceeded;
impl warp::reject::Reject for ConnectionLimitExceeded {}