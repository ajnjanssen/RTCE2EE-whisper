const WebSocket = require("ws");
const http = require("http");
const PORT = process.env.PORT || 8080;

// Create HTTP server for health checks
const server = http.createServer((req, res) => {
  if (req.url === "/" || req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        status: "ok",
        message: "Whisper relay server is running",
        timestamp: new Date().toISOString(),
        connections: wss ? wss.clients.size : 0,
      })
    );
  } else {
    res.writeHead(404);
    res.end("Not Found");
  }
});

const wss = new WebSocket.Server({
  server,
  // Add CORS headers for production
  verifyClient: (info) => {
    // Allow all origins in development, restrict in production if needed
    return true;
  },
});

const rooms = new Map(); // roomId -> Map of ws -> userInfo

server.listen(PORT, () => {
  console.log(`Whisper relay server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`Health check available at: http://localhost:${PORT}/health`);
});

wss.on("connection", (ws) => {
  let joinedRoom = null;
  let userInfo = null;

  // Initialize heartbeat
  ws.isAlive = true;

  ws.on("message", (message) => {
    try {
      console.log("Raw message received:", message.toString());
      const { type, payload } = JSON.parse(message);
      console.log("Parsed message:", { type, payload });

      if (type === "join") {
        const roomId = payload.roomId;
        userInfo = {
          userId: payload.userId,
          username: payload.username,
        };

        if (!rooms.has(roomId)) {
          rooms.set(roomId, new Map());
        }

        rooms.get(roomId).set(ws, userInfo);
        joinedRoom = roomId;

        console.log(
          `${userInfo.username} (${userInfo.userId}) joined room ${roomId}`
        );

        // Broadcast user joined to others in the room
        const peers = rooms.get(roomId);
        for (const [peer, peerInfo] of peers) {
          if (peer !== ws && peer.readyState === WebSocket.OPEN) {
            peer.send(
              JSON.stringify({
                type: "userJoined",
                payload: {
                  userId: userInfo.userId,
                  username: userInfo.username,
                },
              })
            );
          }
        }

        // Send current user list to the newly joined user (excluding themselves)
        const userList = Array.from(peers.values())
          .filter((info) => info.userId !== userInfo.userId)
          .map((info) => ({
            id: info.userId,
            name: info.username,
          }));

        ws.send(
          JSON.stringify({
            type: "userList",
            payload: { users: userList },
          })
        );
      }

      if (type === "leave") {
        if (joinedRoom && rooms.has(joinedRoom) && userInfo) {
          const roomUsers = rooms.get(joinedRoom);
          roomUsers.delete(ws);

          // Broadcast user left to others in the room
          for (const [peer, peerInfo] of roomUsers) {
            if (peer.readyState === WebSocket.OPEN) {
              peer.send(
                JSON.stringify({
                  type: "userLeft",
                  payload: {
                    userId: userInfo.userId,
                  },
                })
              );
            }
          }

          console.log(
            `${userInfo.username} (${userInfo.userId}) left room ${joinedRoom}`
          );

          if (roomUsers.size === 0) {
            rooms.delete(joinedRoom);
          }
        }
      }

      if (type === "message" && joinedRoom) {
        console.log(
          `Broadcasting message in room ${joinedRoom} from ${userInfo.username}`
        );
        const peers = rooms.get(joinedRoom);
        if (peers) {
          for (const [peer, peerInfo] of peers) {
            if (peer !== ws && peer.readyState === WebSocket.OPEN) {
              console.log(
                `Sending message to ${peerInfo.username} (${peerInfo.userId})`
              );
              peer.send(
                JSON.stringify({
                  type: "message",
                  payload: payload.encrypted,
                })
              );
            }
          }
        }
      }
    } catch (err) {
      console.error("Invalid message format", err);
    }
  });

  ws.on("close", () => {
    if (joinedRoom && rooms.has(joinedRoom) && userInfo) {
      const roomUsers = rooms.get(joinedRoom);
      roomUsers.delete(ws);

      // Broadcast user left to others in the room
      for (const [peer, peerInfo] of roomUsers) {
        if (peer.readyState === WebSocket.OPEN) {
          peer.send(
            JSON.stringify({
              type: "userLeft",
              payload: {
                userId: userInfo.userId,
              },
            })
          );
        }
      }

      console.log(
        `${userInfo.username} (${userInfo.userId}) disconnected from room ${joinedRoom}`
      );

      if (roomUsers.size === 0) {
        rooms.delete(joinedRoom);
      }
    }
  });

  // Add error handling for production
  ws.on("error", (error) => {
    console.error("WebSocket error:", error);
  });

  ws.on("pong", () => {
    ws.isAlive = true;
  });
});

// Add heartbeat to detect broken connections (increased interval for production)
const interval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) {
      console.log("Terminating unresponsive connection");
      return ws.terminate();
    }

    ws.isAlive = false;
    ws.ping();
  });
}, 60000); // Increased to 60 seconds for better stability on Render

wss.on("close", () => {
  clearInterval(interval);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down gracefully");
  server.close(() => {
    console.log("HTTP server closed");
    process.exit(0);
  });
});

process.on("SIGINT", () => {
  console.log("SIGINT received, shutting down gracefully");
  server.close(() => {
    console.log("HTTP server closed");
    process.exit(0);
  });
});
