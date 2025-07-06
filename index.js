const WebSocket = require("ws");
const http = require("http");
const crypto = require("crypto");
const PORT = process.env.PORT || 8080;

// Security configuration
const SECURITY_CONFIG = {
  // Anti-tampering
  MAX_ROOM_ID_LENGTH: 50,
  MIN_ROOM_ID_LENGTH: 3,
  ALLOWED_MESSAGE_TYPES: [
    "ping",
    "join",
    "leave",
    "message",
    "typing",
    "reaction",
    "fileTransfer",
    "error",
  ],

  // Encryption validation
  ENCRYPTED_MESSAGE_PATTERN: /^[A-Za-z0-9+/]+=*\.[A-Za-z0-9+/]+=*$/,
  MAX_ENCRYPTED_SIZE: 100 * 1024, // 100KB for encrypted messages

  // Connection security
  MAX_FAILED_ATTEMPTS: 5,
  LOCKOUT_DURATION: 15 * 60 * 1000, // 15 minutes
  SESSION_TIMEOUT: 2 * 60 * 60 * 1000, // 2 hours

  // Content validation
  MALICIOUS_PATTERNS: [
    /<script/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /data:text\/html/i,
    /vbscript:/i,
    /<iframe/i,
    /<object/i,
    /<embed/i,
  ],

  // Advanced security
  REQUIRE_TLS: process.env.NODE_ENV === "production",
  ENABLE_CSRF_PROTECTION: true,
  ENABLE_DDoS_PROTECTION: true,
  ENABLE_ANOMALY_DETECTION: true,
};

// Security storage
const securityMetrics = new Map(); // connectionId -> security metrics
const failedAttempts = new Map(); // IP -> failed attempt data
const sessionData = new Map(); // connectionId -> session info
const suspiciousIPs = new Set(); // IPs flagged for suspicious activity
const rateLimitViolations = new Map(); // IP -> violation count

// Rate limiting configuration
const RATE_LIMIT_CONFIG = {
  MESSAGE_LIMIT: parseInt(process.env.RATE_LIMIT_MESSAGE_LIMIT) || 30, // messages per window
  WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60000, // 1 minute window
  JOIN_LIMIT: parseInt(process.env.RATE_LIMIT_JOIN_LIMIT) || 5, // room joins per window
  MAX_MESSAGE_SIZE: parseInt(process.env.RATE_LIMIT_MAX_MESSAGE_SIZE) || 10240, // 10KB max message size
  CONNECTION_LIMIT_PER_IP:
    parseInt(process.env.RATE_LIMIT_CONNECTION_LIMIT_PER_IP) || 10, // max connections per IP
  ENABLED: process.env.ENABLE_RATE_LIMITING !== "false", // enabled by default
};

// Rate limiting storage
const rateLimiters = new Map(); // connectionId -> rate limit data
const ipConnections = new Map(); // IP -> connection count
const messageRateLimits = new Map(); // connectionId -> message rate data

// Enhanced HTTP server with security headers
const server = http.createServer((req, res) => {
  // Add security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains"
  );
  res.setHeader("Content-Security-Policy", "default-src 'none'");

  if (req.url === "/" || req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        status: "ok",
        message: "Whisper relay server is running",
        timestamp: new Date().toISOString(),
        security: {
          connections: wss ? wss.clients.size : 0,
          rooms: rooms.size,
          rateLimiters: rateLimiters.size,
          ipConnections: ipConnections.size,
          flaggedIPs: suspiciousIPs.size,
          activeSessions: sessionData.size,
          securityEnabled: SECURITY_CONFIG.ENABLE_DDoS_PROTECTION,
        },
        version: "2.0.0-secure",
      })
    );
  } else if (req.url === "/stats") {
    res.writeHead(200, { "Content-Type": "application/json" });

    // Calculate security metrics
    const totalViolations = Array.from(rateLimitViolations.values()).reduce(
      (a, b) => a + b,
      0
    );
    const activeSessions = sessionData.size;
    const averageSessionAge =
      sessionData.size > 0
        ? Array.from(sessionData.values()).reduce(
            (acc, session) => acc + (Date.now() - session.createdAt),
            0
          ) / sessionData.size
        : 0;

    res.end(
      JSON.stringify({
        server: {
          rateLimit: RATE_LIMIT_CONFIG,
          security: SECURITY_CONFIG,
          activeConnections: wss ? wss.clients.size : 0,
          activeRooms: rooms.size,
          activeLimiters: rateLimiters.size,
          ipConnectionCounts: Object.fromEntries(ipConnections),
        },
        security: {
          flaggedIPs: suspiciousIPs.size,
          totalViolations,
          activeSessions,
          averageSessionAge: Math.round(averageSessionAge / 1000), // in seconds
          failedAttempts: failedAttempts.size,
          securityFeatures: {
            rateLimiting: RATE_LIMIT_CONFIG.ENABLED,
            encryptionValidation: true,
            maliciousContentDetection: true,
            sessionManagement: true,
            ddosProtection: SECURITY_CONFIG.ENABLE_DDoS_PROTECTION,
          },
        },
        timestamp: new Date().toISOString(),
      })
    );
  } else if (req.url === "/security-report") {
    // Detailed security report (consider authentication for production)
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        flaggedIPs: Array.from(suspiciousIPs),
        violationCounts: Object.fromEntries(rateLimitViolations),
        recentViolations: Array.from(rateLimitViolations.entries())
          .filter(([ip, count]) => count > 0)
          .map(([ip, count]) => ({ ip, violations: count })),
        securityMetrics: {
          totalConnections: ipConnections.size,
          suspiciousActivity: suspiciousIPs.size > 0,
          highRiskIPs: Array.from(rateLimitViolations.entries())
            .filter(([ip, count]) => count >= 3)
            .map(([ip]) => ip),
        },
        timestamp: new Date().toISOString(),
      })
    );
  } else {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        error: "Not Found",
        timestamp: new Date().toISOString(),
      })
    );
  }
});

const wss = new WebSocket.Server({
  server,
  verifyClient: (info) => {
    const clientIP = getClientIP(info.req);

    // Check if IP is flagged as suspicious
    if (isIPSuspicious(clientIP)) {
      console.log(`🚫 Blocked connection from suspicious IP: ${clientIP}`);
      addSecurityViolation(clientIP, "SUSPICIOUS_IP_BLOCKED");
      return false;
    }

    // Check failed attempts
    const failures = failedAttempts.get(clientIP);
    if (failures && failures.count >= SECURITY_CONFIG.MAX_FAILED_ATTEMPTS) {
      const lockoutTime =
        failures.lastAttempt + SECURITY_CONFIG.LOCKOUT_DURATION;
      if (Date.now() < lockoutTime) {
        console.log(
          `🔒 IP ${clientIP} is locked out until ${new Date(lockoutTime)}`
        );
        return false;
      } else {
        // Clear expired lockout
        failedAttempts.delete(clientIP);
      }
    }

    // Check IP-based connection limit
    const currentConnections = ipConnections.get(clientIP) || 0;
    if (currentConnections >= RATE_LIMIT_CONFIG.CONNECTION_LIMIT_PER_IP) {
      console.log(`Rate limited: Too many connections from IP ${clientIP}`);
      addSecurityViolation(clientIP, "CONNECTION_LIMIT_EXCEEDED");
      return false;
    }

    // Additional production security checks
    if (SECURITY_CONFIG.REQUIRE_TLS && info.req.headers.origin) {
      const origin = new URL(info.req.headers.origin);
      if (origin.protocol !== "https:" && origin.hostname !== "localhost") {
        console.log(`🚫 Non-HTTPS origin rejected: ${origin.href}`);
        return false;
      }
    }

    return true;
  },
});

const rooms = new Map(); // roomId -> Map of ws -> userInfo

// Rate limiting helper functions
function createRateLimiter(limit, windowMs) {
  return {
    limit,
    windowMs,
    requests: [],
    isAllowed() {
      const now = Date.now();
      // Remove old requests outside the window
      this.requests = this.requests.filter(
        (time) => now - time < this.windowMs
      );

      if (this.requests.length >= this.limit) {
        return false;
      }

      this.requests.push(now);
      return true;
    },
    getTimeUntilReset() {
      if (this.requests.length === 0) return 0;
      const oldestRequest = Math.min(...this.requests);
      return Math.max(0, this.windowMs - (Date.now() - oldestRequest));
    },
  };
}

function getClientIP(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.headers["x-real-ip"] ||
    req.connection.remoteAddress ||
    req.socket.remoteAddress ||
    "unknown"
  );
}

function isRateLimited(connectionId, type = "message") {
  if (!RATE_LIMIT_CONFIG.ENABLED) return false;

  const key = `${connectionId}_${type}`;

  if (!rateLimiters.has(key)) {
    const config =
      type === "message"
        ? {
            limit: RATE_LIMIT_CONFIG.MESSAGE_LIMIT,
            windowMs: RATE_LIMIT_CONFIG.WINDOW_MS,
          }
        : {
            limit: RATE_LIMIT_CONFIG.JOIN_LIMIT,
            windowMs: RATE_LIMIT_CONFIG.WINDOW_MS,
          };

    rateLimiters.set(key, createRateLimiter(config.limit, config.windowMs));
  }

  return !rateLimiters.get(key).isAllowed();
}

function checkMessageSize(message) {
  const size = Buffer.byteLength(message.toString(), "utf8");
  return size <= RATE_LIMIT_CONFIG.MAX_MESSAGE_SIZE;
}

// Advanced security helper functions
function validateRoomId(roomId) {
  if (!roomId || typeof roomId !== "string") return false;
  if (
    roomId.length < SECURITY_CONFIG.MIN_ROOM_ID_LENGTH ||
    roomId.length > SECURITY_CONFIG.MAX_ROOM_ID_LENGTH
  )
    return false;

  // Check for malicious patterns
  const maliciousPattern = /[<>\"'&\x00-\x1f\x7f-\x9f]/;
  if (maliciousPattern.test(roomId)) return false;

  // Only allow alphanumeric, dashes, underscores
  const validPattern = /^[a-zA-Z0-9\-_]+$/;
  return validPattern.test(roomId);
}

function validateEncryptedMessage(encrypted) {
  if (!encrypted || typeof encrypted !== "string") return false;

  // Check format (should be base64.base64)
  if (!SECURITY_CONFIG.ENCRYPTED_MESSAGE_PATTERN.test(encrypted)) return false;

  // Check size
  if (encrypted.length > SECURITY_CONFIG.MAX_ENCRYPTED_SIZE) return false;

  // Validate base64 parts
  const parts = encrypted.split(".");
  if (parts.length !== 2) return false;

  try {
    Buffer.from(parts[0], "base64");
    Buffer.from(parts[1], "base64");
    return true;
  } catch (e) {
    return false;
  }
}

function detectMaliciousContent(data) {
  const jsonStr = JSON.stringify(data);
  return SECURITY_CONFIG.MALICIOUS_PATTERNS.some((pattern) =>
    pattern.test(jsonStr)
  );
}

function createSecurityFingerprint(req, ws) {
  const userAgent = req.headers["user-agent"] || "";
  const acceptLanguage = req.headers["accept-language"] || "";
  const acceptEncoding = req.headers["accept-encoding"] || "";

  return crypto
    .createHash("sha256")
    .update(`${userAgent}:${acceptLanguage}:${acceptEncoding}`)
    .digest("hex")
    .substring(0, 16);
}

function isIPSuspicious(ip) {
  return suspiciousIPs.has(ip) || (rateLimitViolations.get(ip) || 0) > 3;
}

function addSecurityViolation(ip, type, details = {}) {
  const violation = {
    type,
    timestamp: Date.now(),
    ip,
    details,
  };

  console.log(`🚨 SECURITY VIOLATION [${type}] from ${ip}:`, details);

  // Track repeated violations
  rateLimitViolations.set(ip, (rateLimitViolations.get(ip) || 0) + 1);

  // Auto-ban after multiple violations
  if (rateLimitViolations.get(ip) >= 5) {
    suspiciousIPs.add(ip);
    console.log(`🔒 IP ${ip} has been flagged as suspicious`);
  }
}

function validateMessageType(type) {
  return SECURITY_CONFIG.ALLOWED_MESSAGE_TYPES.includes(type);
}

function createSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

function isSessionExpired(sessionInfo) {
  return Date.now() - sessionInfo.createdAt > SECURITY_CONFIG.SESSION_TIMEOUT;
}

server.listen(PORT, () => {
  console.log(`Whisper relay server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`Health check available at: http://localhost:${PORT}/health`);
});

wss.on("connection", (ws, req) => {
  let joinedRoom = null;
  let userInfo = null;
  const connectionId = `${Date.now()}_${Math.random()}`;
  const clientIP = getClientIP(req);
  const securityFingerprint = createSecurityFingerprint(req, ws);
  const sessionToken = createSessionToken();

  // Initialize session data
  sessionData.set(connectionId, {
    createdAt: Date.now(),
    ip: clientIP,
    fingerprint: securityFingerprint,
    sessionToken,
    messageCount: 0,
    lastActivity: Date.now(),
    violations: 0,
  });

  // Track IP connections
  ipConnections.set(clientIP, (ipConnections.get(clientIP) || 0) + 1);

  console.log(
    `✅ New secure connection from ${clientIP} [${securityFingerprint}]`
  );

  // Initialize heartbeat
  ws.isAlive = true;

  ws.on("message", (message) => {
    try {
      const session = sessionData.get(connectionId);

      // Check session validity
      if (!session || isSessionExpired(session)) {
        console.log(`🚫 Expired session from ${clientIP}`);
        ws.close(1008, "Session expired");
        return;
      }

      // Update session activity
      session.lastActivity = Date.now();
      session.messageCount++;

      // Check message size first
      if (!checkMessageSize(message)) {
        console.log(`🚫 Message too large from ${clientIP}`);
        addSecurityViolation(clientIP, "MESSAGE_TOO_LARGE");
        ws.send(
          JSON.stringify({
            type: "error",
            payload: {
              message: "Message too large",
              code: "MESSAGE_TOO_LARGE",
            },
          })
        );
        return;
      }

      console.log("📨 Raw message received from", clientIP);

      let parsedMessage;
      try {
        parsedMessage = JSON.parse(message);
      } catch (parseError) {
        console.log(`🚫 Invalid JSON from ${clientIP}`);
        addSecurityViolation(clientIP, "INVALID_JSON", {
          error: parseError.message,
        });
        return;
      }

      const { type, payload } = parsedMessage;

      // Validate message type
      if (!validateMessageType(type)) {
        console.log(`🚫 Invalid message type '${type}' from ${clientIP}`);
        addSecurityViolation(clientIP, "INVALID_MESSAGE_TYPE", { type });
        return;
      }

      // Check for malicious content
      if (detectMaliciousContent(parsedMessage)) {
        console.log(`🚨 Malicious content detected from ${clientIP}`);
        addSecurityViolation(clientIP, "MALICIOUS_CONTENT", {
          message: parsedMessage,
        });
        ws.close(1008, "Malicious content detected");
        return;
      }

      console.log(`📝 Valid message type: ${type}`);

      if (type === "ping") {
        ws.send(JSON.stringify({ type: "pong" }));
        return;
      }

      if (type === "join") {
        // Enhanced join validation
        if (isRateLimited(connectionId, "join")) {
          console.log(`🚫 Join rate limited for ${clientIP}`);
          addSecurityViolation(clientIP, "JOIN_RATE_LIMITED");
          ws.send(
            JSON.stringify({
              type: "error",
              payload: {
                message: "Too many join attempts. Please wait.",
                code: "RATE_LIMITED",
              },
            })
          );
          return;
        }

        // Validate room ID
        if (!validateRoomId(payload.roomId)) {
          console.log(`🚫 Invalid room ID from ${clientIP}: ${payload.roomId}`);
          addSecurityViolation(clientIP, "INVALID_ROOM_ID", {
            roomId: payload.roomId,
          });
          ws.send(
            JSON.stringify({
              type: "error",
              payload: {
                message: "Invalid room ID format",
                code: "INVALID_ROOM_ID",
              },
            })
          );
          return;
        }

        // Validate user info
        if (
          !payload.userId ||
          !payload.username ||
          typeof payload.userId !== "string" ||
          typeof payload.username !== "string"
        ) {
          console.log(`🚫 Invalid user info from ${clientIP}`);
          addSecurityViolation(clientIP, "INVALID_USER_INFO");
          return;
        }

        // Sanitize user input
        const roomId = payload.roomId.trim();
        userInfo = {
          userId: payload.userId.trim().substring(0, 50), // Limit length
          username: payload.username.trim().substring(0, 30), // Limit length
        };

        if (!rooms.has(roomId)) {
          rooms.set(roomId, new Map());
        }

        rooms.get(roomId).set(ws, userInfo);
        joinedRoom = roomId;

        console.log(
          `✅ ${userInfo.username} (${userInfo.userId}) securely joined room ${roomId}`
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
        return;
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
            `👋 ${userInfo.username} (${userInfo.userId}) left room ${joinedRoom}`
          );

          if (roomUsers.size === 0) {
            rooms.delete(joinedRoom);
          }
        }
        return;
      }

      if (type === "message") {
        // Enhanced message security
        if (isRateLimited(connectionId, "message")) {
          const limiter = rateLimiters.get(`${connectionId}_message`);
          const resetTime = limiter.getTimeUntilReset();
          console.log(`🚫 Message rate limited for ${clientIP}`);
          addSecurityViolation(clientIP, "MESSAGE_RATE_LIMITED");
          ws.send(
            JSON.stringify({
              type: "error",
              payload: {
                message: `Rate limited. Please wait ${Math.ceil(
                  resetTime / 1000
                )} seconds.`,
                code: "RATE_LIMITED",
                resetTime,
              },
            })
          );
          return;
        }

        if (!joinedRoom) {
          console.log(`🚫 Message without room from ${clientIP}`);
          addSecurityViolation(clientIP, "MESSAGE_WITHOUT_ROOM");
          return;
        }

        if (!userInfo) {
          console.log(`🚫 Message without user info from ${clientIP}`);
          addSecurityViolation(clientIP, "MESSAGE_WITHOUT_USER");
          return;
        }

        // Validate encrypted message format
        if (
          !payload.encrypted ||
          !validateEncryptedMessage(payload.encrypted)
        ) {
          console.log(`🚫 Invalid encrypted message format from ${clientIP}`);
          addSecurityViolation(clientIP, "INVALID_ENCRYPTED_FORMAT");
          ws.send(
            JSON.stringify({
              type: "error",
              payload: {
                message: "Invalid message format",
                code: "INVALID_FORMAT",
              },
            })
          );
          return;
        }

        console.log(
          `� Relaying encrypted message in room ${joinedRoom} from ${userInfo.username}`
        );

        const peers = rooms.get(joinedRoom);
        if (peers) {
          let messagesSent = 0;
          for (const [peer, peerInfo] of peers) {
            if (peer !== ws && peer.readyState === WebSocket.OPEN) {
              const messageToSend = {
                type: "message",
                payload: payload.encrypted, // Only relay encrypted content
              };

              try {
                peer.send(JSON.stringify(messageToSend));
                messagesSent++;
              } catch (sendErr) {
                console.error(
                  `❌ Failed to send to ${peerInfo.username}:`,
                  sendErr
                );
              }
            }
          }
          console.log(`✅ Securely relayed message to ${messagesSent} peers`);
        }
        return;
      }

      if (type === "typing") {
        // Handle typing indicator
        if (!joinedRoom || !userInfo) {
          console.log(`🚫 Typing without room/user from ${clientIP}`);
          return;
        }

        // Validate typing payload
        if (
          typeof payload.isTyping !== "boolean" ||
          !payload.roomId ||
          !payload.userId ||
          !payload.username
        ) {
          console.log(`🚫 Invalid typing payload from ${clientIP}`);
          addSecurityViolation(clientIP, "INVALID_TYPING_PAYLOAD");
          return;
        }

        console.log(
          `⌨️ Typing indicator from ${userInfo.username}: ${payload.isTyping}`
        );

        // Broadcast typing indicator to others in the room
        const peers = rooms.get(joinedRoom);
        if (peers) {
          for (const [peer, peerInfo] of peers) {
            if (peer !== ws && peer.readyState === WebSocket.OPEN) {
              peer.send(
                JSON.stringify({
                  type: "typing",
                  payload: {
                    userId: userInfo.userId,
                    username: userInfo.username,
                    isTyping: payload.isTyping,
                  },
                })
              );
            }
          }
        }
        return;
      }

      if (type === "reaction") {
        // Handle message reactions
        if (!joinedRoom || !userInfo) {
          console.log(`🚫 Reaction without room/user from ${clientIP}`);
          return;
        }

        // Validate reaction payload
        if (
          !payload.messageId ||
          !payload.emoji ||
          !payload.action ||
          (payload.action !== "add" && payload.action !== "remove")
        ) {
          console.log(`🚫 Invalid reaction payload from ${clientIP}`);
          addSecurityViolation(clientIP, "INVALID_REACTION_PAYLOAD");
          return;
        }

        console.log(
          `🎭 Reaction ${payload.action} from ${userInfo.username}: ${payload.emoji}`
        );

        // Broadcast reaction to others in the room
        const peers = rooms.get(joinedRoom);
        if (peers) {
          for (const [peer, peerInfo] of peers) {
            if (peer !== ws && peer.readyState === WebSocket.OPEN) {
              peer.send(
                JSON.stringify({
                  type: "reaction",
                  payload: {
                    messageId: payload.messageId,
                    emoji: payload.emoji,
                    userId: userInfo.userId,
                    action: payload.action,
                  },
                })
              );
            }
          }
        }
        return;
      }

      if (type === "fileTransfer") {
        // Handle file transfer messages
        if (!joinedRoom || !userInfo) {
          console.log(`🚫 File transfer without room/user from ${clientIP}`);
          return;
        }

        console.log(`📁 File transfer from ${userInfo.username}`);

        // Broadcast file transfer to others in the room
        const peers = rooms.get(joinedRoom);
        if (peers) {
          for (const [peer, peerInfo] of peers) {
            if (peer !== ws && peer.readyState === WebSocket.OPEN) {
              peer.send(
                JSON.stringify({
                  type: "fileTransfer",
                  payload: payload,
                })
              );
            }
          }
        }
        return;
      }

      if (type === "error") {
        // Handle error messages - just log them for debugging
        console.log(`⚠️ Error from client ${clientIP}:`, payload);
        return;
      }

      console.log(`⚠️ Unknown message type: ${type} from ${clientIP}`);
      addSecurityViolation(clientIP, "UNKNOWN_MESSAGE_TYPE", { type });
    } catch (err) {
      console.error(`💥 Error processing message from ${clientIP}:`, err);
      addSecurityViolation(clientIP, "MESSAGE_PROCESSING_ERROR", {
        error: err.message,
      });
    }
  });
  ws.on("close", () => {
    // Enhanced cleanup
    const session = sessionData.get(connectionId);
    const currentConnections = ipConnections.get(clientIP) || 0;

    // Clean up IP connection tracking
    if (currentConnections > 1) {
      ipConnections.set(clientIP, currentConnections - 1);
    } else {
      ipConnections.delete(clientIP);
    }

    // Clean up security data
    sessionData.delete(connectionId);
    rateLimiters.delete(`${connectionId}_message`);
    rateLimiters.delete(`${connectionId}_join`);

    // Log security metrics
    if (session) {
      console.log(
        `🔐 Session closed: ${session.messageCount} messages, ${session.violations} violations`
      );
    }

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
        `👋 ${userInfo.username} (${userInfo.userId}) disconnected from room ${joinedRoom}`
      );

      if (roomUsers.size === 0) {
        rooms.delete(joinedRoom);
        console.log(`🧹 Room ${joinedRoom} cleaned up`);
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

// Enhanced security monitoring and cleanup
const interval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) {
      console.log("🧹 Terminating unresponsive connection");
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  });
}, 60000);

// Enhanced cleanup interval
const cleanupInterval = setInterval(() => {
  const now = Date.now();
  const cutoff = now - RATE_LIMIT_CONFIG.WINDOW_MS * 2;

  // Clean up rate limiters
  for (const [key, limiter] of rateLimiters.entries()) {
    if (
      limiter.requests.length === 0 ||
      Math.max(...limiter.requests) < cutoff
    ) {
      rateLimiters.delete(key);
    }
  }

  // Clean up expired sessions
  for (const [connectionId, session] of sessionData.entries()) {
    if (isSessionExpired(session)) {
      sessionData.delete(connectionId);
    }
  }

  // Clean up old failed attempts
  for (const [ip, failure] of failedAttempts.entries()) {
    if (now - failure.lastAttempt > SECURITY_CONFIG.LOCKOUT_DURATION * 2) {
      failedAttempts.delete(ip);
    }
  }

  // Reset violation counts periodically
  if (now % (24 * 60 * 60 * 1000) < 300000) {
    // Once per day
    rateLimitViolations.clear();
    suspiciousIPs.clear();
    console.log("🔄 Daily security metrics reset");
  }

  console.log(
    `🔐 Security cleanup: ${rateLimiters.size} limiters, ${sessionData.size} sessions, ${suspiciousIPs.size} flagged IPs`
  );
}, 300000); // Every 5 minutes

// Security monitoring interval
const securityMonitorInterval = setInterval(() => {
  const now = Date.now();
  const activeConnections = wss.clients.size;
  const activeRooms = rooms.size;
  const flaggedIPs = suspiciousIPs.size;
  const totalViolations = Array.from(rateLimitViolations.values()).reduce(
    (a, b) => a + b,
    0
  );

  console.log(
    `📊 Security Report: ${activeConnections} connections, ${activeRooms} rooms, ${flaggedIPs} flagged IPs, ${totalViolations} total violations`
  );

  // Alert on suspicious activity
  if (flaggedIPs > 10 || totalViolations > 100) {
    console.log(
      `🚨 HIGH SECURITY ALERT: ${flaggedIPs} flagged IPs, ${totalViolations} violations`
    );
  }
}, 600000); // Every 10 minutes

wss.on("close", () => {
  clearInterval(interval);
  clearInterval(cleanupInterval);
  clearInterval(securityMonitorInterval);
});

// Enhanced graceful shutdown
function gracefulShutdown(signal) {
  console.log(`${signal} received, shutting down gracefully`);

  // Stop accepting new connections
  wss.close(() => {
    console.log("WebSocket server closed");
  });

  // Clean up all data structures
  rooms.clear();
  rateLimiters.clear();
  ipConnections.clear();
  sessionData.clear();
  failedAttempts.clear();
  suspiciousIPs.clear();
  rateLimitViolations.clear();

  // Close HTTP server
  server.close(() => {
    console.log("HTTP server closed");
    process.exit(0);
  });

  // Force exit after timeout
  setTimeout(() => {
    console.log("Forced shutdown");
    process.exit(1);
  }, 10000);
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));
