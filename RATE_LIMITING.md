# Rate Limiting in Whisper Relay Server

This document describes the rate limiting features implemented in the Whisper relay server to protect against abuse and ensure fair usage.

## Rate Limiting Features

### 1. **Message Rate Limiting**

- **Default Limit**: 30 messages per minute per connection
- **Purpose**: Prevents message spam and reduces server load
- **Response**: Returns error with `RATE_LIMITED` code and reset time

### 2. **Room Join Rate Limiting**

- **Default Limit**: 5 room joins per minute per connection
- **Purpose**: Prevents rapid room hopping and potential abuse
- **Response**: Returns error with `RATE_LIMITED` code

### 3. **Connection Limiting per IP**

- **Default Limit**: 10 concurrent connections per IP address
- **Purpose**: Prevents a single IP from consuming too many resources
- **Response**: Connection refused during WebSocket handshake

### 4. **Message Size Limiting**

- **Default Limit**: 10KB (10,240 bytes) per message
- **Purpose**: Prevents large message attacks and bandwidth abuse
- **Response**: Returns error with `MESSAGE_TOO_LARGE` code

## Configuration

### Environment Variables

You can configure rate limiting using these environment variables:

```bash
# Rate Limiting Configuration
RATE_LIMIT_MESSAGE_LIMIT=30          # Messages per minute per connection
RATE_LIMIT_WINDOW_MS=60000           # Rate limit window in milliseconds (1 minute)
RATE_LIMIT_JOIN_LIMIT=5              # Room joins per minute per connection
RATE_LIMIT_MAX_MESSAGE_SIZE=10240    # Maximum message size in bytes
RATE_LIMIT_CONNECTION_LIMIT_PER_IP=10 # Max concurrent connections per IP
ENABLE_RATE_LIMITING=true            # Enable/disable rate limiting
```

### Default Values

If no environment variables are set, the following defaults are used:

- **Message Limit**: 30 per minute
- **Join Limit**: 5 per minute
- **Max Message Size**: 10KB
- **Connections per IP**: 10
- **Rate Limiting**: Enabled

## Error Responses

### Rate Limited Message

```json
{
  "type": "error",
  "payload": {
    "message": "Rate limited. Please wait 45 seconds.",
    "code": "RATE_LIMITED",
    "resetTime": 45000
  }
}
```

### Message Too Large

```json
{
  "type": "error",
  "payload": {
    "message": "Message too large",
    "code": "MESSAGE_TOO_LARGE"
  }
}
```

## Monitoring

### Health Check Endpoint

`GET /health` returns server status including rate limiting metrics:

```json
{
  "status": "ok",
  "message": "Whisper relay server is running",
  "timestamp": "2025-07-05T12:00:00.000Z",
  "connections": 25,
  "rooms": 8,
  "rateLimiters": 50,
  "ipConnections": 15
}
```

### Stats Endpoint

`GET /stats` returns detailed rate limiting statistics:

```json
{
  "rateLimit": {
    "MESSAGE_LIMIT": 30,
    "WINDOW_MS": 60000,
    "JOIN_LIMIT": 5,
    "MAX_MESSAGE_SIZE": 10240,
    "CONNECTION_LIMIT_PER_IP": 10,
    "ENABLED": true
  },
  "activeConnections": 25,
  "activeRooms": 8,
  "activeLimiters": 50,
  "ipConnectionCounts": {
    "192.168.1.100": 3,
    "10.0.0.50": 2
  },
  "timestamp": "2025-07-05T12:00:00.000Z"
}
```

## Implementation Details

### Sliding Window Algorithm

The rate limiter uses a sliding window algorithm that:

1. Tracks timestamps of recent requests
2. Removes expired timestamps outside the window
3. Allows requests if under the limit, otherwise rejects

### Memory Management

- **Automatic Cleanup**: Rate limiters are cleaned up every 5 minutes
- **Connection Tracking**: IP connection counts are cleaned when connections close
- **Memory Efficient**: Only active rate limiters are kept in memory

### Production Considerations

1. **Proxy Compatibility**: The server correctly identifies client IPs behind proxies using:

   - `X-Forwarded-For` header
   - `X-Real-IP` header
   - Connection remote address

2. **Graceful Degradation**: If rate limiting is disabled, the server continues to function normally

3. **Logging**: Rate limit violations are logged for monitoring and debugging

## Customization

### Adjusting Limits for Different Environments

#### Development

```bash
RATE_LIMIT_MESSAGE_LIMIT=100
RATE_LIMIT_CONNECTION_LIMIT_PER_IP=50
```

#### Production (Strict)

```bash
RATE_LIMIT_MESSAGE_LIMIT=15
RATE_LIMIT_JOIN_LIMIT=3
RATE_LIMIT_CONNECTION_LIMIT_PER_IP=5
```

### Disabling Rate Limiting

```bash
ENABLE_RATE_LIMITING=false
```

## Best Practices

1. **Monitor Usage**: Regularly check `/stats` endpoint to understand usage patterns
2. **Adjust Limits**: Tune limits based on actual usage and server capacity
3. **Log Analysis**: Monitor logs for rate limiting violations to detect abuse
4. **Client Handling**: Ensure clients properly handle rate limit errors and respect retry delays

## Troubleshooting

### Common Issues

1. **Legitimate Users Hit Limits**: Increase `MESSAGE_LIMIT` or `JOIN_LIMIT`
2. **Server Under Load**: Decrease limits or add more server capacity
3. **False Positives**: Check if multiple users share the same IP (corporate networks)

### Debugging

Enable detailed logging to see rate limiting decisions:

```bash
LOG_RATE_LIMIT_VIOLATIONS=true
```

This will log when rate limits are triggered and which IPs are affected.
