# Security Testing Guide for RTC-E2EE

This guide provides comprehensive security testing procedures to validate the security measures implemented in the RTC-E2EE application.

## 🧪 Security Test Categories

### 1. **Rate Limiting Tests**

#### Message Rate Limiting

```bash
# Test message spam protection
# Send 35 messages rapidly (should trigger rate limit at 30)
for i in {1..35}; do
  echo "Sending message $i"
  # Use WebSocket client to send messages rapidly
done
```

#### Connection Rate Limiting

```bash
# Test connection flooding from single IP
# Attempt 15 concurrent connections (should block at 10)
for i in {1..15}; do
  wscat -c ws://localhost:8080 &
done
```

#### Join Rate Limiting

```bash
# Test rapid room joining
# Attempt 8 room joins in quick succession (should block at 5)
```

### 2. **Input Validation Tests**

#### Malicious Room ID Tests

```javascript
// Test various malicious room IDs
const maliciousRoomIds = [
  '<script>alert("xss")</script>',
  "javascript:alert(1)",
  'room"onload="alert(1)"',
  "../../../etc/passwd",
  "room\x00null",
  "a".repeat(100), // Too long
  "", // Empty
  null,
  undefined,
];

maliciousRoomIds.forEach((roomId) => {
  // Send join message with malicious room ID
  ws.send(
    JSON.stringify({
      type: "join",
      payload: { roomId, userId: "test", username: "test" },
    })
  );
});
```

#### Malicious Message Content Tests

```javascript
// Test XSS and injection attempts
const maliciousMessages = [
  '<script>document.cookie="stolen"</script>',
  'javascript:alert("xss")',
  '<iframe src="javascript:alert(1)"></iframe>',
  '<object data="data:text/html,<script>alert(1)</script>"></object>',
  'on" onerror="alert(1)" "',
  "data:text/html,<script>alert(1)</script>",
];

maliciousMessages.forEach((content) => {
  // Test each malicious payload
  ws.send(
    JSON.stringify({
      type: "message",
      payload: { encrypted: btoa(content) + "." + btoa("test") },
    })
  );
});
```

### 3. **Encryption Security Tests**

#### Invalid Encrypted Format Tests

```javascript
// Test various invalid encrypted message formats
const invalidFormats = [
  "not-base64",
  "missing.second.part",
  "onlyonepart",
  "",
  null,
  "invalidbase64!@#$",
  "a".repeat(200000), // Too large
  "validbase64.", // Missing second part
  ".validbase64", // Missing first part
];

invalidFormats.forEach((encrypted) => {
  ws.send(
    JSON.stringify({
      type: "message",
      payload: { encrypted },
    })
  );
});
```

#### Encryption Validation Tests

```javascript
// Test client-side encryption validation
const testCases = [
  { text: "<script>alert(1)</script>", shouldFail: true },
  { text: "normal message", shouldFail: false },
  { text: "a".repeat(60000), shouldFail: true }, // Too large
  { roomId: "<script>", shouldFail: true },
  { roomId: "valid-room-123", shouldFail: false },
  { passphrase: "", shouldFail: true },
  { passphrase: "a".repeat(2000), shouldFail: true },
];
```

### 4. **Session Security Tests**

#### Session Expiration Tests

```bash
# Test session timeout (2 hours default)
# 1. Connect and get session
# 2. Wait for session timeout
# 3. Attempt to send message (should fail)
```

#### Session Hijacking Tests

```javascript
// Test session validation
// 1. Capture session fingerprint
// 2. Attempt to use from different "device"
// 3. Should detect and reject
```

### 5. **DDoS Protection Tests**

#### Connection Flooding

```bash
# Test connection flood protection
# Launch multiple connection attempts from same IP
for i in {1..20}; do
  (wscat -c ws://localhost:8080 &)
done
```

#### Message Flooding

```javascript
// Test message flood protection
const messages = Array(100)
  .fill()
  .map((_, i) => ({
    type: "message",
    payload: { encrypted: btoa(`spam ${i}`) + "." + btoa("test") },
  }));

// Send all messages rapidly
messages.forEach((msg) => ws.send(JSON.stringify(msg)));
```

### 6. **Security Header Tests**

#### HTTP Security Headers

```bash
# Test security headers
curl -I http://localhost:8080/health

# Should include:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# X-XSS-Protection: 1; mode=block
# Strict-Transport-Security: max-age=31536000; includeSubDomains
# Content-Security-Policy: default-src 'none'
```

### 7. **Error Handling Tests**

#### Malformed JSON Tests

```javascript
// Test various malformed JSON payloads
const malformedJson = [
  '{"type":"join"', // Incomplete JSON
  '{"type":}', // Invalid syntax
  '{type:"join"}', // Unquoted keys
  '{"type":"join","payload":{"roomId":}}', // Invalid structure
  "not json at all",
  "",
  null,
];

malformedJson.forEach((json) => {
  // Send raw malformed data
  ws.send(json);
});
```

## 🔧 Testing Tools & Scripts

### WebSocket Testing Client

```javascript
// security-test-client.js
const WebSocket = require("ws");

class SecurityTester {
  constructor(url) {
    this.url = url;
    this.results = [];
  }

  async testRateLimit() {
    const ws = new WebSocket(this.url);

    ws.on("open", () => {
      // Send messages rapidly to trigger rate limit
      for (let i = 0; i < 35; i++) {
        ws.send(
          JSON.stringify({
            type: "message",
            payload: { encrypted: btoa(`msg ${i}`) + "." + btoa("test") },
          })
        );
      }
    });

    ws.on("message", (data) => {
      const msg = JSON.parse(data);
      if (msg.type === "error" && msg.payload.code === "RATE_LIMITED") {
        console.log("✅ Rate limiting working correctly");
      }
    });
  }

  async testMaliciousInput() {
    const ws = new WebSocket(this.url);
    const maliciousInputs = [
      '<script>alert("xss")</script>',
      "javascript:alert(1)",
      "../../../etc/passwd",
    ];

    ws.on("open", () => {
      maliciousInputs.forEach((input) => {
        ws.send(
          JSON.stringify({
            type: "join",
            payload: { roomId: input, userId: "test", username: "test" },
          })
        );
      });
    });

    ws.on("close", (code) => {
      if (code === 1008) {
        console.log("✅ Malicious content detection working");
      }
    });
  }
}

// Run tests
const tester = new SecurityTester("ws://localhost:8080");
tester.testRateLimit();
tester.testMaliciousInput();
```

### Load Testing Script

```bash
#!/bin/bash
# load-test.sh

echo "Starting security load test..."

# Test 1: Connection flooding
echo "Testing connection flood protection..."
for i in {1..20}; do
  wscat -c ws://localhost:8080 &
  sleep 0.1
done

# Test 2: Message flooding
echo "Testing message rate limiting..."
wscat -c ws://localhost:8080 -x '{"type":"message","payload":{"encrypted":"dGVzdA==.dGVzdA=="}}' &

# Wait and check server logs
sleep 5
echo "Check server logs for rate limiting messages"
```

## 📊 Expected Security Responses

### Rate Limiting Responses

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

### Malicious Content Response

```json
{
  "type": "error",
  "payload": {
    "message": "Invalid room ID format",
    "code": "INVALID_ROOM_ID"
  }
}
```

### Connection Blocked Response

Connection refused at WebSocket handshake level (no response).

## 🚨 Security Monitoring

### Real-time Monitoring

```bash
# Monitor security logs
tail -f server.log | grep "SECURITY VIOLATION"

# Check security metrics
curl -s http://localhost:8080/security-report | jq
```

### Security Metrics to Monitor

- Number of flagged IPs
- Rate limiting violations per IP
- Invalid message format attempts
- Session violation counts
- Connection rejection rates

## ✅ Security Test Checklist

### Rate Limiting

- [ ] Message rate limiting (30/minute)
- [ ] Join rate limiting (5/minute)
- [ ] Connection rate limiting (10/IP)
- [ ] Message size limiting (10KB)
- [ ] Encrypted payload size limiting (100KB)

### Input Validation

- [ ] Room ID format validation
- [ ] Message type validation
- [ ] Encrypted format validation
- [ ] User input sanitization
- [ ] Malicious pattern detection

### Session Security

- [ ] Session token generation
- [ ] Session expiration (2 hours)
- [ ] Session fingerprinting
- [ ] Activity tracking

### DDoS Protection

- [ ] IP-based blocking
- [ ] Failed attempt tracking
- [ ] Lockout mechanisms (15 minutes)
- [ ] Violation escalation

### Encryption Security

- [ ] Format validation
- [ ] Size constraints
- [ ] Zero-knowledge relay
- [ ] Content integrity

### Monitoring & Alerting

- [ ] Security violation logging
- [ ] Real-time monitoring
- [ ] Automated alerting
- [ ] Security reports

## 🛡️ Security Test Results Format

Document test results using this format:

```markdown
## Test: [Test Name]

**Date**: [Date]
**Tester**: [Name]
**Environment**: [Dev/Staging/Prod]

### Test Steps

1. [Step 1]
2. [Step 2]
3. [Step 3]

### Expected Result

[What should happen]

### Actual Result

[What actually happened]

### Status

- [x] PASS / [ ] FAIL

### Notes

[Additional observations]
```

This comprehensive testing approach ensures all security measures are functioning correctly and provides confidence in the system's resistance to various attack vectors.
