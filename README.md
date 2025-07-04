# Whisper - WebSocket Relay Server

A lightweight Node.js WebSocket relay server for the RTC-E2EE chat application. Whisper enables real-time, end-to-end encrypted communication by routing encrypted messages between clients without storing or decrypting any data.

## Features

- **Zero-Knowledge Relay**: All messages are end-to-end encrypted; the server never sees plaintext
- **Real-time Communication**: WebSocket-based messaging with typing indicators and reactions
- **Room Management**: Automatic room creation/cleanup and user presence tracking
- **Health Monitoring**: Built-in health check endpoint for deployment monitoring
- **Production Ready**: Heartbeat mechanisms, error handling, and graceful shutdown
- **Lightweight**: Minimal dependencies and efficient resource usage

## Environment Variables

- `PORT`: Server port number (default: 8080)
- `NODE_ENV`: Environment mode (development/production)

## API Endpoints

### HTTP Endpoints

- `GET /` or `GET /health`: Health check endpoint returning server status and connection count

### WebSocket Messages

#### Client → Server

- `ping`: Heartbeat ping
- `join`: Join a chat room
- `leave`: Leave current room
- `message`: Send encrypted message to room
- `typing`: Send typing indicator
- `reaction`: Send message reaction

#### Server → Client

- `pong`: Heartbeat response
- `userJoined`: User joined the room
- `userLeft`: User left the room
- `userList`: Current users in room
- `message`: Encrypted message from another user
- `userTyping`: Typing indicator from another user
- `reaction`: Message reaction from another user

## Deployment

### Render (Recommended)

1. Fork this repository
2. Connect to Render
3. Use the included `render.yaml` blueprint
4. Deploy automatically

### Railway

1. Connect your repository
2. Set root directory to this folder
3. Railway will use the `Procfile` automatically

### Heroku

1. Create new Heroku app
2. Connect your repository
3. Set root directory to this folder
4. Deploy using the included `Procfile`

### Manual Deployment

```bash
# Clone and install
git clone https://github.com/ajnjanssen/RTCE2EE-whisper.git
cd RTCE2EE-whisper
npm install

# Production
npm start

# Development
npm run dev
```

## Development

### Local Setup

```bash
npm install
npm run dev
```

### Testing WebSocket Connection

```javascript
const ws = new WebSocket("ws://localhost:8080");
ws.onopen = () => console.log("Connected");
ws.onmessage = (event) => console.log("Received:", event.data);
```

## Architecture

The server maintains:

- **Rooms**: Map of room IDs to user connections
- **Users**: Connection metadata (user ID, username)
- **Messages**: Encrypted payloads (never decrypted server-side)

All message content is end-to-end encrypted by clients before transmission, ensuring zero-knowledge operation.

## Security

- **No Data Persistence**: Messages are not stored or logged
- **Zero-Knowledge**: Server cannot decrypt message content
- **Connection Security**: WebSocket connections with heartbeat monitoring
- **Input Validation**: All incoming messages are validated and sanitized

## Dependencies

- `ws` (^8.18.3): WebSocket library for Node.js

## License

ISC License

## Contributing

This is part of the RTC-E2EE project. For issues and contributions, please refer to the main project repository.

## Related Projects

- [RTC-E2EE Main App](https://github.com/ajnjanssen/RTCE2EE): The React/Next.js chat application
- [Live Demo](https://rtc-e2ee.netlify.app/): Try the chat application

---

**Whisper** - Simple, secure, zero-knowledge WebSocket relay for end-to-end encrypted chat.
