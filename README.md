# Secure Client-Server Messaging Application

A secure messaging application built with end-to-end encryption, real-time communication (without WebSockets), and audit logging capabilities.

## Project Status

**Current Phase: Hour 0-4 COMPLETE** ✅

### Completed Features
- ✅ Project structure setup (server/, client/, docs/)
- ✅ Node.js server with TypeScript configuration
- ✅ PostgreSQL database schema with encryption support
- ✅ Database connection pooling with pg library (raw SQL, no ORM)
- ✅ TypeScript interfaces and types
- ✅ Basic logging system
- ✅ Git configuration with .gitignore

### Next Phase: Hour 4-8 - Authentication System
- User registration and login endpoints
- Secure password hashing with bcrypt
- JWT token generation and validation
- Authentication middleware
- Input validation and sanitization

## Architecture

### Backend (Node.js + TypeScript)
- **Database**: PostgreSQL with raw SQL queries (no ORM)
- **Security**: RSA/AES encryption, bcrypt password hashing
- **Real-time**: Server-Sent Events + Long Polling (no WebSockets)
- **API**: RESTful endpoints with Express.js

### Database Schema
- `users` - User accounts with encrypted keys
- `messages` - Encrypted messages with metadata
- `active_sessions` - JWT session tracking
- `audit_logs` - Security event logging
- `user_keys` - Key management and rotation

## Quick Start

### Prerequisites
- Node.js 18+
- PostgreSQL 14+
- npm or yarn

### Setup
```bash
# Clone and navigate
cd client-server-messaging

# Install server dependencies
cd server
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your database credentials

# Start PostgreSQL and create database
createdb messaging_app

# Run migrations and start server
npm run migrate
npm run dev
```

### Environment Variables
```env
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=messaging_app
DB_USER=postgres
DB_PASSWORD=your_password

# Server Configuration  
PORT=3001
HOST=localhost
NODE_ENV=development

# JWT Configuration (to be added in Hour 4-8)
JWT_SECRET=your-super-secret-key
JWT_EXPIRES_IN=7d

# Encryption Configuration (to be added in Hour 8-12)
BCRYPT_ROUNDS=12
```

## Development Commands

```bash
# Server commands
cd server
npm run dev          # Start development server with hot reload
npm run build        # Build for production
npm run start        # Start production server
npm run migrate      # Run database migrations
npm run seed         # Seed database with test data
npm run test         # Run tests
npm run lint         # Run linting

# Client commands (to be added in Hour 24-28)
cd client
npm run dev          # Start React development server
npm run build        # Build React app for production
npm run test         # Run React tests
```

## API Endpoints (Planned)

### Authentication (Hour 4-8)
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/profile` - Get user profile

### Messages (Hour 12-16)
- `POST /api/messages/send` - Send encrypted message
- `GET /api/messages/history` - Get message history
- `GET /api/messages/search` - Search messages

### Real-time (Hour 16-20)
- `GET /api/messages/stream` - Server-Sent Events
- `GET /api/messages/poll` - Long polling fallback

### System
- `GET /health` - Health check ✅ (Available now)

## Security Features

- **End-to-End Encryption**: RSA/AES hybrid encryption
- **Password Security**: bcrypt hashing with salt
- **Session Management**: JWT tokens with expiration
- **Input Validation**: Comprehensive request validation
- **Rate Limiting**: API rate limiting middleware
- **Audit Logging**: Security event tracking
- **HTTPS/TLS**: All communication encrypted in transit

## Database Design

The application uses raw SQL with PostgreSQL for optimal performance and security control:

- **No ORM**: Direct SQL queries for better performance and security
- **Connection Pooling**: Efficient database connection management
- **Prepared Statements**: SQL injection protection
- **Migrations**: Version-controlled schema changes
- **Indexes**: Optimized queries for 10,000+ concurrent users

## Development Timeline

- **Hour 0-4**: Project Setup & Database ✅ **COMPLETE**
- **Hour 4-8**: Authentication System (Next)
- **Hour 8-12**: Cryptographic System
- **Hour 12-16**: Core Message System
- **Hour 16-20**: Real-Time Communication
- **Hour 20-24**: Security & Optimization
- **Hour 24-28**: React Application Setup
- **Hour 28-32**: Authentication Frontend
- **Hour 32-36**: Client-Side Encryption
- **Hour 36-40**: Real-Time Messaging UI
- **Hour 40-44**: UI/UX Polish
- **Hour 44-48**: Testing & Deployment

## Testing

```bash
# Run all tests
npm test

# Run specific test suites
npm run test:auth      # Authentication tests
npm run test:crypto    # Encryption tests
npm run test:messages  # Message handling tests
npm run test:api       # API endpoint tests

# Load testing
npm run test:load      # Test concurrent user handling
```

## Contributing

1. Follow the 48-hour development plan in `docs/48-hour-tasks.md`
2. Use the existing TypeScript interfaces in `server/src/types/index.ts`
3. Write raw SQL queries (no ORM)
4. Follow security best practices
5. Add comprehensive logging for all operations

## License

MIT