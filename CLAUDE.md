# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

- for every task or request on this projects pick the best agent for the task! think who whould solve of implement the task in the must efficient way, and then let him do the task צמ 

## Project Overview

This is a secure client-server messaging application with the following architecture:
- **Client**: React application for user interface and message handling
- **Server**: Node.js backend for authentication, message broadcasting, and database operations
- **Security**: End-to-end encryption using public/private key mechanism (RSA/AES)
- **Database**: Encrypted message storage for audit purposes
- **Communication**: REST API without WebSockets (constraint specified in requirements)

## Key Requirements

### Server Requirements
- Handle 10,000+ concurrent connections
- Username/password authentication with secure password hashing (bcrypt/Argon2)
- Public/private key encryption for secure communication
- Message broadcasting to all connected clients
- Encrypted message storage in database
- Event logging for monitoring
- API for querying stored messages (authenticated clients only)

### Client Requirements
- User registration and authentication
- Message encryption before sending
- Receive and decrypt broadcast messages from server
- All communication over TLS

### Security Constraints
- No WebSocket usage allowed - must use alternative for real-time communication
- All client-server communication must be encrypted (TLS)
- Messages encrypted at rest in database
- Secure password hashing required

## Development Commands

*Note: Commands will be added once package.json files are created for client and server*

## Architecture Notes

Since WebSockets are prohibited, the application will likely use:
- Long polling or Server-Sent Events for real-time message delivery
- REST API endpoints for message sending and user management
- JWT tokens for session management
- Separate client and server directories with independent package.json files

## Testing Requirements

Must include unit tests for:
- User authentication
- Message encryption/decryption  
- Message broadcasting functionality

## Database Seeding

A database seeding script is required for mock user credentials and messages.