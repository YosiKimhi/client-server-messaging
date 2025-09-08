-- Initial database schema for secure messaging application
-- This migration creates all the necessary tables for the messaging system

-- Enable UUID extension for PostgreSQL
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table: Store user information with encrypted keys
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(32) NOT NULL,
    public_key TEXT NOT NULL, -- RSA public key in PEM format
    private_key_encrypted TEXT NOT NULL, -- AES-256 encrypted RSA private key
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    CONSTRAINT users_username_length CHECK (LENGTH(username) >= 3),
    CONSTRAINT users_email_format CHECK (email ~* '^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+[.][A-Za-z]+$')
);

-- Messages table: Store encrypted messages with metadata
CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_content TEXT NOT NULL, -- AES-256 encrypted message content
    aes_key_encrypted TEXT NOT NULL, -- RSA encrypted AES key
    message_hash VARCHAR(64) NOT NULL, -- SHA-256 hash for integrity verification
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    message_type VARCHAR(20) DEFAULT 'text' CHECK (message_type IN ('text', 'system', 'notification')),
    is_broadcast BOOLEAN DEFAULT true, -- Whether message is broadcast to all users
    recipient_id UUID REFERENCES users(id) ON DELETE SET NULL, -- For direct messages (future feature)
    metadata JSONB DEFAULT '{}', -- Additional message metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Active sessions table: Track user sessions for JWT token management
CREATE TABLE active_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL, -- JWT token identifier
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT sessions_expires_future CHECK (expires_at > created_at)
);

-- Audit logs table: Security and event logging
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL, -- login, logout, message_send, message_receive, etc.
    resource_type VARCHAR(50), -- user, message, session, etc.
    resource_id UUID,
    details JSONB DEFAULT '{}', -- Additional event details
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    severity VARCHAR(20) DEFAULT 'info' CHECK (severity IN ('debug', 'info', 'warn', 'error', 'critical')),
    CONSTRAINT audit_logs_action_not_empty CHECK (LENGTH(action) > 0)
);

-- User keys table: Store additional encryption keys and key rotation history
CREATE TABLE user_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_type VARCHAR(20) NOT NULL CHECK (key_type IN ('rsa_public', 'rsa_private', 'aes_master')),
    key_data TEXT NOT NULL, -- Encrypted key data
    key_version INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT user_keys_unique_active UNIQUE (user_id, key_type, is_active) DEFERRABLE INITIALLY DEFERRED
);

-- Indexes for performance optimization
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_active ON users(is_active) WHERE is_active = true;

CREATE INDEX idx_messages_sender_id ON messages(sender_id);
CREATE INDEX idx_messages_timestamp ON messages(timestamp DESC);
CREATE INDEX idx_messages_type ON messages(message_type);
CREATE INDEX idx_messages_broadcast ON messages(is_broadcast) WHERE is_broadcast = true;
CREATE INDEX idx_messages_recipient ON messages(recipient_id) WHERE recipient_id IS NOT NULL;

CREATE INDEX idx_sessions_user_id ON active_sessions(user_id);
CREATE INDEX idx_sessions_token ON active_sessions(session_token);
CREATE INDEX idx_sessions_expires ON active_sessions(expires_at);
CREATE INDEX idx_sessions_active ON active_sessions(is_active) WHERE is_active = true;

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_severity ON audit_logs(severity);

CREATE INDEX idx_user_keys_user_id ON user_keys(user_id);
CREATE INDEX idx_user_keys_type ON user_keys(key_type);
CREATE INDEX idx_user_keys_active ON user_keys(is_active) WHERE is_active = true;

-- Triggers for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to clean up expired sessions (to be called by a scheduled job)
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM active_sessions 
    WHERE expires_at < NOW() OR last_activity < NOW() - INTERVAL '30 days';
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    INSERT INTO audit_logs (action, resource_type, details, severity)
    VALUES ('session_cleanup', 'system', 
            jsonb_build_object('deleted_sessions', deleted_count),
            'info');
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get user message count
CREATE OR REPLACE FUNCTION get_user_message_count(user_uuid UUID)
RETURNS INTEGER AS $$
BEGIN
    RETURN (SELECT COUNT(*) FROM messages WHERE sender_id = user_uuid);
END;
$$ LANGUAGE plpgsql;

-- Function to log audit events (helper for application)
CREATE OR REPLACE FUNCTION log_audit_event(
    p_user_id UUID,
    p_action VARCHAR(50),
    p_resource_type VARCHAR(50) DEFAULT NULL,
    p_resource_id UUID DEFAULT NULL,
    p_details JSONB DEFAULT '{}',
    p_ip_address INET DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL,
    p_severity VARCHAR(20) DEFAULT 'info'
)
RETURNS UUID AS $$
DECLARE
    audit_id UUID;
BEGIN
    INSERT INTO audit_logs (
        user_id, action, resource_type, resource_id, 
        details, ip_address, user_agent, severity
    ) VALUES (
        p_user_id, p_action, p_resource_type, p_resource_id,
        p_details, p_ip_address, p_user_agent, p_severity
    ) RETURNING id INTO audit_id;
    
    RETURN audit_id;
END;
$$ LANGUAGE plpgsql;

-- Create a view for active user sessions
CREATE VIEW active_user_sessions AS
SELECT 
    s.id as session_id,
    s.user_id,
    u.username,
    u.email,
    s.last_activity,
    s.ip_address,
    s.created_at as session_started,
    s.expires_at
FROM active_sessions s
JOIN users u ON s.user_id = u.id
WHERE s.is_active = true 
  AND s.expires_at > NOW()
ORDER BY s.last_activity DESC;

-- Create a view for recent message activity
CREATE VIEW recent_messages AS
SELECT 
    m.id,
    m.sender_id,
    u.username as sender_username,
    m.timestamp,
    m.message_type,
    m.is_broadcast,
    LENGTH(m.encrypted_content) as content_length
FROM messages m
JOIN users u ON m.sender_id = u.id
ORDER BY m.timestamp DESC
LIMIT 100;

-- Insert initial system user (for system messages)
INSERT INTO users (
    id, 
    username, 
    email, 
    password_hash, 
    salt, 
    public_key, 
    private_key_encrypted,
    is_active
) VALUES (
    '00000000-0000-0000-0000-000000000000',
    'system',
    'system@messaging.app',
    '$2b$12$system.hash.placeholder.for.system.user.account',
    'system_salt',
    '-----BEGIN PUBLIC KEY-----\nSYSTEM_PUBLIC_KEY_PLACEHOLDER\n-----END PUBLIC KEY-----',
    'SYSTEM_PRIVATE_KEY_ENCRYPTED_PLACEHOLDER',
    true
);

-- Log the schema creation
SELECT log_audit_event(
    '00000000-0000-0000-0000-000000000000',
    'schema_created',
    'database',
    NULL,
    '{"version": "001", "tables_created": ["users", "messages", "active_sessions", "audit_logs", "user_keys"]}'::jsonb,
    NULL,
    'migration_script',
    'info'
);