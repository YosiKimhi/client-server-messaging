import { Request } from 'express';

// Database entity types
export interface User {
  id: string;
  username: string;
  email: string;
  password_hash: string;
  salt: string;
  public_key: string;
  private_key_encrypted: string;
  is_active: boolean;
  created_at: Date;
  updated_at: Date;
  last_login?: Date;
}

export interface Message {
  id: string;
  sender_id: string;
  encrypted_content: string;
  aes_key_encrypted: string;
  message_hash: string;
  timestamp: Date;
  message_type: 'text' | 'system' | 'notification';
  is_broadcast: boolean;
  recipient_id?: string;
  metadata: Record<string, any>;
  created_at: Date;
}

export interface ActiveSession {
  id: string;
  user_id: string;
  session_token: string;
  expires_at: Date;
  last_activity: Date;
  ip_address?: string | undefined;
  user_agent?: string | undefined;
  is_active: boolean;
  created_at: Date;
}

export interface AuditLog {
  id: string;
  user_id?: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  details: Record<string, any>;
  ip_address?: string;
  user_agent?: string;
  timestamp: Date;
  severity: 'debug' | 'info' | 'warn' | 'error' | 'critical';
}

export interface UserKey {
  id: string;
  user_id: string;
  key_type: 'rsa_public' | 'rsa_private' | 'aes_master';
  key_data: string;
  key_version: number;
  is_active: boolean;
  expires_at?: Date;
  created_at: Date;
}

// API request/response types
export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  public_key: string;
  private_key_encrypted: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface SendMessageRequest {
  encrypted_content: string;
  aes_key_encrypted: string;
  message_hash: string;
  message_type?: 'text' | 'system' | 'notification';
  recipient_id?: string;
  metadata?: Record<string, any>;
}

export interface AuthResponse {
  user: Omit<User, 'password_hash' | 'salt' | 'private_key_encrypted'>;
  token: string;
  expires_at: Date;
}

export interface MessageResponse {
  id: string;
  sender_id: string;
  sender_username: string;
  encrypted_content: string;
  aes_key_encrypted: string;
  message_hash: string;
  timestamp: Date;
  message_type: string;
  metadata: Record<string, any>;
}

export interface UserProfile {
  id: string;
  username: string;
  email: string;
  public_key: string;
  is_active: boolean;
  created_at: Date;
  last_login?: Date;
}

// Middleware types
export interface AuthenticatedRequest extends Request {
  user?: UserProfile;
  session?: ActiveSession;
}

export interface JWTPayload {
  user_id: string;
  username: string;
  session_id: string;
  iat: number;
  exp: number;
}

// Utility types
export interface PaginationOptions {
  page: number;
  limit: number;
  offset: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}

export interface DatabaseError extends Error {
  code?: string;
  detail?: string;
  constraint?: string;
  table?: string;
  column?: string;
}

export interface ValidationError extends Error {
  field?: string;
  value?: any;
  constraint?: string;
}

// Connection management types
export interface ConnectionInfo {
  id: string;
  user_id: string;
  username: string;
  connected_at: Date;
  last_activity: Date;
  ip_address?: string;
  user_agent?: string;
}

export interface BroadcastMessage {
  type: 'message' | 'user_joined' | 'user_left' | 'system';
  data: any;
  timestamp: Date;
}

// Environment configuration types
export interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  ssl?: boolean | object;
  max: number;
  min: number;
  idleTimeoutMillis: number;
  connectionTimeoutMillis: number;
}

export interface ServerConfig {
  port: number;
  host: string;
  cors_origin: string;
  jwt_secret: string;
  jwt_expires_in: string;
  bcrypt_rounds: number;
  rate_limit_window_ms: number;
  rate_limit_max_requests: number;
}

// Encryption types
export interface EncryptionKeys {
  publicKey: string;
  privateKey: string;
  encryptedPrivateKey: string;
}

export interface EncryptedMessage {
  encrypted_content: string;
  aes_key_encrypted: string;
  message_hash: string;
}

export interface DecryptedMessage {
  content: string;
  sender_id: string;
  timestamp: Date;
  verified: boolean;
}

// Error response types
export interface ErrorResponse {
  error: {
    message: string;
    code?: string;
    field?: string;
    details?: Record<string, any>;
  };
  timestamp: Date;
  path: string;
  method: string;
}

// Success response type
export interface SuccessResponse<T = any> {
  success: true;
  data: T;
  timestamp: Date;
  message?: string;
}

// Generic API response type
export type ApiResponse<T = any> = SuccessResponse<T> | ErrorResponse;