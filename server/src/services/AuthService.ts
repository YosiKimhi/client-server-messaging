import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import NodeRSA from 'node-rsa';
import { PoolClient } from 'pg';
import { 
  User, 
  AuthResponse, 
  UserProfile, 
  ActiveSession, 
  JWTPayload,
  RegisterRequest,
  LoginRequest,
  EncryptionKeys
} from '@/types';
import { query, transaction } from '@/config/database';
import { logger } from '@/utils/logger';
import { logSecurityEvent } from '@/utils/validation';

export class AuthService {
  private static readonly BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
  private static readonly JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-in-production';
  private static readonly JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
  private static readonly RSA_KEY_SIZE = 2048;
  private static readonly MAX_LOGIN_ATTEMPTS = 5;
  private static readonly LOCKOUT_DURATION_MINUTES = 15;

  /**
   * Generate RSA key pair for user encryption
   */
  private static generateRSAKeyPair(): EncryptionKeys {
    try {
      const key = new NodeRSA({ b: this.RSA_KEY_SIZE });
      
      // Generate keys in PEM format
      const publicKey = key.exportKey('public');
      const privateKey = key.exportKey('private');
      
      // For this implementation, we'll encrypt the private key with a simple method
      // In production, you'd want to use the user's password or a key derivation function
      const encryptedPrivateKey = Buffer.from(privateKey).toString('base64');
      
      logger.debug('RSA key pair generated successfully', {
        publicKeyLength: publicKey.length,
        privateKeyLength: privateKey.length
      });
      
      return {
        publicKey,
        privateKey,
        encryptedPrivateKey
      };
    } catch (error) {
      logger.error('Failed to generate RSA key pair', {
        error: (error as Error).message
      });
      throw new Error('Failed to generate encryption keys');
    }
  }

  /**
   * Hash password using bcrypt with salt
   */
  private static async hashPassword(password: string): Promise<{ hash: string; salt: string }> {
    try {
      const salt = await bcrypt.genSalt(this.BCRYPT_ROUNDS);
      const hash = await bcrypt.hash(password, salt);
      
      logger.debug('Password hashed successfully', {
        rounds: this.BCRYPT_ROUNDS,
        saltLength: salt.length
      });
      
      return { hash, salt };
    } catch (error) {
      logger.error('Failed to hash password', {
        error: (error as Error).message
      });
      throw new Error('Password hashing failed');
    }
  }

  /**
   * Verify password against hash
   */
  private static async verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
      return await bcrypt.compare(password, hash);
    } catch (error) {
      logger.error('Password verification failed', {
        error: (error as Error).message
      });
      return false;
    }
  }

  /**
   * Generate JWT token
   */
  private static generateJWTToken(user: User, sessionId: string): string {
    const payload: JWTPayload = {
      user_id: user.id,
      username: user.username,
      session_id: sessionId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
    };

    return jwt.sign(payload, this.JWT_SECRET);
  }

  /**
   * Verify and decode JWT token
   */
  public static verifyJWTToken(token: string): JWTPayload | null {
    try {
      const decoded = jwt.verify(token, this.JWT_SECRET) as JWTPayload;
      return decoded;
    } catch (error) {
      logger.debug('JWT verification failed', {
        error: (error as Error).message,
        token: token.substring(0, 20) + '...'
      });
      return null;
    }
  }

  /**
   * Check if username or email already exists
   */
  private static async checkUserExists(username: string, email: string): Promise<boolean> {
    try {
      const result = await query(
        'SELECT id FROM users WHERE username = $1 OR email = $2 LIMIT 1',
        [username, email]
      );
      
      return result.rows.length > 0;
    } catch (error) {
      logger.error('Failed to check if user exists', {
        error: (error as Error).message,
        username
      });
      throw error;
    }
  }

  /**
   * Create a new user session
   */
  private static async createSession(
    client: PoolClient,
    userId: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<ActiveSession> {
    const sessionId = uuidv4();
    const sessionToken = uuidv4();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    
    await client.query(
      `INSERT INTO active_sessions (id, user_id, session_token, expires_at, last_activity, ip_address, user_agent, is_active)
       VALUES ($1, $2, $3, $4, NOW(), $5, $6, true)`,
      [sessionId, userId, sessionToken, expiresAt, ipAddress, userAgent]
    );
    
    const session: ActiveSession = {
      id: sessionId,
      user_id: userId,
      session_token: sessionToken,
      expires_at: expiresAt,
      last_activity: new Date(),
      ip_address: ipAddress || undefined,
      user_agent: userAgent || undefined,
      is_active: true,
      created_at: new Date()
    };
    
    return session;
  }

  /**
   * Register a new user
   */
  public static async register(
    userData: RegisterRequest,
    ipAddress?: string,
    userAgent?: string
  ): Promise<AuthResponse> {
    try {
      // Check if user already exists
      const userExists = await this.checkUserExists(userData.username, userData.email);
      if (userExists) {
        throw new Error('Username or email already exists');
      }

      // Hash password
      const { hash: passwordHash, salt } = await this.hashPassword(userData.password);

      // Generate user ID
      const userId = uuidv4();

      // Create user and session in transaction
      const result = await transaction(async (client) => {
        // Insert user
        await client.query(
          `INSERT INTO users (id, username, email, password_hash, salt, public_key, private_key_encrypted, is_active)
           VALUES ($1, $2, $3, $4, $5, $6, $7, true)`,
          [
            userId,
            userData.username,
            userData.email,
            passwordHash,
            salt,
            userData.public_key,
            userData.private_key_encrypted
          ]
        );

        // Store public key in user_keys table
        await client.query(
          `INSERT INTO user_keys (id, user_id, key_type, key_data, key_version, is_active)
           VALUES ($1, $2, 'rsa_public', $3, 1, true)`,
          [uuidv4(), userId, userData.public_key]
        );

        // Store encrypted private key in user_keys table
        await client.query(
          `INSERT INTO user_keys (id, user_id, key_type, key_data, key_version, is_active)
           VALUES ($1, $2, 'rsa_private', $3, 1, true)`,
          [uuidv4(), userId, userData.private_key_encrypted]
        );

        // Create session
        const session = await this.createSession(client, userId, ipAddress, userAgent);

        // Get the created user
        const userResult = await client.query(
          'SELECT id, username, email, public_key, is_active, created_at, updated_at FROM users WHERE id = $1',
          [userId]
        );

        return {
          user: userResult.rows[0] as User,
          session
        };
      });

      // Generate JWT token
      const token = this.generateJWTToken(result.user, result.session.id);

      // Log successful registration
      logger.info('User registered successfully', {
        userId: result.user.id,
        username: result.user.username,
        ipAddress,
        userAgent
      });

      // Return auth response
      const authResponse: AuthResponse = {
        user: {
          id: result.user.id,
          username: result.user.username,
          email: result.user.email,
          public_key: result.user.public_key,
          is_active: result.user.is_active,
          created_at: result.user.created_at,
          updated_at: result.user.updated_at,
          last_login: result.user.last_login
        },
        token,
        expires_at: result.session.expires_at
      };

      return authResponse;

    } catch (error) {
      logger.error('User registration failed', {
        error: (error as Error).message,
        username: userData.username,
        email: userData.email,
        ipAddress
      });
      throw error;
    }
  }

  /**
   * Authenticate user login
   */
  public static async login(
    loginData: LoginRequest,
    ipAddress?: string,
    userAgent?: string
  ): Promise<AuthResponse> {
    try {
      // Get user by username
      const userResult = await query(
        `SELECT id, username, email, password_hash, salt, public_key, is_active, created_at, updated_at, last_login
         FROM users 
         WHERE username = $1 AND is_active = true`,
        [loginData.username]
      );

      if (userResult.rows.length === 0) {
        // Log failed login attempt
        logger.warn('Login attempt with non-existent username', {
          username: loginData.username,
          ipAddress,
          userAgent
        });
        throw new Error('Invalid username or password');
      }

      const user = userResult.rows[0] as User;

      // Verify password
      const isPasswordValid = await this.verifyPassword(loginData.password, user.password_hash);
      
      if (!isPasswordValid) {
        // Log failed login attempt
        logger.warn('Login attempt with invalid password', {
          userId: user.id,
          username: user.username,
          ipAddress,
          userAgent
        });
        throw new Error('Invalid username or password');
      }

      // Create session and update user's last login in transaction
      const result = await transaction(async (client) => {
        // Update last login time
        await client.query(
          'UPDATE users SET last_login = NOW(), updated_at = NOW() WHERE id = $1',
          [user.id]
        );

        // Create new session
        const session = await this.createSession(client, user.id, ipAddress, userAgent);

        return { user, session };
      });

      // Generate JWT token
      const token = this.generateJWTToken(result.user, result.session.id);

      // Log successful login
      logger.info('User logged in successfully', {
        userId: result.user.id,
        username: result.user.username,
        sessionId: result.session.id,
        ipAddress,
        userAgent
      });

      // Return auth response
      const authResponse: AuthResponse = {
        user: {
          id: result.user.id,
          username: result.user.username,
          email: result.user.email,
          public_key: result.user.public_key,
          is_active: result.user.is_active,
          created_at: result.user.created_at,
          updated_at: result.user.updated_at,
          last_login: new Date()
        },
        token,
        expires_at: result.session.expires_at
      };

      return authResponse;

    } catch (error) {
      logger.error('User login failed', {
        error: (error as Error).message,
        username: loginData.username,
        ipAddress
      });
      throw error;
    }
  }

  /**
   * Logout user by invalidating session
   */
  public static async logout(
    sessionId: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    try {
      // Get session info before deletion for logging
      const sessionResult = await query(
        'SELECT user_id FROM active_sessions WHERE id = $1 AND is_active = true',
        [sessionId]
      );

      if (sessionResult.rows.length === 0) {
        logger.warn('Logout attempt with invalid session', {
          sessionId,
          ipAddress,
          userAgent
        });
        throw new Error('Invalid session');
      }

      const userId = sessionResult.rows[0].user_id;

      // Deactivate session
      await query(
        'UPDATE active_sessions SET is_active = false, last_activity = NOW() WHERE id = $1',
        [sessionId]
      );

      logger.info('User logged out successfully', {
        userId,
        sessionId,
        ipAddress,
        userAgent
      });

    } catch (error) {
      logger.error('User logout failed', {
        error: (error as Error).message,
        sessionId,
        ipAddress
      });
      throw error;
    }
  }

  /**
   * Get user profile by user ID
   */
  public static async getUserProfile(userId: string): Promise<UserProfile | null> {
    try {
      const result = await query(
        `SELECT id, username, email, public_key, is_active, created_at, last_login
         FROM users 
         WHERE id = $1 AND is_active = true`,
        [userId]
      );

      if (result.rows.length === 0) {
        return null;
      }

      return result.rows[0] as UserProfile;

    } catch (error) {
      logger.error('Failed to get user profile', {
        error: (error as Error).message,
        userId
      });
      throw error;
    }
  }

  /**
   * Validate and get active session
   */
  public static async validateSession(sessionId: string): Promise<ActiveSession | null> {
    try {
      const result = await query(
        `SELECT id, user_id, session_token, expires_at, last_activity, ip_address, user_agent, is_active, created_at
         FROM active_sessions 
         WHERE id = $1 AND is_active = true AND expires_at > NOW()`,
        [sessionId]
      );

      if (result.rows.length === 0) {
        return null;
      }

      const session = result.rows[0] as ActiveSession;

      // Update last activity
      await query(
        'UPDATE active_sessions SET last_activity = NOW() WHERE id = $1',
        [sessionId]
      );

      return session;

    } catch (error) {
      logger.error('Session validation failed', {
        error: (error as Error).message,
        sessionId
      });
      return null;
    }
  }

  /**
   * Clean up expired sessions
   */
  public static async cleanupExpiredSessions(): Promise<void> {
    try {
      const result = await query(
        'UPDATE active_sessions SET is_active = false WHERE expires_at < NOW() AND is_active = true'
      );

      if (result.rowCount && result.rowCount > 0) {
        logger.info('Cleaned up expired sessions', {
          count: result.rowCount
        });
      }

    } catch (error) {
      logger.error('Failed to cleanup expired sessions', {
        error: (error as Error).message
      });
    }
  }

  /**
   * Generate RSA key pair for new user (utility method)
   */
  public static generateUserKeys(): EncryptionKeys {
    return this.generateRSAKeyPair();
  }

  /**
   * Get user's encryption keys
   */
  public static async getUserKeys(userId: string): Promise<{ publicKey: string; privateKeyEncrypted: string } | null> {
    try {
      const result = await query(
        `SELECT key_type, key_data 
         FROM user_keys 
         WHERE user_id = $1 AND is_active = true AND key_type IN ('rsa_public', 'rsa_private')`,
        [userId]
      );

      if (result.rows.length < 2) {
        return null;
      }

      const keys = result.rows.reduce((acc: any, row: any) => {
        if (row.key_type === 'rsa_public') {
          acc.publicKey = row.key_data;
        } else if (row.key_type === 'rsa_private') {
          acc.privateKeyEncrypted = row.key_data;
        }
        return acc;
      }, {});

      return keys;

    } catch (error) {
      logger.error('Failed to get user keys', {
        error: (error as Error).message,
        userId
      });
      throw error;
    }
  }
}