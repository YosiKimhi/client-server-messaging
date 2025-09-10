import { describe, test, expect, beforeAll, afterAll } from '@jest/globals';
import request from 'supertest';
import { app } from '../server';
import { initializeDatabase, closeDatabaseConnection, pool } from '../config/database';

describe('Authentication System', () => {
  let testUserId: string;
  let authToken: string;

  beforeAll(async () => {
    await initializeDatabase();
    // Clean up test data
    await pool.query('DELETE FROM users WHERE username LIKE $1', ['test_%']);
  });

  afterAll(async () => {
    // Clean up test data
    if (testUserId) {
      await pool.query('DELETE FROM users WHERE id = $1', [testUserId]);
    }
    await closeDatabaseConnection();
  });

  describe('User Registration', () => {
    test('should register a new user with valid credentials', async () => {
      const userData = {
        username: 'test_user_123',
        email: 'test@example.com',
        password: 'SecurePassword123!',
        public_key: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----',
        private_key_encrypted: 'encrypted_private_key_data_here'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.username).toBe(userData.username);
      expect(response.body.data.user.email).toBe(userData.email);
      expect(response.body.data.token).toBeDefined();

      // Store for cleanup
      testUserId = response.body.data.user.id;
      authToken = response.body.data.token;
    });

    test('should reject registration with duplicate username', async () => {
      const userData = {
        username: 'test_user_123', // Same as above
        email: 'test2@example.com',
        password: 'SecurePassword123!',
        public_key: '-----BEGIN PUBLIC KEY-----\nTest...\n-----END PUBLIC KEY-----',
        private_key_encrypted: 'encrypted_private_key_data_here'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('USERNAME_EXISTS');
    });

    test('should reject registration with weak password', async () => {
      const userData = {
        username: 'test_weak_pass',
        email: 'weak@example.com',
        password: '123', // Too weak
        public_key: '-----BEGIN PUBLIC KEY-----\nTest...\n-----END PUBLIC KEY-----',
        private_key_encrypted: 'encrypted_private_key_data_here'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    test('should reject registration with missing fields', async () => {
      const userData = {
        username: 'test_incomplete',
        // Missing required fields
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('User Login', () => {
    test('should login with correct credentials', async () => {
      const loginData = {
        username: 'test_user_123',
        password: 'SecurePassword123!'
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.username).toBe(loginData.username);
      expect(response.body.data.token).toBeDefined();

      // Verify JWT token structure
      const tokenParts = response.body.data.token.split('.');
      expect(tokenParts).toHaveLength(3); // header.payload.signature
    });

    test('should reject login with incorrect password', async () => {
      const loginData = {
        username: 'test_user_123',
        password: 'WrongPassword123!'
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('INVALID_CREDENTIALS');
    });

    test('should reject login with non-existent username', async () => {
      const loginData = {
        username: 'non_existent_user',
        password: 'SecurePassword123!'
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('INVALID_CREDENTIALS');
    });

    test('should handle rate limiting on multiple failed attempts', async () => {
      const loginData = {
        username: 'test_user_123',
        password: 'WrongPassword123!'
      };

      // Make multiple failed attempts
      for (let i = 0; i < 6; i++) {
        await request(app)
          .post('/api/auth/login')
          .send(loginData);
      }

      // Should be rate limited
      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(429);

      expect(response.body.error.code).toBe('TOO_MANY_REQUESTS');
    });
  });

  describe('Token Validation', () => {
    test('should validate correct JWT token', async () => {
      const response = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.username).toBe('test_user_123');
    });

    test('should reject invalid JWT token', async () => {
      const response = await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer invalid_token_here')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('INVALID_TOKEN');
    });

    test('should reject missing authorization header', async () => {
      const response = await request(app)
        .get('/api/auth/me')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('NO_TOKEN');
    });
  });

  describe('Password Security', () => {
    test('should hash passwords with bcrypt', async () => {
      // Get user from database to verify password is hashed
      const result = await pool.query(
        'SELECT password_hash FROM users WHERE id = $1',
        [testUserId]
      );

      const hashedPassword = result.rows[0]?.password_hash;
      expect(hashedPassword).toBeDefined();
      expect(hashedPassword).not.toBe('SecurePassword123!'); // Not plain text
      expect(hashedPassword.startsWith('$2b$')).toBe(true); // bcrypt format
    });
  });

  describe('Session Management', () => {
    test('should create session on login', async () => {
      const loginData = {
        username: 'test_user_123',
        password: 'SecurePassword123!'
      };

      await request(app)
        .post('/api/auth/login')
        .send(loginData)
        .expect(200);

      // Verify session was created in database
      const sessionResult = await pool.query(
        'SELECT COUNT(*) FROM active_sessions WHERE user_id = $1',
        [testUserId]
      );

      expect(parseInt(sessionResult.rows[0].count)).toBeGreaterThan(0);
    });

    test('should logout and invalidate session', async () => {
      const response = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);

      // Verify token is now invalid
      await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(401);
    });
  });
});