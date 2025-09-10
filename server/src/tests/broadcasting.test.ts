import { describe, test, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import request from 'supertest';
import { app } from '../server';
import { initializeDatabase, closeDatabaseConnection, pool } from '../config/database';
import { broadcastService } from '../services/BroadcastService';
import { connectionManager } from '../services/ConnectionManager';
import { MessageService } from '../services/MessageService';

describe('Message Broadcasting System', () => {
  let testUsers: Array<{ id: string; username: string; token: string }> = [];

  beforeAll(async () => {
    await initializeDatabase();
    
    // Clean up test data
    await pool.query('DELETE FROM messages WHERE sender_id IN (SELECT id FROM users WHERE username LIKE $1)', ['broadcast_test_%']);
    await pool.query('DELETE FROM users WHERE username LIKE $1', ['broadcast_test_%']);
  });

  beforeEach(async () => {
    // Create test users for broadcasting tests
    for (let i = 1; i <= 3; i++) {
      const userData = {
        username: `broadcast_test_user_${i}`,
        email: `broadcast${i}@example.com`,
        password: 'SecurePassword123!',
        public_key: '-----BEGIN PUBLIC KEY-----\nTestKey...\n-----END PUBLIC KEY-----',
        private_key_encrypted: 'encrypted_private_key_data_here'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData);

      testUsers.push({
        id: response.body.data.user.id,
        username: response.body.data.user.username,
        token: response.body.data.token
      });
    }
  });

  afterAll(async () => {
    // Clean up test data
    await pool.query('DELETE FROM messages WHERE sender_id IN (SELECT id FROM users WHERE username LIKE $1)', ['broadcast_test_%']);
    await pool.query('DELETE FROM users WHERE username LIKE $1', ['broadcast_test_%']);
    await closeDatabaseConnection();
  });

  describe('Message Sending', () => {
    test('should send message with encryption', async () => {
      const messageData = {
        encrypted_content: 'U2FsdGVkX1+ABC123DEF456',
        iv: 'abc123def456789012345678901234567'
      };

      const response = await request(app)
        .post('/api/messages/send')
        .set('Authorization', `Bearer ${testUsers[0].token}`)
        .send(messageData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.id).toBeDefined();
      expect(response.body.data.sender_id).toBe(testUsers[0].id);
      expect(response.body.data.encrypted_content).toBeDefined();
    });

    test('should reject message without content', async () => {
      const messageData = {}; // Empty message

      const response = await request(app)
        .post('/api/messages/send')
        .set('Authorization', `Bearer ${testUsers[0].token}`)
        .send(messageData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    test('should reject message without authentication', async () => {
      const messageData = {
        content: 'Test message'
      };

      const response = await request(app)
        .post('/api/messages/send')
        .send(messageData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('UNAUTHORIZED');
    });

    test('should validate message content length', async () => {
      const longMessage = 'x'.repeat(5001); // Over limit
      const messageData = {
        content: longMessage
      };

      const response = await request(app)
        .post('/api/messages/send')
        .set('Authorization', `Bearer ${testUsers[0].token}`)
        .send(messageData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('Message Broadcasting', () => {
    test('should store message in database', async () => {
      const messageData = {
        encrypted_content: 'U2FsdGVkX1+ABC123DEF456',
        iv: 'abc123def456789012345678901234567'
      };

      const response = await request(app)
        .post('/api/messages/send')
        .set('Authorization', `Bearer ${testUsers[0].token}`)
        .send(messageData);

      const messageId = response.body.data.id;

      // Verify message exists in database
      const dbResult = await pool.query(
        'SELECT * FROM messages WHERE id = $1',
        [messageId]
      );

      expect(dbResult.rows).toHaveLength(1);
      expect(dbResult.rows[0].sender_id).toBe(testUsers[0].id);
      expect(dbResult.rows[0].encrypted_content).toBeDefined();
    });

    test('should broadcast message to all connected users', async () => {
      // Mock connection manager to simulate connected users
      const broadcastedMessages: any[] = [];
      const originalSendToUser = connectionManager.sendToUser;
      
      connectionManager.sendToUser = jest.fn((userId: string, type: string, data: any) => {
        broadcastedMessages.push({ userId, type, data });
        return 1; // Simulate successful send
      }) as any;

      // Mock connected users
      const mockGetConnectedUsers = jest.fn(() => testUsers.map(u => u.id));
      connectionManager.getConnectedUsers = mockGetConnectedUsers;

      const messageData = {
        encrypted_content: 'U2FsdGVkX1+ABC123DEF456',
        iv: 'abc123def456789012345678901234567'
      };

      await request(app)
        .post('/api/messages/send')
        .set('Authorization', `Bearer ${testUsers[0].token}`)
        .send(messageData);

      // Allow time for broadcast processing
      await new Promise(resolve => setTimeout(resolve, 200));

      // Verify broadcast was attempted
      expect(connectionManager.sendToUser).toHaveBeenCalled();

      // Restore original function
      connectionManager.sendToUser = originalSendToUser;
    });

    test('should handle broadcast queue overflow gracefully', async () => {
      const originalMaxQueueSize = (broadcastService as any).MAX_QUEUE_SIZE;
      (broadcastService as any).MAX_QUEUE_SIZE = 2; // Small queue for testing

      // Send multiple messages quickly to overflow queue
      const promises = [];
      for (let i = 0; i < 5; i++) {
        const messageData = {
          encrypted_content: `U2FsdGVkX1+ABC123DEF45${i}`,
          iv: 'abc123def456789012345678901234567'
        };

        promises.push(
          request(app)
            .post('/api/messages/send')
            .set('Authorization', `Bearer ${testUsers[0].token}`)
            .send(messageData)
        );
      }

      const responses = await Promise.all(promises);

      // All messages should be sent successfully (queue should handle overflow)
      responses.forEach(response => {
        expect(response.status).toBe(201);
        expect(response.body.success).toBe(true);
      });

      // Restore original queue size
      (broadcastService as any).MAX_QUEUE_SIZE = originalMaxQueueSize;
    });
  });

  describe('Message History', () => {
    beforeEach(async () => {
      // Send some test messages
      for (let i = 0; i < 5; i++) {
        const messageData = {
          content: `Test message ${i + 1}`
        };

        await request(app)
          .post('/api/messages/send')
          .set('Authorization', `Bearer ${testUsers[i % testUsers.length].token}`)
          .send(messageData);
      }
    });

    test('should retrieve message history with pagination', async () => {
      const response = await request(app)
        .get('/api/messages/history?page=1&limit=3')
        .set('Authorization', `Bearer ${testUsers[0].token}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.messages).toBeDefined();
      expect(response.body.data.messages.length).toBeLessThanOrEqual(3);
      expect(response.body.data.total).toBeDefined();
      expect(response.body.data.page).toBe(1);
      expect(response.body.data.limit).toBe(3);
    });

    test('should filter messages by date range', async () => {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      
      const tomorrow = new Date();
      tomorrow.setDate(tomorrow.getDate() + 1);

      const response = await request(app)
        .get(`/api/messages/history?start_date=${yesterday.toISOString()}&end_date=${tomorrow.toISOString()}`)
        .set('Authorization', `Bearer ${testUsers[0].token}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.messages).toBeDefined();
    });

    test('should require authentication for message history', async () => {
      const response = await request(app)
        .get('/api/messages/history')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('UNAUTHORIZED');
    });
  });

  describe('Real-time Connection Management', () => {
    test('should track connected users', async () => {
      // Simulate user connections
      const userConnections = connectionManager.getUserConnections(testUsers[0].id);
      expect(Array.isArray(userConnections)).toBe(true);
    });

    test('should get total connection count', async () => {
      const totalConnections = connectionManager.getTotalConnectionCount();
      expect(typeof totalConnections).toBe('number');
      expect(totalConnections).toBeGreaterThanOrEqual(0);
    });

    test('should get broadcast queue status', async () => {
      const queueStatus = broadcastService.getQueueStatus();
      
      expect(queueStatus).toHaveProperty('size');
      expect(queueStatus).toHaveProperty('highPriority');
      expect(queueStatus).toHaveProperty('normalPriority');
      expect(queueStatus).toHaveProperty('lowPriority');
      expect(queueStatus).toHaveProperty('isProcessing');
      
      expect(typeof queueStatus.size).toBe('number');
      expect(typeof queueStatus.isProcessing).toBe('boolean');
    });
  });

  describe('Error Handling', () => {
    test('should handle database connection errors gracefully', async () => {
      // Mock database error
      const originalQuery = pool.query;
      pool.query = jest.fn().mockRejectedValue(new Error('Database connection failed'));

      const messageData = {
        content: 'Test message'
      };

      const response = await request(app)
        .post('/api/messages/send')
        .set('Authorization', `Bearer ${testUsers[0].token}`)
        .send(messageData)
        .expect(500);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('INTERNAL_ERROR');

      // Restore original function
      pool.query = originalQuery;
    });

    test('should validate message type parameter', async () => {
      const messageData = {
        content: 'Test message',
        message_type: 'invalid_type'
      };

      const response = await request(app)
        .post('/api/messages/send')
        .set('Authorization', `Bearer ${testUsers[0].token}`)
        .send(messageData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });
  });
});