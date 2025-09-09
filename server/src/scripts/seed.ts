import { Pool } from 'pg';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import NodeRSA from 'node-rsa';
import { logger } from '../utils/logger';
import { initializeDatabase, closeDatabaseConnection, pool } from '../config/database';
import { cryptoService } from '../services/CryptoService';

/**
 * Database seeding script for secure messaging application
 * Creates test users, keys, and sample messages for development and testing
 */

interface SeedUser {
  id: string;
  username: string;
  email: string;
  password: string;
  salt: string;
  publicKey: string;
  privateKeyEncrypted: string;
}

interface SeedMessage {
  id: string;
  senderId: string;
  encryptedContent: string;
  aesKeyEncrypted: string;
  messageHash: string;
  messageType: string;
}

/**
 * Generate RSA key pair for a user
 */
function generateKeyPair(): { publicKey: string; privateKey: string } {
  const key = new NodeRSA({ b: 2048 });
  return {
    publicKey: key.exportKey('public'),
    privateKey: key.exportKey('private')
  };
}

/**
 * Create test users with proper encryption keys
 */
async function createSeedUsers(): Promise<SeedUser[]> {
  const seedUsers: SeedUser[] = [];
  
  const userTemplates = [
    { username: 'alice_demo', email: 'alice@example.com', password: 'SecurePass123!' },
    { username: 'bob_demo', email: 'bob@example.com', password: 'StrongPass456!' },
    { username: 'charlie_demo', email: 'charlie@example.com', password: 'SafePass789!' },
    { username: 'diana_demo', email: 'diana@example.com', password: 'ProtectedPass012!' },
    { username: 'eve_demo', email: 'eve@example.com', password: 'SecureKey345!' }
  ];

  for (const template of userTemplates) {
    const userId = uuidv4();
    const keyPair = generateKeyPair();
    
    // Hash password with salt
    const saltRounds = 12;
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(template.password, salt);
    
    // For demo purposes, we'll store the private key encrypted with a simple method
    // In real applications, this would be encrypted with the user's password
    const privateKeyEncrypted = Buffer.from(keyPair.privateKey).toString('base64');

    seedUsers.push({
      id: userId,
      username: template.username,
      email: template.email,
      password: hashedPassword,
      salt: salt,
      publicKey: keyPair.publicKey,
      privateKeyEncrypted
    });
  }

  return seedUsers;
}

/**
 * Create sample encrypted messages between users
 */
async function createSeedMessages(users: SeedUser[]): Promise<SeedMessage[]> {
  const messages: SeedMessage[] = [];
  
  const messageTemplates = [
    { content: 'Hello everyone! Welcome to the secure messaging platform.', type: 'text' },
    { content: 'This is a test message to verify encryption is working properly.', type: 'text' },
    { content: 'The system supports end-to-end encryption using RSA and AES.', type: 'text' },
    { content: 'All messages are encrypted before being stored in the database.', type: 'text' },
    { content: 'System initialized successfully. All services are operational.', type: 'system' },
    { content: 'Rate limiting is active to prevent abuse and ensure fair usage.', type: 'text' },
    { content: 'Welcome to the demo! Feel free to send messages to test the system.', type: 'notification' },
    { content: 'Remember that this is a demonstration environment with test data.', type: 'text' }
  ];

  // Create messages from random users
  for (let i = 0; i < messageTemplates.length; i++) {
    const template = messageTemplates[i];
    if (!template) continue;
    
    const sender = users[i % users.length]; // Rotate through users
    if (!sender) continue;
    const messageId = uuidv4();

    try {
      // Encrypt message using CryptoService (simplified for demo)
      const encryptionResult = cryptoService.encryptMessage(template.content, sender.publicKey);
      
      const encryptedContent = encryptionResult.encryptedData;
      const aesKeyEncrypted = encryptionResult.encryptedKey;
      
      // Create message hash
      const messageHash = require('crypto')
        .createHash('sha256')
        .update(template.content)
        .digest('hex');

      messages.push({
        id: messageId,
        senderId: sender.id,
        encryptedContent,
        aesKeyEncrypted,
        messageHash,
        messageType: template.type
      });

    } catch (error) {
      logger.error('Error creating seed message', {
        messageIndex: i,
        senderId: sender.id,
        error: (error as Error).message
      });
    }
  }

  return messages;
}

/**
 * Insert users into database
 */
async function insertUsers(pool: Pool, users: SeedUser[]): Promise<void> {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    for (const user of users) {
      // Insert user
      await client.query(`
        INSERT INTO users (id, username, email, password_hash, salt, public_key, private_key_encrypted, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        ON CONFLICT (username) DO NOTHING
      `, [user.id, user.username, user.email, user.password, user.salt, user.publicKey, user.privateKeyEncrypted]);
      
      // Insert user keys into user_keys table (skip if already exists)
      const keyExists = await client.query(`
        SELECT 1 FROM user_keys WHERE user_id = $1 AND key_type = $2 LIMIT 1
      `, [user.id, 'rsa_public']);
      
      if (keyExists.rows.length === 0) {
        await client.query(`
          INSERT INTO user_keys (user_id, key_type, key_data, created_at)
          VALUES ($1, $2, $3, NOW())
        `, [user.id, 'rsa_public', user.publicKey]);
        
        await client.query(`
          INSERT INTO user_keys (user_id, key_type, key_data, created_at)
          VALUES ($1, $2, $3, NOW())
        `, [user.id, 'rsa_private', user.privateKeyEncrypted]);
      }
    }
    
    await client.query('COMMIT');
    logger.info(`Inserted ${users.length} seed users`);
    
  } catch (error) {
    await client.query('ROLLBACK');
    logger.error('Error inserting seed users', { error: (error as Error).message });
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Insert messages into database
 */
async function insertMessages(pool: Pool, messages: SeedMessage[]): Promise<void> {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    for (const message of messages) {
      await client.query(`
        INSERT INTO messages (id, sender_id, encrypted_content, aes_key_encrypted, message_hash, message_type, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (id) DO NOTHING
      `, [
        message.id,
        message.senderId,
        message.encryptedContent,
        message.aesKeyEncrypted,
        message.messageHash,
        message.messageType
      ]);
    }
    
    await client.query('COMMIT');
    logger.info(`Inserted ${messages.length} seed messages`);
    
  } catch (error) {
    await client.query('ROLLBACK');
    logger.error('Error inserting seed messages', { error: (error as Error).message });
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Insert audit log entries
 */
async function insertAuditLogs(pool: Pool, users: SeedUser[]): Promise<void> {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const auditEvents = [
      'USER_REGISTERED',
      'USER_LOGIN',
      'MESSAGE_SENT',
      'MESSAGE_RECEIVED',
      'KEY_GENERATED',
      'SESSION_CREATED'
    ];

    for (let i = 0; i < 20; i++) {
      const user = users[i % users.length];
      if (!user) continue;
      const event = auditEvents[i % auditEvents.length];
      
      await client.query(`
        INSERT INTO audit_logs (id, user_id, action, details, ip_address, user_agent, timestamp)
        VALUES ($1, $2, $3, $4, $5, $6, NOW() - INTERVAL '${i} hours')
        ON CONFLICT (id) DO NOTHING
      `, [
        uuidv4(),
        user.id,
        event,
        JSON.stringify({ demo: true, seeded: true }),
        '127.0.0.1',
        'SeedScript/1.0'
      ]);
    }
    
    await client.query('COMMIT');
    logger.info('Inserted audit log entries');
    
  } catch (error) {
    await client.query('ROLLBACK');
    logger.error('Error inserting audit logs', { error: (error as Error).message });
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Check if database already has seed data
 */
async function checkExistingData(pool: Pool): Promise<boolean> {
  const result = await pool.query('SELECT COUNT(*) FROM users WHERE username LIKE \'%_demo\'');
  const count = parseInt(result.rows[0].count);
  return count > 0;
}

/**
 * Clear existing seed data
 */
async function clearSeedData(pool: Pool): Promise<void> {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Delete in correct order due to foreign key constraints
    await client.query('DELETE FROM audit_logs WHERE user_agent = \'SeedScript/1.0\'');
    await client.query('DELETE FROM messages WHERE sender_id IN (SELECT id FROM users WHERE username LIKE \'%_demo\')');
    await client.query('DELETE FROM user_keys WHERE user_id IN (SELECT id FROM users WHERE username LIKE \'%_demo\')');
    await client.query('DELETE FROM users WHERE username LIKE \'%_demo\'');
    
    await client.query('COMMIT');
    logger.info('Cleared existing seed data');
    
  } catch (error) {
    await client.query('ROLLBACK');
    logger.error('Error clearing seed data', { error: (error as Error).message });
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Main seeding function
 */
async function seed(): Promise<void> {
  try {
    logger.info('Starting database seeding...');
    
    // Initialize database connection
    await initializeDatabase();
    
    // Check if seed data already exists
    const hasExistingData = await checkExistingData(pool);
    
    if (hasExistingData) {
      const shouldClear = process.argv.includes('--clear') || process.argv.includes('--force');
      
      if (shouldClear) {
        logger.info('Clearing existing seed data...');
        await clearSeedData(pool);
      } else {
        logger.info('Seed data already exists. Use --clear or --force to regenerate.');
        return;
      }
    }
    
    // Create seed data
    logger.info('Generating seed users...');
    const users = await createSeedUsers();
    
    logger.info('Generating seed messages...');
    const messages = await createSeedMessages(users);
    
    // Insert data
    logger.info('Inserting seed data into database...');
    await insertUsers(pool, users);
    await insertMessages(pool, messages);
    await insertAuditLogs(pool, users);
    
    logger.info('Database seeding completed successfully!');
    logger.info('Seed data summary:', {
      users: users.length,
      messages: messages.length,
      auditLogs: 20,
      demoUsers: users.map(u => ({ username: u.username, email: u.email }))
    });
    
    logger.info('Demo login credentials (for testing):');
    users.forEach((user, index) => {
      const originalPassword = ['SecurePass123!', 'StrongPass456!', 'SafePass789!', 'ProtectedPass012!', 'SecureKey345!'][index];
      logger.info(`  ${user.username}: ${originalPassword}`);
    });
    
  } catch (error) {
    logger.error('Database seeding failed', {
      error: (error as Error).message,
      stack: (error as Error).stack
    });
    throw error;
  } finally {
    await closeDatabaseConnection();
  }
}

// Run seeding if this file is executed directly
if (require.main === module) {
  seed()
    .then(() => {
      logger.info('Seeding process completed');
      process.exit(0);
    })
    .catch((error) => {
      logger.error('Seeding process failed', {
        error: error.message,
        stack: error.stack
      });
      process.exit(1);
    });
}

export { seed };