import { Pool } from 'pg';
import { pool } from '../config/database';
import { cryptoService, KeyPair } from '../services/CryptoService';
import { logger } from '../utils/logger';

export interface UserKeyData {
  userId: string;
  publicKey: string;
  privateKey: string;
  createdAt: Date;
  updatedAt: Date;
}

export class UserKeysModel {
  private db: Pool;

  constructor() {
    this.db = pool;
  }

  /**
   * Generate and store new key pair for user
   */
  async generateAndStoreKeyPair(userId: string): Promise<KeyPair | null> {
    try {
      // Generate new key pair
      const keyPair = cryptoService.generateKeyPair();
      
      // Encrypt private key for storage
      const encryptedPrivateKey = cryptoService.encryptForStorage(keyPair.privateKey);
      
      // Update the users table with the new keys
      const query = `
        UPDATE users 
        SET public_key = $1, private_key_encrypted = $2, updated_at = NOW()
        WHERE id = $3
        RETURNING id, public_key, updated_at
      `;
      
      const result = await this.db.query(query, [keyPair.publicKey, encryptedPrivateKey, userId]);
      
      if (result.rows.length > 0) {
        logger.info(`Key pair generated and stored for user ${userId}`);
        return keyPair;
      }
      
      return null;
    } catch (error) {
      logger.error(`Failed to generate key pair for user ${userId}:`, error);
      return null;
    }
  }

  /**
   * Get user's public key
   */
  async getUserPublicKey(userId: string): Promise<string | null> {
    try {
      const query = 'SELECT public_key FROM users WHERE id = $1';
      const result = await this.db.query(query, [userId]);
      
      return result.rows.length > 0 ? result.rows[0].public_key : null;
    } catch (error) {
      logger.error(`Failed to get public key for user ${userId}:`, error);
      return null;
    }
  }

  /**
   * Get user's private key (decrypted)
   */
  async getUserPrivateKey(userId: string): Promise<string | null> {
    try {
      const query = 'SELECT private_key_encrypted FROM users WHERE id = $1';
      const result = await this.db.query(query, [userId]);
      
      if (result.rows.length > 0) {
        const encryptedPrivateKey = result.rows[0].private_key_encrypted;
        return cryptoService.decryptFromStorage(encryptedPrivateKey);
      }
      
      return null;
    } catch (error) {
      logger.error(`Failed to get private key for user ${userId}:`, error);
      return null;
    }
  }

  /**
   * Get all user key information
   */
  async getUserKeys(userId: string): Promise<UserKeyData | null> {
    try {
      const query = `
        SELECT id, public_key, private_key_encrypted, created_at, updated_at
        FROM users 
        WHERE id = $1
      `;
      const result = await this.db.query(query, [userId]);
      
      if (result.rows.length > 0) {
        const row = result.rows[0];
        const privateKey = cryptoService.decryptFromStorage(row.private_key_encrypted);
        
        return {
          userId: row.id,
          publicKey: row.public_key,
          privateKey,
          createdAt: row.created_at,
          updatedAt: row.updated_at
        };
      }
      
      return null;
    } catch (error) {
      logger.error(`Failed to get keys for user ${userId}:`, error);
      return null;
    }
  }

  /**
   * Check if user has keys
   */
  async userHasKeys(userId: string): Promise<boolean> {
    try {
      const query = 'SELECT 1 FROM users WHERE id = $1 AND public_key IS NOT NULL AND private_key_encrypted IS NOT NULL';
      const result = await this.db.query(query, [userId]);
      return result.rows.length > 0;
    } catch (error) {
      logger.error(`Failed to check keys for user ${userId}:`, error);
      return false;
    }
  }

  /**
   * Delete user's keys
   */
  async deleteUserKeys(userId: string): Promise<boolean> {
    try {
      const query = 'UPDATE users SET public_key = NULL, private_key_encrypted = NULL, updated_at = NOW() WHERE id = $1';
      const result = await this.db.query(query, [userId]);
      
      logger.info(`Keys deleted for user ${userId}`);
      return (result.rowCount ?? 0) > 0;
    } catch (error) {
      logger.error(`Failed to delete keys for user ${userId}:`, error);
      return false;
    }
  }

  /**
   * Get public keys for multiple users (for broadcasting)
   */
  async getMultipleUserPublicKeys(userIds: string[]): Promise<Record<string, string>> {
    try {
      const query = 'SELECT id, public_key FROM users WHERE id = ANY($1) AND public_key IS NOT NULL';
      const result = await this.db.query(query, [userIds]);
      
      const keyMap: Record<string, string> = {};
      result.rows.forEach(row => {
        keyMap[row.id] = row.public_key;
      });
      
      return keyMap;
    } catch (error) {
      logger.error('Failed to get multiple user public keys:', error);
      return {};
    }
  }

  /**
   * Verify user's key pair integrity
   */
  async verifyUserKeyPair(userId: string): Promise<boolean> {
    try {
      const keys = await this.getUserKeys(userId);
      if (!keys) return false;
      
      return cryptoService.verifyKeyPair(keys.publicKey, keys.privateKey);
    } catch (error) {
      logger.error(`Failed to verify key pair for user ${userId}:`, error);
      return false;
    }
  }
}

export const userKeysModel = new UserKeysModel();