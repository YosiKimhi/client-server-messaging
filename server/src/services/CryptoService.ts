import crypto from 'crypto';
import NodeRSA from 'node-rsa';
import { logger } from '../utils/logger';

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export interface EncryptedMessage {
  encryptedData: string;
  encryptedKey: string;
  iv: string;
}

export class CryptoService {
  private static instance: CryptoService;
  
  public static getInstance(): CryptoService {
    if (!CryptoService.instance) {
      CryptoService.instance = new CryptoService();
    }
    return CryptoService.instance;
  }

  /**
   * Generate RSA key pair (2048-bit)
   */
  public generateKeyPair(): KeyPair {
    try {
      const key = new NodeRSA({ b: 2048 });
      
      return {
        publicKey: key.exportKey('public'),
        privateKey: key.exportKey('private')
      };
    } catch (error) {
      logger.error('Failed to generate RSA key pair:', error);
      throw new Error('Key pair generation failed');
    }
  }

  /**
   * Encrypt message using hybrid RSA+AES encryption
   * - Generate random AES key
   * - Encrypt message with AES
   * - Encrypt AES key with RSA public key
   */
  public encryptMessage(message: string, publicKey: string): EncryptedMessage {
    try {
      // Generate random AES key and IV
      const aesKey = crypto.randomBytes(32); // 256-bit key
      const iv = crypto.randomBytes(16);     // 128-bit IV

      // Encrypt message with AES-256-CBC
      const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
      cipher.setAutoPadding(true);
      let encryptedData = cipher.update(message, 'utf8', 'base64');
      encryptedData += cipher.final('base64');

      // Encrypt AES key with RSA public key
      const rsa = new NodeRSA(publicKey);
      const encryptedKey = rsa.encrypt(aesKey, 'base64');

      return {
        encryptedData,
        encryptedKey,
        iv: iv.toString('base64')
      };
    } catch (error) {
      logger.error('Message encryption failed:', error);
      throw new Error('Message encryption failed');
    }
  }

  /**
   * Decrypt message using hybrid RSA+AES decryption
   */
  public decryptMessage(encryptedMessage: EncryptedMessage, privateKey: string): string {
    try {
      // Decrypt AES key with RSA private key
      const rsa = new NodeRSA(privateKey);
      const aesKey = rsa.decrypt(encryptedMessage.encryptedKey, 'buffer');
      
      // Decrypt message with AES
      const iv = Buffer.from(encryptedMessage.iv, 'base64');
      const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
      decipher.setAutoPadding(true);
      let decrypted = decipher.update(encryptedMessage.encryptedData, 'base64', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      logger.error('Message decryption failed:', error);
      throw new Error('Message decryption failed');
    }
  }

  /**
   * Encrypt data for database storage using AES with server key
   */
  public encryptForStorage(data: string): string {
    try {
      const serverKey = process.env.DB_ENCRYPTION_KEY || 'default-server-key-change-in-production';
      const cipher = crypto.createCipher('aes-256-cbc', serverKey);
      let encrypted = cipher.update(data, 'utf8', 'base64');
      encrypted += cipher.final('base64');
      return encrypted;
    } catch (error) {
      logger.error('Storage encryption failed:', error);
      throw new Error('Storage encryption failed');
    }
  }

  /**
   * Decrypt data from database storage
   */
  public decryptFromStorage(encryptedData: string): string {
    try {
      const serverKey = process.env.DB_ENCRYPTION_KEY || 'default-server-key-change-in-production';
      const decipher = crypto.createDecipher('aes-256-cbc', serverKey);
      let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (error) {
      logger.error('Storage decryption failed:', error);
      throw new Error('Storage decryption failed');
    }
  }

  /**
   * Generate secure random token
   */
  public generateSecureToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Hash data using SHA-256
   */
  public hash(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Verify RSA key pair validity
   */
  public verifyKeyPair(publicKey: string, privateKey: string): boolean {
    try {
      const testMessage = 'test-message-for-verification';
      const encrypted = this.encryptMessage(testMessage, publicKey);
      const decrypted = this.decryptMessage(encrypted, privateKey);
      return decrypted === testMessage;
    } catch (error) {
      return false;
    }
  }
}

export const cryptoService = CryptoService.getInstance();