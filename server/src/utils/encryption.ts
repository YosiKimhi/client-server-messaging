import { cryptoService, EncryptedMessage } from '../services/CryptoService';
import { logger } from './logger';

/**
 * Utility functions for message encryption workflow
 */

export interface MessageEncryptionResult {
  success: boolean;
  encryptedMessage?: EncryptedMessage;
  error?: string;
}

export interface MessageDecryptionResult {
  success: boolean;
  decryptedMessage?: string;
  error?: string;
}

/**
 * Encrypt a message for a specific recipient using their public key
 */
export function encryptMessageForRecipient(
  message: string,
  recipientPublicKey: string
): MessageEncryptionResult {
  try {
    const encryptedMessage = cryptoService.encryptMessage(message, recipientPublicKey);
    
    logger.debug('Message encrypted successfully for recipient');
    
    return {
      success: true,
      encryptedMessage
    };
  } catch (error) {
    logger.error('Failed to encrypt message for recipient:', error);
    
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Encryption failed'
    };
  }
}

/**
 * Decrypt a message using recipient's private key
 */
export function decryptMessageForRecipient(
  encryptedMessage: EncryptedMessage,
  recipientPrivateKey: string
): MessageDecryptionResult {
  try {
    const decryptedMessage = cryptoService.decryptMessage(encryptedMessage, recipientPrivateKey);
    
    logger.debug('Message decrypted successfully');
    
    return {
      success: true,
      decryptedMessage
    };
  } catch (error) {
    logger.error('Failed to decrypt message:', error);
    
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Decryption failed'
    };
  }
}

/**
 * Prepare message for database storage (encrypt with server key)
 */
export function prepareMessageForStorage(message: EncryptedMessage): string {
  try {
    const messageData = JSON.stringify(message);
    return cryptoService.encryptForStorage(messageData);
  } catch (error) {
    logger.error('Failed to prepare message for storage:', error);
    throw new Error('Storage preparation failed');
  }
}

/**
 * Retrieve message from database storage (decrypt with server key)
 */
export function retrieveMessageFromStorage(encryptedData: string): EncryptedMessage {
  try {
    const decryptedData = cryptoService.decryptFromStorage(encryptedData);
    return JSON.parse(decryptedData) as EncryptedMessage;
  } catch (error) {
    logger.error('Failed to retrieve message from storage:', error);
    throw new Error('Storage retrieval failed');
  }
}

/**
 * Validate encryption parameters
 */
export function validateEncryptionParams(message: string, publicKey: string): boolean {
  if (!message || message.trim().length === 0) {
    return false;
  }
  
  if (!publicKey || !publicKey.includes('PUBLIC KEY')) {
    return false;
  }
  
  return true;
}

/**
 * Validate decryption parameters
 */
export function validateDecryptionParams(
  encryptedMessage: EncryptedMessage,
  privateKey: string
): boolean {
  if (!encryptedMessage || !encryptedMessage.encryptedData || !encryptedMessage.encryptedKey) {
    return false;
  }
  
  if (!privateKey || !privateKey.includes('PRIVATE KEY')) {
    return false;
  }
  
  return true;
}