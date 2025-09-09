import { cryptoService, KeyPair, EncryptedPrivateKey, EncryptedMessage } from '../services/cryptoService';

// Type definitions for encrypted registration data
export interface EncryptedRegistrationData {
  publicKey: string;
  encryptedPrivateKey: string;
  salt: string;
  iv: string;
}

// Type definitions for message encryption
export interface MessageEncryptionData {
  encryptedContent: string;
  iv: string;
  timestamp: number;
}

/**
 * Generate encryption keys for user registration
 * @param password - User's password for encrypting private key
 * @returns Promise containing public key and encrypted private key data
 */
export async function generateRegistrationKeys(password: string): Promise<EncryptedRegistrationData> {
  try {
    // Generate RSA key pair
    const keyPair: KeyPair = await cryptoService.generateRSAKeyPair();
    
    // Encrypt private key with user's password
    const encryptedPrivateKey: EncryptedPrivateKey = cryptoService.encryptPrivateKey(
      keyPair.privateKey,
      password
    );

    return {
      publicKey: keyPair.publicKey,
      encryptedPrivateKey: encryptedPrivateKey.encryptedPrivateKey,
      salt: encryptedPrivateKey.salt,
      iv: encryptedPrivateKey.iv
    };
  } catch (error) {
    console.error('Error generating registration keys:', error);
    throw new Error('Failed to generate encryption keys for registration');
  }
}

/**
 * Decrypt and retrieve user's private key
 * @param userId - User's ID for storage key
 * @param password - User's password for decryption
 * @returns Decrypted private key or null if not found/invalid
 */
export function getUserPrivateKey(userId: string, password: string): string | null {
  try {
    const storedData = cryptoService.getStoredEncryptedPrivateKey(userId);
    
    if (!storedData) {
      console.warn('No stored private key found for user:', userId);
      return null;
    }

    return cryptoService.decryptPrivateKey(storedData, password);
  } catch (error) {
    console.error('Error retrieving user private key:', error);
    return null;
  }
}

/**
 * Store user's encrypted private key after successful registration/login
 * @param userId - User's ID
 * @param encryptedData - Encrypted private key data
 */
export function storeUserPrivateKey(
  userId: string,
  encryptedData: EncryptedPrivateKey
): void {
  try {
    cryptoService.storeEncryptedPrivateKey(userId, encryptedData);
  } catch (error) {
    console.error('Error storing user private key:', error);
    throw new Error('Failed to store encryption key');
  }
}

/**
 * Encrypt a message before sending
 * @param content - Message content to encrypt
 * @param secretKey - Optional secret key (generates random if not provided)
 * @returns Encrypted message data with timestamp
 */
export function encryptMessageForSending(
  content: string,
  secretKey?: string
): MessageEncryptionData {
  try {
    const encrypted: EncryptedMessage = cryptoService.encryptMessage(content, secretKey);
    
    return {
      encryptedContent: encrypted.encryptedContent,
      iv: encrypted.iv,
      timestamp: Date.now()
    };
  } catch (error) {
    console.error('Error encrypting message:', error);
    throw new Error('Failed to encrypt message');
  }
}

/**
 * Decrypt a received message
 * @param encryptedData - Encrypted message data
 * @param secretKey - Secret key for decryption
 * @returns Decrypted message content
 */
export function decryptReceivedMessage(
  encryptedData: MessageEncryptionData,
  secretKey: string
): string {
  try {
    const encryptedMessage: EncryptedMessage = {
      encryptedContent: encryptedData.encryptedContent,
      iv: encryptedData.iv
    };

    return cryptoService.decryptMessage(encryptedMessage, secretKey);
  } catch (error) {
    console.error('Error decrypting received message:', error);
    throw new Error('Failed to decrypt message');
  }
}

/**
 * Validate encryption key formats
 * @param publicKey - RSA public key in PEM format
 * @param privateKey - RSA private key in PEM format (optional)
 * @returns Boolean indicating if keys are valid
 */
export function validateEncryptionKeys(
  publicKey: string,
  privateKey?: string
): boolean {
  try {
    // Validate public key
    if (!cryptoService.validateRSAKey(publicKey, 'public')) {
      console.error('Invalid public key format');
      return false;
    }

    // Validate private key if provided
    if (privateKey && !cryptoService.validateRSAKey(privateKey, 'private')) {
      console.error('Invalid private key format');
      return false;
    }

    return true;
  } catch (error) {
    console.error('Error validating encryption keys:', error);
    return false;
  }
}

/**
 * Generate a secure session key for message encryption
 * @returns Random AES key in hex format
 */
export function generateSessionKey(): string {
  try {
    return cryptoService.generateAESKey();
  } catch (error) {
    console.error('Error generating session key:', error);
    throw new Error('Failed to generate session key');
  }
}

/**
 * Clean up encryption data on logout
 * @param userId - User's ID (optional, clears all if not provided)
 */
export function cleanupEncryptionData(userId?: string): void {
  try {
    if (userId) {
      cryptoService.removeStoredPrivateKey(userId);
    } else {
      cryptoService.clearAllEncryptionData();
    }
  } catch (error) {
    console.error('Error cleaning up encryption data:', error);
  }
}

/**
 * Verify user password by attempting to decrypt their private key
 * @param userId - User's ID
 * @param password - Password to verify
 * @returns Boolean indicating if password is correct
 */
export function verifyUserPassword(userId: string, password: string): boolean {
  try {
    const privateKey = getUserPrivateKey(userId, password);
    return privateKey !== null;
  } catch (error) {
    console.error('Error verifying user password:', error);
    return false;
  }
}

/**
 * Format encryption data for server registration request
 * @param encryptedData - Encrypted registration data
 * @returns Formatted data for server API
 */
export function formatRegistrationEncryptionData(
  encryptedData: EncryptedRegistrationData
): { public_key: string; private_key_encrypted: string } {
  try {
    // Combine encrypted private key data into a single string
    const privateKeyData = JSON.stringify({
      encryptedPrivateKey: encryptedData.encryptedPrivateKey,
      salt: encryptedData.salt,
      iv: encryptedData.iv
    });

    return {
      public_key: encryptedData.publicKey,
      private_key_encrypted: privateKeyData
    };
  } catch (error) {
    console.error('Error formatting encryption data:', error);
    throw new Error('Failed to format encryption data');
  }
}

/**
 * Parse encrypted private key data from server response
 * @param encryptedDataString - JSON string containing encrypted private key data or Base64 encoded key
 * @returns Parsed encrypted private key data
 */
export function parseEncryptedPrivateKeyData(
  encryptedDataString: string
): EncryptedPrivateKey {
  try {
    // Try to parse as JSON first (new format)
    try {
      const parsed = JSON.parse(encryptedDataString);
      
      if (parsed.encryptedPrivateKey && parsed.salt && parsed.iv) {
        return {
          encryptedPrivateKey: parsed.encryptedPrivateKey,
          salt: parsed.salt,
          iv: parsed.iv
        };
      }
    } catch {
      // Not JSON, continue to Base64 handling
    }
    
    // Handle Base64 encoded RSA private key (legacy/seed format)
    // For demo purposes, we'll create dummy salt and iv for the Base64 format
    // In a real application, you'd want to properly migrate this data
    return {
      encryptedPrivateKey: encryptedDataString, // Base64 encoded RSA private key
      salt: 'demo_salt', // Placeholder for compatibility
      iv: 'demo_iv' // Placeholder for compatibility
    };
  } catch (error) {
    console.error('Error parsing encrypted private key data:', error);
    throw new Error('Failed to parse encrypted private key data');
  }
}

/**
 * Check if Web Crypto API is available
 * @returns Boolean indicating if crypto operations are supported
 */
export function isCryptoSupported(): boolean {
  try {
    return !!(window.crypto && window.crypto.subtle);
  } catch (error) {
    console.error('Crypto API not supported:', error);
    return false;
  }
}

/**
 * Generate a secure random password suggestion
 * @param length - Password length (default: 16)
 * @returns Secure random password
 */
export function generateSecurePassword(length: number = 16): string {
  try {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    const randomString = cryptoService.generateSecureRandomString(length);
    
    // Convert hex string to password using charset
    let password = '';
    for (let i = 0; i < length; i++) {
      const randomIndex = parseInt(randomString.substr(i * 2, 2), 16) % charset.length;
      password += charset[randomIndex];
    }
    
    return password;
  } catch (error) {
    console.error('Error generating secure password:', error);
    throw new Error('Failed to generate secure password');
  }
}

// Export crypto service for direct access if needed
export { cryptoService };