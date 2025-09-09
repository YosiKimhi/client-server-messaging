import CryptoJS from 'crypto-js';

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export interface EncryptedPrivateKey {
  encryptedPrivateKey: string;
  salt: string;
  iv: string;
}

export interface EncryptedMessage {
  encryptedContent: string;
  iv: string;
}

class CryptoService {
  // Generate RSA key pair using Web Crypto API (2048-bit)
  async generateRSAKeyPair(): Promise<KeyPair> {
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true, // extractable
        ['encrypt', 'decrypt']
      );

      // Export public key in SPKI format (for PEM)
      const publicKeyArrayBuffer = await window.crypto.subtle.exportKey(
        'spki',
        keyPair.publicKey
      );

      // Export private key in PKCS8 format (for PEM)
      const privateKeyArrayBuffer = await window.crypto.subtle.exportKey(
        'pkcs8',
        keyPair.privateKey
      );

      // Convert to PEM format
      const publicKey = this.arrayBufferToPEM(publicKeyArrayBuffer, 'PUBLIC KEY');
      const privateKey = this.arrayBufferToPEM(privateKeyArrayBuffer, 'PRIVATE KEY');

      return {
        publicKey,
        privateKey,
      };
    } catch (error) {
      console.error('Error generating RSA key pair:', error);
      throw new Error('Failed to generate RSA key pair');
    }
  }

  // Convert ArrayBuffer to PEM format
  private arrayBufferToPEM(buffer: ArrayBuffer, label: string): string {
    const base64 = this.arrayBufferToBase64(buffer);
    const formatted = base64.match(/.{1,64}/g)?.join('\n') || base64;
    return `-----BEGIN ${label}-----\n${formatted}\n-----END ${label}-----`;
  }

  // Convert ArrayBuffer to base64
  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const binary = String.fromCharCode(...new Uint8Array(buffer));
    return window.btoa(binary);
  }

  // Encrypt private key with user password using AES-256
  encryptPrivateKey(privateKey: string, password: string): EncryptedPrivateKey {
    try {
      // Generate random salt and IV
      const salt = CryptoJS.lib.WordArray.random(32); // 256 bits
      const iv = CryptoJS.lib.WordArray.random(16); // 128 bits

      // Derive key from password using PBKDF2
      const key = CryptoJS.PBKDF2(password, salt, {
        keySize: 8, // 256 bits (8 * 32 bits)
        iterations: 10000,
        hasher: CryptoJS.algo.SHA256
      });

      // Encrypt private key
      const encrypted = CryptoJS.AES.encrypt(privateKey, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });

      return {
        encryptedPrivateKey: encrypted.toString(),
        salt: salt.toString(CryptoJS.enc.Hex),
        iv: iv.toString(CryptoJS.enc.Hex)
      };
    } catch (error) {
      console.error('Error encrypting private key:', error);
      throw new Error('Failed to encrypt private key');
    }
  }

  // Decrypt private key with user password
  decryptPrivateKey(
    encryptedData: EncryptedPrivateKey,
    password: string
  ): string {
    try {
      // Parse salt and IV from hex strings
      const salt = CryptoJS.enc.Hex.parse(encryptedData.salt);
      const iv = CryptoJS.enc.Hex.parse(encryptedData.iv);

      // Derive key from password using same parameters
      const key = CryptoJS.PBKDF2(password, salt, {
        keySize: 8, // 256 bits
        iterations: 10000,
        hasher: CryptoJS.algo.SHA256
      });

      // Decrypt private key
      const decrypted = CryptoJS.AES.decrypt(
        encryptedData.encryptedPrivateKey,
        key,
        {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        }
      );

      const privateKey = decrypted.toString(CryptoJS.enc.Utf8);
      
      if (!privateKey) {
        throw new Error('Invalid password or corrupted data');
      }

      return privateKey;
    } catch (error) {
      console.error('Error decrypting private key:', error);
      throw new Error('Failed to decrypt private key. Check your password.');
    }
  }

  // Encrypt message content using AES-256
  encryptMessage(content: string, secretKey?: string): EncryptedMessage {
    try {
      // Use provided key or generate a random one
      const key = secretKey 
        ? CryptoJS.enc.Utf8.parse(secretKey) 
        : CryptoJS.lib.WordArray.random(32); // 256 bits

      const iv = CryptoJS.lib.WordArray.random(16); // 128 bits

      const encrypted = CryptoJS.AES.encrypt(content, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });

      return {
        encryptedContent: encrypted.toString(),
        iv: iv.toString(CryptoJS.enc.Hex)
      };
    } catch (error) {
      console.error('Error encrypting message:', error);
      throw new Error('Failed to encrypt message');
    }
  }

  // Decrypt message content using AES-256
  decryptMessage(
    encryptedMessage: EncryptedMessage,
    secretKey: string
  ): string {
    try {
      const key = CryptoJS.enc.Utf8.parse(secretKey);
      const iv = CryptoJS.enc.Hex.parse(encryptedMessage.iv);

      const decrypted = CryptoJS.AES.decrypt(
        encryptedMessage.encryptedContent,
        key,
        {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        }
      );

      const content = decrypted.toString(CryptoJS.enc.Utf8);
      
      if (!content) {
        throw new Error('Invalid key or corrupted message');
      }

      return content;
    } catch (error) {
      console.error('Error decrypting message:', error);
      throw new Error('Failed to decrypt message');
    }
  }

  // Generate random AES key for message encryption
  generateAESKey(): string {
    const key = CryptoJS.lib.WordArray.random(32); // 256 bits
    return key.toString(CryptoJS.enc.Hex);
  }

  // Hash password for verification (not for storage - server handles that)
  hashPassword(password: string): string {
    return CryptoJS.SHA256(password).toString(CryptoJS.enc.Hex);
  }

  // Validate RSA key format
  validateRSAKey(key: string, type: 'public' | 'private'): boolean {
    const keyType = type.toUpperCase();
    const beginMarker = `-----BEGIN ${keyType} KEY-----`;
    const endMarker = `-----END ${keyType} KEY-----`;
    
    return key.includes(beginMarker) && key.includes(endMarker);
  }

  // Generate secure random string for session keys
  generateSecureRandomString(length: number): string {
    const array = new Uint8Array(length);
    window.crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  // Store encrypted private key in localStorage
  storeEncryptedPrivateKey(
    userId: string,
    encryptedPrivateKey: EncryptedPrivateKey
  ): void {
    try {
      const key = `encrypted_private_key_${userId}`;
      localStorage.setItem(key, JSON.stringify(encryptedPrivateKey));
    } catch (error) {
      console.error('Error storing encrypted private key:', error);
      throw new Error('Failed to store private key');
    }
  }

  // Retrieve encrypted private key from localStorage
  getStoredEncryptedPrivateKey(userId: string): EncryptedPrivateKey | null {
    try {
      const key = `encrypted_private_key_${userId}`;
      const stored = localStorage.getItem(key);
      return stored ? JSON.parse(stored) : null;
    } catch (error) {
      console.error('Error retrieving encrypted private key:', error);
      return null;
    }
  }

  // Remove stored encrypted private key
  removeStoredPrivateKey(userId: string): void {
    try {
      const key = `encrypted_private_key_${userId}`;
      localStorage.removeItem(key);
    } catch (error) {
      console.error('Error removing stored private key:', error);
    }
  }

  // Clear all stored encryption data
  clearAllEncryptionData(): void {
    try {
      // Get all keys from localStorage
      const keys = Object.keys(localStorage);
      
      // Remove all encryption-related keys
      keys.forEach(key => {
        if (key.startsWith('encrypted_private_key_')) {
          localStorage.removeItem(key);
        }
      });
    } catch (error) {
      console.error('Error clearing encryption data:', error);
    }
  }
}

// Export singleton instance
export const cryptoService = new CryptoService();
export default cryptoService;