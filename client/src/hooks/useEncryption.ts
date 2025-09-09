import { useState, useCallback, useContext } from 'react';
import {
  generateRegistrationKeys,
  getUserPrivateKey,
  storeUserPrivateKey,
  encryptMessageForSending,
  decryptReceivedMessage,
  validateEncryptionKeys,
  generateSessionKey,
  cleanupEncryptionData,
  verifyUserPassword,
  formatRegistrationEncryptionData,
  parseEncryptedPrivateKeyData,
  isCryptoSupported,
  EncryptedRegistrationData,
  MessageEncryptionData
} from '../utils/encryption';
import { EncryptedPrivateKey } from '../services/cryptoService';

// Hook state interface
interface EncryptionState {
  isGeneratingKeys: boolean;
  isEncrypting: boolean;
  isDecrypting: boolean;
  error: string | null;
  isSupported: boolean;
}

// Hook return interface
interface UseEncryptionReturn {
  // State
  state: EncryptionState;
  
  // Key generation and management
  generateKeysForRegistration: (password: string) => Promise<EncryptedRegistrationData | null>;
  storePrivateKey: (userId: string, encryptedData: EncryptedPrivateKey) => boolean;
  retrievePrivateKey: (userId: string, password: string) => string | null;
  
  // Message encryption/decryption
  encryptMessage: (content: string, secretKey?: string) => MessageEncryptionData | null;
  decryptMessage: (encryptedData: MessageEncryptionData, secretKey: string) => string | null;
  
  // Utility functions
  validateKeys: (publicKey: string, privateKey?: string) => boolean;
  createSessionKey: () => string | null;
  verifyPassword: (userId: string, password: string) => boolean;
  
  // Cleanup
  cleanup: (userId?: string) => void;
  
  // Error handling
  clearError: () => void;
}

/**
 * Custom React hook for encryption operations
 * Provides a clean interface for all cryptographic operations in the application
 */
export function useEncryption(): UseEncryptionReturn {
  const [state, setState] = useState<EncryptionState>({
    isGeneratingKeys: false,
    isEncrypting: false,
    isDecrypting: false,
    error: null,
    isSupported: isCryptoSupported()
  });

  // Helper function to update state
  const updateState = useCallback((updates: Partial<EncryptionState>) => {
    setState(prev => ({ ...prev, ...updates }));
  }, []);

  // Clear error state
  const clearError = useCallback(() => {
    updateState({ error: null });
  }, [updateState]);

  // Handle errors consistently
  const handleError = useCallback((error: unknown, operation: string): null => {
    const errorMessage = error instanceof Error ? error.message : `Unknown error during ${operation}`;
    console.error(`Encryption error (${operation}):`, error);
    updateState({ error: errorMessage });
    return null;
  }, [updateState]);

  // Generate encryption keys for user registration
  const generateKeysForRegistration = useCallback(async (password: string): Promise<EncryptedRegistrationData | null> => {
    if (!state.isSupported) {
      updateState({ error: 'Encryption is not supported in this browser' });
      return null;
    }

    if (!password) {
      updateState({ error: 'Password is required for key generation' });
      return null;
    }

    updateState({ isGeneratingKeys: true, error: null });

    try {
      const keyData = await generateRegistrationKeys(password);
      updateState({ isGeneratingKeys: false });
      return keyData;
    } catch (error) {
      updateState({ isGeneratingKeys: false });
      return handleError(error, 'key generation');
    }
  }, [state.isSupported, updateState, handleError]);

  // Store encrypted private key
  const storePrivateKey = useCallback((userId: string, encryptedData: EncryptedPrivateKey): boolean => {
    if (!userId) {
      updateState({ error: 'User ID is required for storing private key' });
      return false;
    }

    try {
      storeUserPrivateKey(userId, encryptedData);
      return true;
    } catch (error) {
      handleError(error, 'storing private key');
      return false;
    }
  }, [updateState, handleError]);

  // Retrieve user's private key
  const retrievePrivateKey = useCallback((userId: string, password: string): string | null => {
    if (!userId || !password) {
      updateState({ error: 'User ID and password are required for retrieving private key' });
      return null;
    }

    try {
      return getUserPrivateKey(userId, password);
    } catch (error) {
      return handleError(error, 'retrieving private key');
    }
  }, [updateState, handleError]);

  // Encrypt a message
  const encryptMessage = useCallback((content: string, secretKey?: string): MessageEncryptionData | null => {
    if (!content) {
      updateState({ error: 'Message content is required for encryption' });
      return null;
    }

    updateState({ isEncrypting: true, error: null });

    try {
      const encrypted = encryptMessageForSending(content, secretKey);
      updateState({ isEncrypting: false });
      return encrypted;
    } catch (error) {
      updateState({ isEncrypting: false });
      return handleError(error, 'message encryption');
    }
  }, [updateState, handleError]);

  // Decrypt a message
  const decryptMessage = useCallback((
    encryptedData: MessageEncryptionData,
    secretKey: string
  ): string | null => {
    if (!encryptedData || !secretKey) {
      updateState({ error: 'Encrypted data and secret key are required for decryption' });
      return null;
    }

    updateState({ isDecrypting: true, error: null });

    try {
      const decrypted = decryptReceivedMessage(encryptedData, secretKey);
      updateState({ isDecrypting: false });
      return decrypted;
    } catch (error) {
      updateState({ isDecrypting: false });
      return handleError(error, 'message decryption');
    }
  }, [updateState, handleError]);

  // Validate encryption keys
  const validateKeys = useCallback((publicKey: string, privateKey?: string): boolean => {
    try {
      return validateEncryptionKeys(publicKey, privateKey);
    } catch (error) {
      handleError(error, 'key validation');
      return false;
    }
  }, [handleError]);

  // Create a new session key
  const createSessionKey = useCallback((): string | null => {
    try {
      return generateSessionKey();
    } catch (error) {
      return handleError(error, 'session key generation');
    }
  }, [handleError]);

  // Verify user password
  const verifyPassword = useCallback((userId: string, password: string): boolean => {
    if (!userId || !password) {
      updateState({ error: 'User ID and password are required for verification' });
      return false;
    }

    try {
      return verifyUserPassword(userId, password);
    } catch (error) {
      handleError(error, 'password verification');
      return false;
    }
  }, [updateState, handleError]);

  // Cleanup encryption data
  const cleanup = useCallback((userId?: string): void => {
    try {
      cleanupEncryptionData(userId);
      // Clear any encryption-related errors on cleanup
      updateState({ error: null });
    } catch (error) {
      handleError(error, 'cleanup');
    }
  }, [updateState, handleError]);

  return {
    state,
    generateKeysForRegistration,
    storePrivateKey,
    retrievePrivateKey,
    encryptMessage,
    decryptMessage,
    validateKeys,
    createSessionKey,
    verifyPassword,
    cleanup,
    clearError
  };
}

/**
 * Hook specifically for registration form
 * Provides simplified interface for registration-specific encryption operations
 */
export function useRegistrationEncryption() {
  const encryption = useEncryption();

  const generateAndFormatKeys = useCallback(async (password: string) => {
    const keyData = await encryption.generateKeysForRegistration(password);
    
    if (!keyData) {
      return null;
    }

    return formatRegistrationEncryptionData(keyData);
  }, [encryption]);

  return {
    ...encryption,
    generateAndFormatKeys
  };
}

/**
 * Hook specifically for message operations
 * Provides simplified interface for message encryption/decryption
 */
export function useMessageEncryption() {
  const encryption = useEncryption();
  const [currentSessionKey, setCurrentSessionKey] = useState<string | null>(null);

  // Initialize or get session key
  const getSessionKey = useCallback((): string | null => {
    if (currentSessionKey) {
      return currentSessionKey;
    }

    const newKey = encryption.createSessionKey();
    if (newKey) {
      setCurrentSessionKey(newKey);
    }
    return newKey;
  }, [currentSessionKey, encryption]);

  // Encrypt message with current session key
  const encryptWithSessionKey = useCallback((content: string): MessageEncryptionData | null => {
    const sessionKey = getSessionKey();
    if (!sessionKey) {
      return null;
    }

    return encryption.encryptMessage(content, sessionKey);
  }, [encryption, getSessionKey]);

  // Decrypt message with current session key
  const decryptWithSessionKey = useCallback((encryptedData: MessageEncryptionData): string | null => {
    const sessionKey = getSessionKey();
    if (!sessionKey) {
      return null;
    }

    return encryption.decryptMessage(encryptedData, sessionKey);
  }, [encryption, getSessionKey]);

  // Reset session key
  const resetSessionKey = useCallback(() => {
    setCurrentSessionKey(null);
  }, []);

  return {
    ...encryption,
    currentSessionKey,
    getSessionKey,
    encryptWithSessionKey,
    decryptWithSessionKey,
    resetSessionKey
  };
}

export default useEncryption;