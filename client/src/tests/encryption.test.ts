// Basic test file for encryption functionality
// This would normally be run with a testing framework like Jest

import { cryptoService } from '../services/cryptoService';
import {
  generateRegistrationKeys,
  encryptMessageForSending,
  decryptReceivedMessage,
  formatRegistrationEncryptionData,
  parseEncryptedPrivateKeyData,
  validateEncryptionKeys,
  isCryptoSupported
} from '../utils/encryption';

// Test function to validate encryption functionality
export async function testEncryptionFlow() {
  console.log('🔒 Starting encryption flow test...');

  try {
    // 1. Check crypto support
    const isSupported = isCryptoSupported();
    console.log('✅ Crypto support:', isSupported);

    if (!isSupported) {
      console.error('❌ Crypto API not supported in this environment');
      return false;
    }

    // 2. Generate registration keys
    console.log('🔑 Testing key generation...');
    const password = 'TestPassword123!';
    const keyData = await generateRegistrationKeys(password);
    console.log('✅ Key generation successful');
    console.log('  - Public key length:', keyData.publicKey.length);
    console.log('  - Encrypted private key length:', keyData.encryptedPrivateKey.length);

    // 3. Validate key formats
    console.log('🔍 Validating key formats...');
    const isPublicKeyValid = validateEncryptionKeys(keyData.publicKey);
    console.log('✅ Public key validation:', isPublicKeyValid);

    // 4. Format for server
    console.log('📤 Testing server format conversion...');
    const serverFormat = formatRegistrationEncryptionData(keyData);
    console.log('✅ Server format created');
    console.log('  - Public key starts with:', serverFormat.public_key.substring(0, 30) + '...');

    // 5. Parse back from server format
    console.log('📥 Testing server format parsing...');
    const parsedData = parseEncryptedPrivateKeyData(serverFormat.private_key_encrypted);
    console.log('✅ Server format parsing successful');

    // 6. Test private key decryption
    console.log('🔓 Testing private key decryption...');
    const decryptedPrivateKey = cryptoService.decryptPrivateKey(parsedData, password);
    console.log('✅ Private key decryption successful');

    // 7. Test message encryption/decryption
    console.log('💬 Testing message encryption...');
    const testMessage = 'This is a test message for encryption!';
    const sessionKey = cryptoService.generateAESKey();
    
    const encryptedMessage = encryptMessageForSending(testMessage, sessionKey);
    console.log('✅ Message encryption successful');
    console.log('  - Encrypted content length:', encryptedMessage.encryptedContent.length);

    const decryptedMessage = decryptReceivedMessage(encryptedMessage, sessionKey);
    console.log('✅ Message decryption successful');
    console.log('  - Original message:', testMessage);
    console.log('  - Decrypted message:', decryptedMessage);
    console.log('  - Messages match:', testMessage === decryptedMessage);

    // 8. Test wrong password scenario
    console.log('🚫 Testing wrong password...');
    try {
      cryptoService.decryptPrivateKey(parsedData, 'WrongPassword123!');
      console.error('❌ Wrong password test failed - should have thrown error');
      return false;
    } catch (error) {
      console.log('✅ Wrong password correctly rejected');
    }

    console.log('🎉 All encryption tests passed!');
    return true;

  } catch (error) {
    console.error('❌ Encryption test failed:', error);
    return false;
  }
}

// Test function for browser compatibility
export function testBrowserSupport() {
  console.log('🌐 Testing browser support...');

  const tests = {
    webCrypto: !!(window.crypto && window.crypto.subtle),
    generateKey: !!(window.crypto?.subtle?.generateKey),
    exportKey: !!(window.crypto?.subtle?.exportKey),
    localStorage: !!window.localStorage,
    btoa: !!window.btoa,
    atob: !!window.atob
  };

  console.log('Browser support results:', tests);

  const allSupported = Object.values(tests).every(test => test);
  console.log('✅ All features supported:', allSupported);

  return tests;
}

// Performance test for key generation
export async function testKeyGenerationPerformance() {
  console.log('⚡ Testing key generation performance...');

  const iterations = 3;
  const times: number[] = [];

  for (let i = 0; i < iterations; i++) {
    const startTime = performance.now();
    
    try {
      await generateRegistrationKeys('TestPassword123!');
      const endTime = performance.now();
      const duration = endTime - startTime;
      times.push(duration);
      console.log(`  Iteration ${i + 1}: ${duration.toFixed(2)}ms`);
    } catch (error) {
      console.error(`  Iteration ${i + 1} failed:`, error);
    }
  }

  if (times.length > 0) {
    const avgTime = times.reduce((a, b) => a + b) / times.length;
    console.log(`✅ Average key generation time: ${avgTime.toFixed(2)}ms`);
    
    if (avgTime > 5000) {
      console.warn('⚠️  Key generation is slow (>5s), consider optimization');
    }
  }

  return times;
}

// Export for manual testing in browser console
(window as any).testEncryption = {
  testEncryptionFlow,
  testBrowserSupport,
  testKeyGenerationPerformance
};