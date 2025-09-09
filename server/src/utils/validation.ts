import { body, validationResult, ValidationChain } from 'express-validator';
import { Request, Response, NextFunction } from 'express';
import { ValidationError } from '../types';
import { logger } from './logger';

// Validation error handler middleware
export function handleValidationErrors(req: Request, res: Response, next: NextFunction): void {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const errorArray = errors.array();
    const firstError = errorArray[0];
    
    if (firstError) {
      logger.warn('Validation error occurred', {
        path: req.path,
        method: req.method,
        errors: errorArray,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      const validationError: ValidationError = new Error(firstError.msg);
      if ('path' in firstError && firstError.path) {
        validationError.field = firstError.path;
      }
      if ('value' in firstError) {
        validationError.value = firstError.value;
      }
      validationError.name = 'ValidationError';
      
      res.status(400).json({
        error: {
          message: firstError.msg,
          field: 'path' in firstError ? firstError.path : 'unknown',
          code: 'VALIDATION_ERROR'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
      return;
    }
  }
  
  next();
}

// Username validation rules
export const validateUsername = (): ValidationChain => {
  return body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username can only contain letters, numbers, underscores, and hyphens')
    .custom(async (value: string) => {
      // Check for reserved usernames
      const reservedUsernames = ['admin', 'root', 'system', 'api', 'www', 'support', 'help'];
      if (reservedUsernames.includes(value.toLowerCase())) {
        throw new Error('This username is reserved');
      }
      return true;
    });
};

// Email validation rules
export const validateEmail = (): ValidationChain => {
  return body('email')
    .trim()
    .toLowerCase()
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail({
      gmail_remove_dots: false,
      gmail_remove_subaddress: false,
      outlookdotcom_remove_subaddress: false,
      yahoo_remove_subaddress: false,
      icloud_remove_subaddress: false
    })
    .isLength({ max: 100 })
    .withMessage('Email address is too long');
};

// Password validation rules
export const validatePassword = (): ValidationChain => {
  return body('password')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be between 8 and 128 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character (@$!%*?&)')
    .custom((value: string) => {
      // Check for common weak passwords
      const commonPasswords = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'password123', 'admin123', 'letmein', 'welcome', 'monkey'
      ];
      
      if (commonPasswords.some(weak => value.toLowerCase().includes(weak))) {
        throw new Error('Password contains common weak patterns');
      }
      
      // Check for sequences and repetitions
      if (/(.)\1{2,}/.test(value)) {
        throw new Error('Password cannot contain repeated characters');
      }
      
      if (/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(value)) {
        throw new Error('Password cannot contain sequential characters');
      }
      
      return true;
    });
};

// Public key validation (for RSA keys)
export const validatePublicKey = (): ValidationChain => {
  return body('public_key')
    .trim()
    .notEmpty()
    .withMessage('Public key is required')
    .matches(/^-----BEGIN (RSA )?PUBLIC KEY-----[\s\S]*-----END (RSA )?PUBLIC KEY-----$/)
    .withMessage('Invalid public key format')
    .isLength({ min: 200, max: 2000 })
    .withMessage('Public key length is invalid');
};

// Private key validation (for encrypted RSA keys)
export const validatePrivateKeyEncrypted = (): ValidationChain => {
  return body('private_key_encrypted')
    .trim()
    .notEmpty()
    .withMessage('Encrypted private key is required')
    .isLength({ min: 100, max: 5000 })
    .withMessage('Encrypted private key length is invalid');
};

// Registration validation rules
export const validateRegistration = (): ValidationChain[] => {
  return [
    validateUsername(),
    validateEmail(),
    validatePassword(),
    validatePublicKey(),
    validatePrivateKeyEncrypted()
  ];
};

// Login validation rules
export const validateLogin = (): ValidationChain[] => {
  return [
    body('username')
      .trim()
      .notEmpty()
      .withMessage('Username is required')
      .isLength({ max: 30 })
      .withMessage('Username is too long'),
    body('password')
      .notEmpty()
      .withMessage('Password is required')
      .isLength({ max: 128 })
      .withMessage('Password is too long')
  ];
};

// Message validation rules
export const validateMessage = (): ValidationChain[] => {
  return [
    body('encrypted_content')
      .trim()
      .notEmpty()
      .withMessage('Message content is required')
      .isLength({ max: 10000 })
      .withMessage('Message content is too long'),
    body('aes_key_encrypted')
      .trim()
      .notEmpty()
      .withMessage('Encrypted AES key is required')
      .isLength({ max: 1000 })
      .withMessage('Encrypted AES key is too long'),
    body('message_hash')
      .trim()
      .notEmpty()
      .withMessage('Message hash is required')
      .matches(/^[a-f0-9]{64}$/)
      .withMessage('Invalid message hash format'),
    body('message_type')
      .optional()
      .isIn(['text', 'system', 'notification'])
      .withMessage('Invalid message type'),
    body('recipient_id')
      .optional()
      .isUUID()
      .withMessage('Invalid recipient ID format')
  ];
};

// Sanitization utility functions
export function sanitizeString(input: string, maxLength: number = 1000): string {
  if (typeof input !== 'string') {
    return '';
  }
  
  return input
    .trim()
    .substring(0, maxLength)
    // Remove null bytes
    .replace(/\0/g, '')
    // Remove control characters except newlines and tabs
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

// HTML entity encoding for preventing XSS
export function escapeHtml(text: string): string {
  const map: { [key: string]: string } = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  
  return text.replace(/[&<>"']/g, (m) => map[m] || m);
}

// SQL injection prevention helper
export function sanitizeForDatabase(input: string): string {
  // Remove or escape potentially dangerous SQL characters
  return sanitizeString(input)
    .replace(/'/g, "''")  // Escape single quotes
    .replace(/;/g, '')    // Remove semicolons
    .replace(/--/g, '')   // Remove SQL comments
    .replace(/\/\*/g, '') // Remove block comment starts
    .replace(/\*\//g, ''); // Remove block comment ends
}

// Rate limiting key generator
export function generateRateLimitKey(req: Request, suffix?: string): string {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const userAgent = req.get('User-Agent') || 'unknown';
  
  // Create a simple hash for the user agent to avoid extremely long keys
  const uaHash = Buffer.from(userAgent).toString('base64').substring(0, 16);
  
  return `${ip}:${uaHash}${suffix ? `:${suffix}` : ''}`;
}

// Security headers utility
export function setSecurityHeaders(res: Response): void {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
}

// Request ID generator for tracking
export function generateRequestId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// Audit log helper for security events
export function logSecurityEvent(
  action: string,
  req: Request,
  userId?: string,
  additionalDetails?: Record<string, any>
): void {
  logger.info(`Security event: ${action}`, {
    action,
    userId,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    path: req.path,
    method: req.method,
    timestamp: new Date(),
    ...additionalDetails
  });
}