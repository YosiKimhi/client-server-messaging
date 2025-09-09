import dotenv from 'dotenv';
import { logger } from '@/utils/logger';

// Load environment variables
dotenv.config();

/**
 * Server configuration interface
 */
export interface ServerConfig {
  // Server settings
  NODE_ENV: 'development' | 'production' | 'test';
  PORT: number;
  HOST: string;
  TRUST_PROXY: boolean;

  // Database settings
  database: {
    host: string;
    port: number;
    database: string;
    user: string;
    password: string;
    ssl: boolean | object;
    pool: {
      max: number;
      min: number;
      idleTimeoutMillis: number;
      connectionTimeoutMillis: number;
      queryTimeoutMillis: number;
      statementTimeoutMillis: number;
    };
  };

  // JWT settings
  jwt: {
    secret: string;
    expiresIn: string;
  };

  // Password hashing
  bcrypt: {
    rounds: number;
  };

  // Rate limiting
  rateLimiting: {
    general: {
      windowMs: number;
      maxRequests: number;
    };
    auth: {
      windowMs: number;
      maxRequests: number;
    };
    register: {
      windowMs: number;
      maxRequests: number;
    };
  };

  // CORS settings
  cors: {
    origin: string | string[] | boolean;
    credentials: boolean;
  };

  // Security settings
  security: {
    helmetEnabled: boolean;
    cspEnabled: boolean;
    hstsEnabled: boolean;
    secureCookies: boolean;
  };

  // SSL/TLS settings
  ssl?: {
    certPath?: string;
    keyPath?: string;
    caPath?: string;
  };

  // Session settings
  session: {
    cleanupIntervalMs: number;
  };

  // Encryption settings
  encryption: {
    rsaKeySize: number;
    aesKeyLength: number;
  };

  // Logging settings
  logging: {
    level: string;
    file?: string;
    maxSize?: string;
    maxFiles?: number;
    datePattern?: string;
  };

  // Feature flags
  features: {
    healthCheckEnabled: boolean;
    metricsEnabled: boolean;
    runMigrations: boolean;
  };
}

/**
 * Validate required environment variables
 */
function validateEnvironment(): void {
  const required = [
    'JWT_SECRET',
    'DB_NAME',
    'DB_USER'
  ];

  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    logger.error('Missing required environment variables', { missing });
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }

  // Validate JWT secret length
  const jwtSecret = process.env.JWT_SECRET;
  if (jwtSecret && jwtSecret.length < 32) {
    logger.error('JWT_SECRET must be at least 32 characters long');
    throw new Error('JWT_SECRET must be at least 32 characters long for security');
  }

  // Validate bcrypt rounds
  const bcryptRounds = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
  if (bcryptRounds < 10 || bcryptRounds > 15) {
    logger.warn('BCRYPT_ROUNDS should be between 10 and 15 for optimal security/performance balance');
  }

  // Production-specific validations
  if (process.env.NODE_ENV === 'production') {
    const productionRequired = [
      'DB_PASSWORD'
    ];

    const missingProduction = productionRequired.filter(key => !process.env[key]);
    
    if (missingProduction.length > 0) {
      logger.error('Missing required production environment variables', { 
        missing: missingProduction 
      });
      throw new Error(`Missing required production variables: ${missingProduction.join(', ')}`);
    }

    // Warn about insecure production settings
    if (process.env.JWT_SECRET === 'your-super-secret-jwt-key-change-this-in-production-must-be-at-least-32-chars') {
      logger.error('JWT_SECRET must be changed in production');
      throw new Error('Default JWT_SECRET detected in production environment');
    }

    if (!process.env.DB_PASSWORD || process.env.DB_PASSWORD === 'your_password_here') {
      logger.error('DB_PASSWORD must be set in production');
      throw new Error('DB_PASSWORD must be properly configured in production');
    }
  }
}

/**
 * Parse CORS origin configuration
 */
function parseCorsOrigin(): string | string[] | boolean {
  const origin = process.env.CORS_ORIGIN;
  
  if (!origin || origin === 'false') {
    return false;
  }
  
  if (origin === 'true') {
    return true;
  }
  
  if (origin.includes(',')) {
    return origin.split(',').map(o => o.trim());
  }
  
  return origin;
}

/**
 * Create and validate configuration
 */
function createConfig(): ServerConfig {
  validateEnvironment();

  const config: ServerConfig = {
    NODE_ENV: (process.env.NODE_ENV as 'development' | 'production' | 'test') || 'development',
    PORT: parseInt(process.env.PORT || '3001', 10),
    HOST: process.env.HOST || 'localhost',
    TRUST_PROXY: process.env.TRUST_PROXY === 'true',

    database: {
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432', 10),
      database: process.env.DB_NAME!,
      user: process.env.DB_USER!,
      password: process.env.DB_PASSWORD || '',
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
      pool: {
        max: parseInt(process.env.DB_POOL_MAX || '20', 10),
        min: parseInt(process.env.DB_POOL_MIN || '2', 10),
        idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT || '30000', 10),
        connectionTimeoutMillis: parseInt(process.env.DB_CONNECTION_TIMEOUT || '10000', 10),
        queryTimeoutMillis: parseInt(process.env.DB_QUERY_TIMEOUT || '60000', 10),
        statementTimeoutMillis: parseInt(process.env.DB_STATEMENT_TIMEOUT || '60000', 10),
      }
    },

    jwt: {
      secret: process.env.JWT_SECRET!,
      expiresIn: process.env.JWT_EXPIRES_IN || '24h'
    },

    bcrypt: {
      rounds: parseInt(process.env.BCRYPT_ROUNDS || '12', 10)
    },

    rateLimiting: {
      general: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '3600000', 10), // 1 hour
        maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10)
      },
      auth: {
        windowMs: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
        maxRequests: parseInt(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS || '5', 10)
      },
      register: {
        windowMs: parseInt(process.env.REGISTER_RATE_LIMIT_WINDOW_MS || '3600000', 10), // 1 hour
        maxRequests: parseInt(process.env.REGISTER_RATE_LIMIT_MAX_REQUESTS || '2', 10)
      }
    },

    cors: {
      origin: parseCorsOrigin(),
      credentials: process.env.CORS_CREDENTIALS === 'true'
    },

    security: {
      helmetEnabled: process.env.HELMET_ENABLED !== 'false',
      cspEnabled: process.env.CSP_ENABLED === 'true',
      hstsEnabled: process.env.HSTS_ENABLED === 'true',
      secureCookies: process.env.SECURE_COOKIES === 'true' || process.env.NODE_ENV === 'production'
    },

    session: {
      cleanupIntervalMs: parseInt(process.env.SESSION_CLEANUP_INTERVAL || '3600000', 10) // 1 hour
    },

    encryption: {
      rsaKeySize: parseInt(process.env.RSA_KEY_SIZE || '2048', 10),
      aesKeyLength: parseInt(process.env.AES_KEY_LENGTH || '256', 10)
    },

    logging: {
      level: process.env.LOG_LEVEL || 'info',
      file: process.env.LOG_FILE,
      maxSize: process.env.LOG_MAX_SIZE,
      maxFiles: process.env.LOG_MAX_FILES ? parseInt(process.env.LOG_MAX_FILES, 10) : undefined,
      datePattern: process.env.LOG_DATE_PATTERN
    },

    features: {
      healthCheckEnabled: process.env.HEALTH_CHECK_ENABLED !== 'false',
      metricsEnabled: process.env.METRICS_ENABLED === 'true',
      runMigrations: process.env.RUN_MIGRATIONS === 'true' || process.env.NODE_ENV === 'development'
    }
  };

  // Add SSL configuration if provided
  if (process.env.SSL_CERT_PATH && process.env.SSL_KEY_PATH) {
    config.ssl = {
      certPath: process.env.SSL_CERT_PATH,
      keyPath: process.env.SSL_KEY_PATH,
      caPath: process.env.SSL_CA_PATH
    };
  }

  return config;
}

// Create and export configuration
export const config = createConfig();

/**
 * Log configuration summary (without sensitive data)
 */
export function logConfiguration(): void {
  logger.info('Server configuration loaded', {
    nodeEnv: config.NODE_ENV,
    port: config.PORT,
    host: config.HOST,
    database: {
      host: config.database.host,
      port: config.database.port,
      database: config.database.database,
      ssl: !!config.database.ssl,
      poolMax: config.database.pool.max
    },
    cors: {
      origin: typeof config.cors.origin === 'string' ? 
        config.cors.origin.substring(0, 50) + (config.cors.origin.length > 50 ? '...' : '') : 
        config.cors.origin,
      credentials: config.cors.credentials
    },
    security: config.security,
    features: config.features,
    rateLimiting: {
      general: `${config.rateLimiting.general.maxRequests}/${config.rateLimiting.general.windowMs}ms`,
      auth: `${config.rateLimiting.auth.maxRequests}/${config.rateLimiting.auth.windowMs}ms`,
      register: `${config.rateLimiting.register.maxRequests}/${config.rateLimiting.register.windowMs}ms`
    }
  });
}

/**
 * Get configuration for specific environment
 */
export function getEnvironmentConfig(): {
  isDevelopment: boolean;
  isProduction: boolean;
  isTest: boolean;
} {
  return {
    isDevelopment: config.NODE_ENV === 'development',
    isProduction: config.NODE_ENV === 'production',
    isTest: config.NODE_ENV === 'test'
  };
}

export default config;