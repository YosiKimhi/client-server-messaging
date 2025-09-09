import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import * as fs from 'fs';
import * as https from 'https';
import * as http from 'http';
import { logger } from './utils/logger';
import { initializeDatabase, closeDatabaseConnection } from './config/database';
import { config, logConfiguration, getEnvironmentConfig } from './config/environment';
import { AuthService } from './services/AuthService';

// Import routes
import authRoutes from './routes/auth';
import messageRoutes from './routes/messages';

// Import middleware
import { generalRateLimit } from './middleware/rateLimiting';
import { requestContext } from './middleware/auth';

const { isDevelopment, isProduction } = getEnvironmentConfig();

/**
 * Create Express application with middleware
 */
function createExpressApp(): express.Application {
  const app = express();

  // Trust proxy if configured (for accurate IP addresses behind load balancers)
  if (config.TRUST_PROXY) {
    app.set('trust proxy', 1);
  }

  // Security middleware
  if (config.security.helmetEnabled) {
    app.use(helmet({
      contentSecurityPolicy: config.security.cspEnabled ? {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
        },
      } : false,
      hsts: config.security.hstsEnabled ? {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
      } : false
    }));
  }

  // CORS configuration
  app.use(cors({
    origin: config.cors.origin,
    credentials: config.cors.credentials,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
  }));

  // Body parsing middleware
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Request context and logging
  app.use(requestContext);

  // General rate limiting
  app.use(generalRateLimit);

  // Health check endpoint (before authentication)
  app.get('/health', (req: Request, res: Response) => {
    res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      environment: config.NODE_ENV,
      version: '1.0.0',
      message: 'Authentication system is running',
      database: 'connected',
      uptime: process.uptime()
    });
  });

  // API status endpoint
  app.get('/api/status', (req: Request, res: Response) => {
    res.status(200).json({
      success: true,
      data: {
        status: 'operational',
        timestamp: new Date(),
        environment: config.NODE_ENV,
        features: {
          authentication: 'enabled',
          rateLimiting: 'enabled',
          encryption: 'enabled'
        }
      },
      message: 'API is operational'
    });
  });

  // Mount authentication routes
  app.use('/api/auth', authRoutes);
  
  // Mount message routes
  app.use('/api/messages', messageRoutes);

  // 404 handler for unknown routes
  app.use('*', (req: Request, res: Response) => {
    logger.warn('Route not found', {
      path: req.originalUrl,
      method: req.method,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(404).json({
      error: {
        message: 'Route not found',
        code: 'ROUTE_NOT_FOUND',
        path: req.originalUrl,
        availableEndpoints: [
          'GET /health',
          'GET /api/status',
          'POST /api/auth/register',
          'POST /api/auth/login',
          'POST /api/auth/logout',
          'GET /api/auth/profile',
          'GET /api/auth/session',
          'POST /api/auth/refresh',
          'GET /api/auth/keys',
          'POST /api/messages/send',
          'GET /api/messages/history',
          'GET /api/messages/:id',
          'DELETE /api/messages/:id',
          'GET /api/messages/stats'
        ]
      },
      timestamp: new Date(),
      path: req.originalUrl,
      method: req.method
    });
  });

  // Global error handler
  app.use((error: any, req: Request, res: Response, next: NextFunction) => {
    logger.error('Unhandled error in Express app', {
      error: error.message,
      stack: error.stack,
      path: req.path,
      method: req.method,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Don't leak error details in production
    const message = isProduction ? 'Internal server error' : error.message;
    const details = isProduction ? undefined : {
      stack: error.stack,
      name: error.name
    };

    res.status(500).json({
      error: {
        message,
        code: 'INTERNAL_SERVER_ERROR',
        details
      },
      timestamp: new Date(),
      path: req.path,
      method: req.method
    });
  });

  return app;
}

/**
 * Start session cleanup interval
 */
function startSessionCleanup(): void {
  const cleanupInterval = config.session.cleanupIntervalMs;
  
  logger.info('Starting session cleanup service', {
    intervalMs: cleanupInterval
  });

  setInterval(async () => {
    try {
      await AuthService.cleanupExpiredSessions();
    } catch (error) {
      logger.error('Session cleanup failed', {
        error: (error as Error).message
      });
    }
  }, cleanupInterval);
}

/**
 * Create HTTP/HTTPS server
 */
function createServer(app: express.Application): http.Server | https.Server {
  if (config.ssl && config.ssl.certPath && config.ssl.keyPath) {
    logger.info('Starting HTTPS server with SSL/TLS');
    
    const sslOptions = {
      cert: fs.readFileSync(config.ssl.certPath),
      key: fs.readFileSync(config.ssl.keyPath),
      ca: config.ssl.caPath ? fs.readFileSync(config.ssl.caPath) : undefined
    };
    
    return https.createServer(sslOptions, app);
  } else {
    if (isProduction) {
      logger.warn('Starting HTTP server in production - consider using HTTPS');
    }
    return http.createServer(app);
  }
}

/**
 * Setup graceful shutdown
 */
function setupGracefulShutdown(server: http.Server | https.Server): void {
  const gracefulShutdown = async (signal: string) => {
    logger.info(`${signal} received, starting graceful shutdown`);
    
    // Stop accepting new connections
    server.close(async (error) => {
      if (error) {
        logger.error('Error during server shutdown', { 
          error: error.message 
        });
        process.exit(1);
        return;
      }
      
      try {
        // Close database connections
        logger.info('Closing database connections...');
        await closeDatabaseConnection();
        
        logger.info('Graceful shutdown complete');
        process.exit(0);
      } catch (shutdownError) {
        logger.error('Error during graceful shutdown', { 
          error: (shutdownError as Error).message 
        });
        process.exit(1);
      }
    });

    // Force shutdown after 30 seconds
    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 30000);
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  
  // Handle uncaught exceptions
  process.on('uncaughtException', (error: Error) => {
    logger.error('Uncaught Exception', {
      error: error.message,
      stack: error.stack
    });
    process.exit(1);
  });

  // Handle unhandled promise rejections
  process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
    logger.error('Unhandled Rejection', {
      reason: reason?.message || reason,
      stack: reason?.stack
    });
    process.exit(1);
  });
}

/**
 * Main server startup function
 */
async function startServer(): Promise<void> {
  try {
    logger.info('Starting secure messaging server...');
    
    // Log configuration
    logConfiguration();
    
    // Initialize database connection and run migrations
    logger.info('Initializing database...');
    await initializeDatabase();
    
    // Create Express application
    logger.info('Creating Express application...');
    const app = createExpressApp();
    
    // Create server
    logger.info('Creating server...');
    const server = createServer(app);
    
    // Setup graceful shutdown
    setupGracefulShutdown(server);
    
    // Start session cleanup service
    startSessionCleanup();
    
    // Start listening
    server.listen(config.PORT, config.HOST, () => {
      const protocol = config.ssl ? 'https' : 'http';
      const serverUrl = `${protocol}://${config.HOST}:${config.PORT}`;
      
      logger.info('Server started successfully', {
        url: serverUrl,
        environment: config.NODE_ENV,
        port: config.PORT,
        host: config.HOST,
        ssl: !!config.ssl,
        processId: process.pid
      });
      
      logger.info('BE-004: Core Message System - COMPLETE');
      logger.info('Available endpoints:', {
        health: `${serverUrl}/health`,
        status: `${serverUrl}/api/status`,
        register: `${serverUrl}/api/auth/register`,
        login: `${serverUrl}/api/auth/login`,
        logout: `${serverUrl}/api/auth/logout`,
        profile: `${serverUrl}/api/auth/profile`,
        session: `${serverUrl}/api/auth/session`,
        refresh: `${serverUrl}/api/auth/refresh`,
        keys: `${serverUrl}/api/auth/keys`,
        messageSend: `${serverUrl}/api/messages/send`,
        messageHistory: `${serverUrl}/api/messages/history`,
        messageById: `${serverUrl}/api/messages/:id`,
        messageDelete: `${serverUrl}/api/messages/:id`,
        messageStats: `${serverUrl}/api/messages/stats`
      });
      
      if (isDevelopment) {
        logger.info('Development mode notes:', {
          message: 'Core messaging system is ready for testing',
          features: 'Authentication, message encryption, audit logging enabled',
          rateLimits: 'Rate limiting is active - check logs for details',
          security: 'Security headers and CORS are configured',
          database: 'Database migrations have been applied',
          encryption: 'Messages are encrypted before storage with RSA+AES'
        });
      }
    });
    
  } catch (error) {
    logger.error('Failed to start server', {
      error: (error as Error).message,
      stack: (error as Error).stack
    });
    process.exit(1);
  }
}

// Start the server
if (require.main === module) {
  startServer().catch((error) => {
    logger.error('Server startup failed', { 
      error: error.message,
      stack: error.stack 
    });
    process.exit(1);
  });
}

export { createExpressApp, startServer };