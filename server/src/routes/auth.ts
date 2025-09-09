import { Router, Request, Response } from 'express';
import { AuthenticatedRequest, RegisterRequest, LoginRequest, AuthResponse, UserProfile } from '../types/index';
import { AuthService } from '../services/AuthService';
import { authenticate, requestContext } from '../middleware/auth';
import { 
  authRateLimit, 
  registerRateLimit 
} from '../middleware/rateLimiting';
import { 
  validateRegistration, 
  validateLogin, 
  handleValidationErrors,
  logSecurityEvent,
  sanitizeString
} from '../utils/validation';
import { logger } from '../utils/logger';

const router = Router();

/**
 * POST /api/auth/register
 * Register a new user with encryption keys
 */
router.post('/register', 
  registerRateLimit, // Apply strict rate limiting for registration
  validateRegistration(),
  handleValidationErrors,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { username, email, password, public_key, private_key_encrypted } = req.body;

      // Sanitize input data
      const sanitizedData: RegisterRequest = {
        username: sanitizeString(username, 30).toLowerCase(),
        email: sanitizeString(email, 100).toLowerCase(),
        password: password, // Don't sanitize password as it may contain special chars
        public_key: sanitizeString(public_key, 2000),
        private_key_encrypted: sanitizeString(private_key_encrypted, 5000)
      };

      // Get client information
      const ipAddress = req.ip;
      const userAgent = req.get('User-Agent');

      // Log registration attempt
      logger.info('User registration attempt', {
        username: sanitizedData.username,
        email: sanitizedData.email,
        ip: ipAddress,
        userAgent
      });

      // Register user
      const authResponse: AuthResponse = await AuthService.register(
        sanitizedData,
        ipAddress,
        userAgent
      );

      // Log successful registration
      logSecurityEvent('USER_REGISTERED', req, authResponse.user.id, {
        username: authResponse.user.username,
        email: authResponse.user.email
      });

      // Return success response
      res.status(201).json({
        success: true,
        data: authResponse,
        message: 'User registered successfully',
        timestamp: new Date()
      });

    } catch (error) {
      logger.error('Registration failed', {
        error: (error as Error).message,
        username: req.body?.username,
        email: req.body?.email,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      logSecurityEvent('REGISTRATION_FAILED', req, undefined, {
        error: (error as Error).message,
        username: req.body?.username
      });

      // Return error response
      const statusCode = (error as Error).message.includes('already exists') ? 409 : 400;
      
      res.status(statusCode).json({
        error: {
          message: (error as Error).message,
          code: 'REGISTRATION_FAILED'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
    }
  }
);

/**
 * POST /api/auth/login
 * Authenticate user and create session
 */
router.post('/login',
  validateLogin(),
  handleValidationErrors,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { username, password } = req.body;

      // Sanitize username
      const loginData: LoginRequest = {
        username: sanitizeString(username, 30).toLowerCase(),
        password: password // Don't sanitize password
      };

      // Get client information
      const ipAddress = req.ip;
      const userAgent = req.get('User-Agent');

      // Log login attempt
      logger.info('User login attempt', {
        username: loginData.username,
        ip: ipAddress,
        userAgent
      });

      // Authenticate user
      const authResponse: AuthResponse = await AuthService.login(
        loginData,
        ipAddress,
        userAgent
      );

      // Log successful login
      logSecurityEvent('USER_LOGIN', req, authResponse.user.id, {
        username: authResponse.user.username,
        sessionId: authResponse.token.substring(0, 10) + '...'
      });

      // Return success response
      res.status(200).json({
        success: true,
        data: authResponse,
        message: 'Login successful',
        timestamp: new Date()
      });

    } catch (error) {
      logger.error('Login failed', {
        error: (error as Error).message,
        username: req.body?.username,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      logSecurityEvent('LOGIN_FAILED', req, undefined, {
        error: (error as Error).message,
        username: req.body?.username
      });

      // Return error response
      res.status(401).json({
        error: {
          message: (error as Error).message,
          code: 'LOGIN_FAILED'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
    }
  }
);

/**
 * POST /api/auth/logout
 * Logout user and invalidate session
 */
router.post('/logout',
  authenticate,
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      if (!req.session) {
        res.status(400).json({
          error: {
            message: 'No active session to logout',
            code: 'NO_SESSION'
          },
          timestamp: new Date(),
          path: req.path,
          method: req.method
        });
        return;
      }

      const sessionId = req.session.id;
      const userId = req.user?.id;
      const username = req.user?.username;

      // Get client information
      const ipAddress = req.ip;
      const userAgent = req.get('User-Agent');

      // Log logout attempt
      logger.info('User logout attempt', {
        userId,
        username,
        sessionId,
        ip: ipAddress,
        userAgent
      });

      // Logout user (invalidate session)
      await AuthService.logout(sessionId, ipAddress, userAgent);

      // Log successful logout
      logSecurityEvent('USER_LOGOUT', req, userId, {
        username,
        sessionId
      });

      // Return success response
      res.status(200).json({
        success: true,
        data: null,
        message: 'Logout successful',
        timestamp: new Date()
      });

    } catch (error) {
      logger.error('Logout failed', {
        error: (error as Error).message,
        userId: req.user?.id,
        sessionId: req.session?.id,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      logSecurityEvent('LOGOUT_FAILED', req, req.user?.id, {
        error: (error as Error).message,
        sessionId: req.session?.id
      });

      // Return error response
      res.status(500).json({
        error: {
          message: 'Logout failed',
          code: 'LOGOUT_FAILED'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
    }
  }
);

/**
 * GET /api/auth/profile
 * Get authenticated user's profile
 */
router.get('/profile',
  authenticate,
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      if (!req.user) {
        res.status(401).json({
          error: {
            message: 'No authenticated user',
            code: 'NO_USER'
          },
          timestamp: new Date(),
          path: req.path,
          method: req.method
        });
        return;
      }

      // Log profile access
      logger.debug('User profile accessed', {
        userId: req.user.id,
        username: req.user.username,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      // Get fresh user profile from database
      const userProfile = await AuthService.getUserProfile(req.user.id);

      if (!userProfile) {
        res.status(404).json({
          error: {
            message: 'User profile not found',
            code: 'PROFILE_NOT_FOUND'
          },
          timestamp: new Date(),
          path: req.path,
          method: req.method
        });
        return;
      }

      // Return user profile
      res.status(200).json({
        success: true,
        data: userProfile,
        message: 'Profile retrieved successfully',
        timestamp: new Date()
      });

    } catch (error) {
      logger.error('Failed to get user profile', {
        error: (error as Error).message,
        userId: req.user?.id,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      // Return error response
      res.status(500).json({
        error: {
          message: 'Failed to retrieve profile',
          code: 'PROFILE_ERROR'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
    }
  }
);

/**
 * GET /api/auth/session
 * Get current session information
 */
router.get('/session',
  authenticate,
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      if (!req.session || !req.user) {
        res.status(401).json({
          error: {
            message: 'No active session',
            code: 'NO_SESSION'
          },
          timestamp: new Date(),
          path: req.path,
          method: req.method
        });
        return;
      }

      // Return session information (without sensitive data)
      const sessionInfo = {
        id: req.session.id,
        user: {
          id: req.user.id,
          username: req.user.username,
          email: req.user.email
        },
        expires_at: req.session.expires_at,
        last_activity: req.session.last_activity,
        created_at: req.session.created_at
      };

      res.status(200).json({
        success: true,
        data: sessionInfo,
        message: 'Session information retrieved',
        timestamp: new Date()
      });

    } catch (error) {
      logger.error('Failed to get session info', {
        error: (error as Error).message,
        userId: req.user?.id,
        sessionId: req.session?.id,
        ip: req.ip
      });

      res.status(500).json({
        error: {
          message: 'Failed to retrieve session information',
          code: 'SESSION_ERROR'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
    }
  }
);

/**
 * POST /api/auth/refresh
 * Refresh user session and get new token
 */
router.post('/refresh',
  authenticate,
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      if (!req.session || !req.user) {
        res.status(401).json({
          error: {
            message: 'No active session to refresh',
            code: 'NO_SESSION'
          },
          timestamp: new Date(),
          path: req.path,
          method: req.method
        });
        return;
      }

      // Validate current session
      const activeSession = await AuthService.validateSession(req.session.id);
      
      if (!activeSession) {
        res.status(401).json({
          error: {
            message: 'Current session is no longer valid',
            code: 'INVALID_SESSION'
          },
          timestamp: new Date(),
          path: req.path,
          method: req.method
        });
        return;
      }

      // For now, we'll just return the current session info
      // In a full implementation, you might create a new session or extend the current one
      
      logSecurityEvent('SESSION_REFRESHED', req, req.user.id, {
        sessionId: req.session.id
      });

      res.status(200).json({
        success: true,
        data: {
          user: req.user,
          session: {
            expires_at: activeSession.expires_at,
            last_activity: activeSession.last_activity
          }
        },
        message: 'Session refreshed successfully',
        timestamp: new Date()
      });

    } catch (error) {
      logger.error('Session refresh failed', {
        error: (error as Error).message,
        userId: req.user?.id,
        sessionId: req.session?.id,
        ip: req.ip
      });

      res.status(500).json({
        error: {
          message: 'Failed to refresh session',
          code: 'REFRESH_FAILED'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
    }
  }
);

/**
 * GET /api/auth/keys
 * Get user's encryption keys
 */
router.get('/keys',
  authenticate,
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      if (!req.user) {
        res.status(401).json({
          error: {
            message: 'Authentication required',
            code: 'NO_AUTH'
          },
          timestamp: new Date(),
          path: req.path,
          method: req.method
        });
        return;
      }

      // Get user's encryption keys
      const keys = await AuthService.getUserKeys(req.user.id);

      if (!keys) {
        res.status(404).json({
          error: {
            message: 'User encryption keys not found',
            code: 'KEYS_NOT_FOUND'
          },
          timestamp: new Date(),
          path: req.path,
          method: req.method
        });
        return;
      }

      // Log key access
      logSecurityEvent('ENCRYPTION_KEYS_ACCESSED', req, req.user.id);

      res.status(200).json({
        success: true,
        data: {
          public_key: keys.publicKey,
          // Note: We return the encrypted private key, client will need to decrypt it
          private_key_encrypted: keys.privateKeyEncrypted
        },
        message: 'Encryption keys retrieved',
        timestamp: new Date()
      });

    } catch (error) {
      logger.error('Failed to get user keys', {
        error: (error as Error).message,
        userId: req.user?.id,
        ip: req.ip
      });

      res.status(500).json({
        error: {
          message: 'Failed to retrieve encryption keys',
          code: 'KEYS_ERROR'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
    }
  }
);

export default router;