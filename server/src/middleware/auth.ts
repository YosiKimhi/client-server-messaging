import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest, JWTPayload, UserProfile, ActiveSession } from '../types/index';
import { AuthService } from '../services/AuthService';
import { logger } from '../utils/logger';
import { setSecurityHeaders, logSecurityEvent } from '../utils/validation';

/**
 * Extract JWT token from request headers or query parameters
 */
function extractToken(req: Request): string | null {
  // First try to get token from Authorization header (standard approach)
  const authHeader = req.headers.authorization;
  
  if (authHeader) {
    // Check for Bearer token format
    const parts = authHeader.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      logger.info('Token extracted from Authorization header', {
        path: req.path,
        tokenLength: parts[1]?.length || 0
      });
      return parts[1] || null;
    }
  }

  // For SSE connections, try to get token from query parameters
  // This is necessary since EventSource doesn't support custom headers
  if (req.query && req.query.token && typeof req.query.token === 'string') {
    logger.info('Token extracted from query parameters', {
      path: req.path,
      tokenLength: req.query.token.length,
      tokenPreview: req.query.token.substring(0, 20) + '...'
    });
    return req.query.token;
  }

  logger.warn('No token found in request', {
    path: req.path,
    hasAuthHeader: !!authHeader,
    hasQueryToken: !!req.query?.token,
    queryTokenType: typeof req.query?.token,
    queryKeys: Object.keys(req.query || {})
  });

  return null;
}

/**
 * Authentication middleware - validates JWT token and sets user context
 */
export async function authenticate(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // Set security headers
    setSecurityHeaders(res);

    // Extract token from Authorization header or query parameters (for SSE)
    const token = extractToken(req);
    
    // Debug logging for SSE authentication
    if (req.path.includes('/stream/events')) {
      logger.info('SSE Authentication Debug', {
        path: req.path,
        method: req.method,
        hasAuthHeader: !!req.headers.authorization,
        hasTokenQuery: !!req.query?.token,
        tokenLength: token ? token.length : 0,
        ip: req.ip
      });
    }
    
    // Debug logging for SSE authentication issues
    logger.debug('Authentication middleware called', {
      path: req.path,
      originalUrl: req.originalUrl,
      method: req.method,
      hasAuthHeader: !!req.headers.authorization,
      hasTokenQuery: !!req.query?.token,
      tokenLength: token ? token.length : 0,
      ip: req.ip
    });
    
    if (!token) {
      logger.warn('Authentication failed: No token provided', {
        path: req.path,
        originalUrl: req.originalUrl,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        authHeader: req.headers.authorization ? 'present' : 'missing',
        queryToken: req.query?.token ? 'present' : 'missing',
        queryTokenType: typeof req.query?.token,
        queryTokenLength: req.query?.token ? String(req.query.token).length : 0,
        isSSERequest: req.path.includes('/stream/events')
      });
      
      res.status(401).json({
        error: {
          message: 'Authentication required',
          code: 'NO_TOKEN'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
      return;
    }

    // Verify JWT token
    const payload = AuthService.verifyJWTToken(token);
    
    if (!payload) {
      logger.warn('Authentication failed: Invalid token', {
        path: req.path,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        token: token.substring(0, 20) + '...'
      });
      
      logSecurityEvent('INVALID_TOKEN_ATTEMPT', req);
      
      res.status(401).json({
        error: {
          message: 'Invalid or expired token',
          code: 'INVALID_TOKEN'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
      return;
    }

    // Check if token has expired
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
      logger.warn('Authentication failed: Token expired', {
        userId: payload.user_id,
        sessionId: payload.session_id,
        expiredAt: new Date(payload.exp * 1000),
        path: req.path,
        ip: req.ip
      });
      
      res.status(401).json({
        error: {
          message: 'Token has expired',
          code: 'TOKEN_EXPIRED'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
      return;
    }

    // Validate session is still active
    const session = await AuthService.validateSession(payload.session_id);
    
    if (!session) {
      logger.warn('Authentication failed: Invalid or expired session', {
        userId: payload.user_id,
        sessionId: payload.session_id,
        path: req.path,
        ip: req.ip
      });
      
      logSecurityEvent('INVALID_SESSION_ATTEMPT', req, payload.user_id);
      
      res.status(401).json({
        error: {
          message: 'Session has expired or is invalid',
          code: 'INVALID_SESSION'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
      return;
    }

    // Get user profile
    const userProfile = await AuthService.getUserProfile(payload.user_id);
    
    if (!userProfile) {
      logger.warn('Authentication failed: User not found or inactive', {
        userId: payload.user_id,
        sessionId: payload.session_id,
        path: req.path,
        ip: req.ip
      });
      
      logSecurityEvent('USER_NOT_FOUND_ATTEMPT', req, payload.user_id);
      
      res.status(401).json({
        error: {
          message: 'User account not found or inactive',
          code: 'USER_NOT_FOUND'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
      return;
    }

    // Set user and session context on request
    req.user = userProfile;
    req.session = session;

    // Log successful authentication
    logger.debug('User authenticated successfully', {
      userId: userProfile.id,
      username: userProfile.username,
      sessionId: session.id,
      path: req.path,
      method: req.method,
      ip: req.ip
    });

    next();

  } catch (error) {
    logger.error('Authentication middleware error', {
      error: (error as Error).message,
      stack: (error as Error).stack,
      path: req.path,
      method: req.method,
      ip: req.ip
    });

    res.status(500).json({
      error: {
        message: 'Authentication service unavailable',
        code: 'AUTH_SERVICE_ERROR'
      },
      timestamp: new Date(),
      path: req.path,
      method: req.method
    });
  }
}

/**
 * Optional authentication middleware - sets user context if valid token provided, but doesn't require it
 */
export async function optionalAuthenticate(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // Set security headers
    setSecurityHeaders(res);

    // Extract token from Authorization header or query parameters (for SSE)
    const token = extractToken(req);
    
    // If no token provided, continue without authentication
    if (!token) {
      next();
      return;
    }

    // Verify JWT token
    const payload = AuthService.verifyJWTToken(token);
    
    if (!payload) {
      // Invalid token, but don't block request
      logger.debug('Optional authentication: Invalid token ignored', {
        path: req.path,
        method: req.method,
        ip: req.ip
      });
      next();
      return;
    }

    // Check if token has expired
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
      // Expired token, continue without authentication
      next();
      return;
    }

    // Validate session
    const session = await AuthService.validateSession(payload.session_id);
    
    if (!session) {
      // Invalid session, continue without authentication
      next();
      return;
    }

    // Get user profile
    const userProfile = await AuthService.getUserProfile(payload.user_id);
    
    if (!userProfile) {
      // User not found, continue without authentication
      next();
      return;
    }

    // Set user and session context on request
    req.user = userProfile;
    req.session = session;

    logger.debug('Optional authentication successful', {
      userId: userProfile.id,
      username: userProfile.username,
      path: req.path
    });

    next();

  } catch (error) {
    // On error, log it but continue without authentication
    logger.error('Optional authentication middleware error', {
      error: (error as Error).message,
      path: req.path,
      method: req.method,
      ip: req.ip
    });

    next();
  }
}

/**
 * Role-based authorization middleware factory
 */
export function requireRole(allowedRoles: string[]) {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      // First ensure user is authenticated
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

      // For now, we'll implement a simple admin check
      // In a full implementation, you'd have a roles system
      const userRoles = req.user.username === 'admin' ? ['admin'] : ['user'];
      
      const hasRequiredRole = allowedRoles.some(role => userRoles.includes(role));
      
      if (!hasRequiredRole) {
        logger.warn('Authorization failed: Insufficient permissions', {
          userId: req.user.id,
          username: req.user.username,
          requiredRoles: allowedRoles,
          userRoles,
          path: req.path,
          method: req.method,
          ip: req.ip
        });

        logSecurityEvent('AUTHORIZATION_FAILED', req, req.user.id, {
          requiredRoles: allowedRoles,
          userRoles
        });
        
        res.status(403).json({
          error: {
            message: 'Insufficient permissions',
            code: 'INSUFFICIENT_PERMISSIONS'
          },
          timestamp: new Date(),
          path: req.path,
          method: req.method
        });
        return;
      }

      next();

    } catch (error) {
      logger.error('Authorization middleware error', {
        error: (error as Error).message,
        path: req.path,
        method: req.method,
        userId: req.user?.id,
        ip: req.ip
      });

      res.status(500).json({
        error: {
          message: 'Authorization service unavailable',
          code: 'AUTHZ_SERVICE_ERROR'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
    }
  };
}

/**
 * Session validation middleware - ensures session is still valid
 */
export async function validateSession(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    if (!req.session) {
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

    // Check if session has expired
    const now = new Date();
    if (req.session.expires_at < now) {
      logger.warn('Session expired', {
        userId: req.user?.id,
        sessionId: req.session.id,
        expiredAt: req.session.expires_at,
        path: req.path,
        ip: req.ip
      });

      res.status(401).json({
        error: {
          message: 'Session has expired',
          code: 'SESSION_EXPIRED'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
      return;
    }

    // Check if session is still active in database
    const activeSession = await AuthService.validateSession(req.session.id);
    
    if (!activeSession) {
      logger.warn('Session no longer active', {
        userId: req.user?.id,
        sessionId: req.session.id,
        path: req.path,
        ip: req.ip
      });

      res.status(401).json({
        error: {
          message: 'Session is no longer active',
          code: 'INACTIVE_SESSION'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      });
      return;
    }

    // Update session with latest activity
    req.session = activeSession;

    next();

  } catch (error) {
    logger.error('Session validation error', {
      error: (error as Error).message,
      sessionId: req.session?.id,
      userId: req.user?.id,
      path: req.path,
      ip: req.ip
    });

    res.status(500).json({
      error: {
        message: 'Session validation service unavailable',
        code: 'SESSION_SERVICE_ERROR'
      },
      timestamp: new Date(),
      path: req.path,
      method: req.method
    });
  }
}

/**
 * Request context middleware - adds request ID and logging context
 */
export function requestContext(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  // Add request ID for tracking
  const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  req.headers['x-request-id'] = requestId;
  res.setHeader('X-Request-ID', requestId);

  // Log request start
  logger.info('Request started', {
    requestId,
    method: req.method,
    path: req.path,
    query: req.query,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id || 'anonymous'
  });

  // Track response time
  const startTime = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    
    logger.info('Request completed', {
      requestId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      userId: req.user?.id || 'anonymous',
      ip: req.ip
    });
  });

  next();
}