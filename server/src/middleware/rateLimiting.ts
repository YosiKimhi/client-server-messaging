import rateLimit from 'express-rate-limit';
import { Request, Response } from 'express';
import { logger } from '../utils/logger';
import { logSecurityEvent, generateRateLimitKey } from '../utils/validation';

/**
 * Store for tracking rate limiting data in memory
 * In production, you'd use Redis or another distributed store
 */
interface RateLimitStore {
  [key: string]: {
    count: number;
    resetTime: number;
  };
}

const rateLimitStore: RateLimitStore = {};

/**
 * Clean up expired rate limit entries
 */
function cleanupExpiredEntries(): void {
  const now = Date.now();
  for (const key in rateLimitStore) {
    if (rateLimitStore[key].resetTime < now) {
      delete rateLimitStore[key];
    }
  }
}

// Clean up expired entries every 5 minutes
setInterval(cleanupExpiredEntries, 5 * 60 * 1000);

/**
 * Custom rate limit handler for better logging and security
 */
function rateLimitHandler(req: Request, res: Response): void {
  const ip = req.ip;
  const userAgent = req.get('User-Agent') || 'unknown';
  const path = req.path;

  logger.warn('Rate limit exceeded', {
    ip,
    userAgent,
    path,
    method: req.method,
    timestamp: new Date()
  });

  logSecurityEvent('RATE_LIMIT_EXCEEDED', req, undefined, {
    path,
    userAgent,
    rateLimitType: 'general'
  });

  res.status(429).json({
    error: {
      message: 'Too many requests. Please try again later.',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: '1 hour'
    },
    timestamp: new Date(),
    path: req.path,
    method: req.method
  });
}

/**
 * Authentication-specific rate limit handler
 */
function authRateLimitHandler(req: Request, res: Response): void {
  const ip = req.ip;
  const userAgent = req.get('User-Agent') || 'unknown';
  const path = req.path;

  logger.warn('Authentication rate limit exceeded', {
    ip,
    userAgent,
    path,
    method: req.method,
    timestamp: new Date()
  });

  logSecurityEvent('AUTH_RATE_LIMIT_EXCEEDED', req, undefined, {
    path,
    userAgent,
    rateLimitType: 'authentication'
  });

  res.status(429).json({
    error: {
      message: 'Too many authentication attempts. Please try again later.',
      code: 'AUTH_RATE_LIMIT_EXCEEDED',
      retryAfter: '15 minutes'
    },
    timestamp: new Date(),
    path: req.path,
    method: req.method
  });
}

/**
 * General rate limiting middleware
 * 100 requests per hour per IP
 */
export const generalRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: {
      message: 'Too many requests from this IP, please try again later.',
      code: 'RATE_LIMIT_EXCEEDED'
    }
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: rateLimitHandler,
  keyGenerator: (req: Request) => {
    return generateRateLimitKey(req, 'general');
  },
  skip: (req: Request) => {
    // Skip rate limiting for health checks
    return req.path === '/health' || req.path === '/api/health';
  }
});

/**
 * Strict rate limiting for authentication endpoints
 * 5 login attempts per 15 minutes per IP
 */
export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: {
    error: {
      message: 'Too many authentication attempts, please try again later.',
      code: 'AUTH_RATE_LIMIT_EXCEEDED'
    }
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: authRateLimitHandler,
  keyGenerator: (req: Request) => {
    return generateRateLimitKey(req, 'auth');
  }
});

/**
 * Even more strict rate limiting for registration
 * 2 registration attempts per hour per IP
 */
export const registerRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 2, // Limit each IP to 2 registration requests per hour
  message: {
    error: {
      message: 'Too many registration attempts, please try again later.',
      code: 'REGISTER_RATE_LIMIT_EXCEEDED'
    }
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    const ip = req.ip;
    const userAgent = req.get('User-Agent') || 'unknown';

    logger.warn('Registration rate limit exceeded', {
      ip,
      userAgent,
      path: req.path,
      method: req.method,
      timestamp: new Date()
    });

    logSecurityEvent('REGISTER_RATE_LIMIT_EXCEEDED', req, undefined, {
      userAgent,
      rateLimitType: 'registration'
    });

    res.status(429).json({
      error: {
        message: 'Too many registration attempts. Please try again in an hour.',
        code: 'REGISTER_RATE_LIMIT_EXCEEDED',
        retryAfter: '1 hour'
      },
      timestamp: new Date(),
      path: req.path,
      method: req.method
    });
  },
  keyGenerator: (req: Request) => {
    return generateRateLimitKey(req, 'register');
  }
});

/**
 * Rate limiting for password reset attempts
 * 3 attempts per hour per IP
 */
export const passwordResetRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 password reset attempts per hour
  message: {
    error: {
      message: 'Too many password reset attempts, please try again later.',
      code: 'PASSWORD_RESET_RATE_LIMIT_EXCEEDED'
    }
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    const ip = req.ip;
    const userAgent = req.get('User-Agent') || 'unknown';

    logger.warn('Password reset rate limit exceeded', {
      ip,
      userAgent,
      path: req.path,
      method: req.method,
      timestamp: new Date()
    });

    logSecurityEvent('PASSWORD_RESET_RATE_LIMIT_EXCEEDED', req, undefined, {
      userAgent,
      rateLimitType: 'password_reset'
    });

    res.status(429).json({
      error: {
        message: 'Too many password reset attempts. Please try again in an hour.',
        code: 'PASSWORD_RESET_RATE_LIMIT_EXCEEDED',
        retryAfter: '1 hour'
      },
      timestamp: new Date(),
      path: req.path,
      method: req.method
    });
  },
  keyGenerator: (req: Request) => {
    return generateRateLimitKey(req, 'password_reset');
  }
});

/**
 * Rate limiting for API endpoints
 * 1000 requests per hour per authenticated user
 */
export const apiRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 1000, // Limit each authenticated user to 1000 API requests per hour
  message: {
    error: {
      message: 'API rate limit exceeded, please try again later.',
      code: 'API_RATE_LIMIT_EXCEEDED'
    }
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    const ip = req.ip;
    const userAgent = req.get('User-Agent') || 'unknown';

    logger.warn('API rate limit exceeded', {
      ip,
      userAgent,
      path: req.path,
      method: req.method,
      timestamp: new Date()
    });

    logSecurityEvent('API_RATE_LIMIT_EXCEEDED', req, undefined, {
      userAgent,
      rateLimitType: 'api'
    });

    res.status(429).json({
      error: {
        message: 'API rate limit exceeded. Please try again later.',
        code: 'API_RATE_LIMIT_EXCEEDED',
        retryAfter: '1 hour'
      },
      timestamp: new Date(),
      path: req.path,
      method: req.method
    });
  },
  keyGenerator: (req: Request) => {
    // Use user ID if available, otherwise fall back to IP
    const user = (req as any).user;
    if (user && user.id) {
      return `user:${user.id}`;
    }
    return generateRateLimitKey(req, 'api');
  }
});

/**
 * Message sending rate limit
 * 100 messages per minute per user
 */
export const messageRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // Limit each user to 100 messages per minute
  message: {
    error: {
      message: 'Message rate limit exceeded, please slow down.',
      code: 'MESSAGE_RATE_LIMIT_EXCEEDED'
    }
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    const ip = req.ip;
    const userAgent = req.get('User-Agent') || 'unknown';
    const user = (req as any).user;

    logger.warn('Message rate limit exceeded', {
      ip,
      userAgent,
      userId: user?.id,
      username: user?.username,
      path: req.path,
      method: req.method,
      timestamp: new Date()
    });

    logSecurityEvent('MESSAGE_RATE_LIMIT_EXCEEDED', req, user?.id, {
      userAgent,
      rateLimitType: 'message'
    });

    res.status(429).json({
      error: {
        message: 'Too many messages sent. Please slow down.',
        code: 'MESSAGE_RATE_LIMIT_EXCEEDED',
        retryAfter: '1 minute'
      },
      timestamp: new Date(),
      path: req.path,
      method: req.method
    });
  },
  keyGenerator: (req: Request) => {
    // Always use user ID for message rate limiting
    const user = (req as any).user;
    if (user && user.id) {
      return `messages:${user.id}`;
    }
    // Fallback to IP if no user (shouldn't happen for message endpoints)
    return generateRateLimitKey(req, 'messages');
  }
});

/**
 * Custom rate limiter class for more complex rate limiting scenarios
 */
export class CustomRateLimiter {
  private store: RateLimitStore = {};
  private windowMs: number;
  private maxRequests: number;

  constructor(windowMs: number, maxRequests: number) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
  }

  /**
   * Check if request should be rate limited
   */
  public checkLimit(key: string): { allowed: boolean; resetTime: number; count: number } {
    const now = Date.now();
    const resetTime = now + this.windowMs;

    if (!this.store[key] || this.store[key].resetTime < now) {
      // Initialize or reset the counter
      this.store[key] = {
        count: 1,
        resetTime
      };
      return { allowed: true, resetTime, count: 1 };
    }

    this.store[key].count++;

    return {
      allowed: this.store[key].count <= this.maxRequests,
      resetTime: this.store[key].resetTime,
      count: this.store[key].count
    };
  }

  /**
   * Create Express middleware from this rate limiter
   */
  public middleware() {
    return (req: Request, res: Response, next: Function) => {
      const key = generateRateLimitKey(req);
      const result = this.checkLimit(key);

      // Set rate limit headers
      res.set({
        'RateLimit-Limit': this.maxRequests.toString(),
        'RateLimit-Remaining': Math.max(0, this.maxRequests - result.count).toString(),
        'RateLimit-Reset': new Date(result.resetTime).toISOString()
      });

      if (!result.allowed) {
        logger.warn('Custom rate limit exceeded', {
          key,
          count: result.count,
          maxRequests: this.maxRequests,
          windowMs: this.windowMs,
          path: req.path,
          ip: req.ip
        });

        return res.status(429).json({
          error: {
            message: 'Rate limit exceeded',
            code: 'RATE_LIMIT_EXCEEDED',
            retryAfter: Math.ceil((result.resetTime - Date.now()) / 1000)
          },
          timestamp: new Date(),
          path: req.path,
          method: req.method
        });
      }

      next();
    };
  }
}

/**
 * Get rate limit info for monitoring
 */
export function getRateLimitStats(): any {
  return {
    storeSize: Object.keys(rateLimitStore).length,
    timestamp: new Date()
  };
}

/**
 * Clear rate limit store (useful for testing)
 */
export function clearRateLimitStore(): void {
  Object.keys(rateLimitStore).forEach(key => {
    delete rateLimitStore[key];
  });
}

export default {
  generalRateLimit,
  authRateLimit,
  registerRateLimit,
  passwordResetRateLimit,
  apiRateLimit,
  messageRateLimit,
  CustomRateLimiter,
  getRateLimitStats,
  clearRateLimitStore
};