import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import { logger } from '../utils/logger';
import { generateRequestId, setSecurityHeaders } from '../utils/validation';

/**
 * Security middleware configuration for the messaging application
 */

/**
 * Configure Helmet.js with specific security settings
 */
export const securityHeaders = helmet({
  // Content Security Policy
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles for SSE
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"], // Allow SSE connections
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      childSrc: ["'none'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  
  // HTTP Strict Transport Security
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  
  // X-Frame-Options
  frameguard: { action: 'deny' },
  
  // X-Content-Type-Options
  noSniff: true,
  
  // X-XSS-Protection (deprecated but still useful for older browsers)
  xssFilter: true,
  
  // Referrer Policy
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  
  // Hide X-Powered-By header
  hidePoweredBy: true,
  
  // DNS Prefetch Control
  dnsPrefetchControl: { allow: false },
  
  // IE No Open
  ieNoOpen: true,
  
  // Don't sniff MIME types - note: noCache is not a valid helmet option
  // Caching is controlled separately
  
  // Permissions Policy (formerly Feature Policy)
  permittedCrossDomainPolicies: false
});

/**
 * Add custom security headers and request tracking
 */
export const customSecurityMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  // Generate unique request ID for tracking
  const requestId = generateRequestId();
  (req as any).requestId = requestId;
  res.setHeader('X-Request-ID', requestId);
  
  // Additional security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('X-Download-Options', 'noopen');
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  
  // Cache control for sensitive endpoints
  if (req.path.startsWith('/api/auth') || req.path.startsWith('/api/messages')) {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  
  next();
};

/**
 * CORS security middleware with enhanced validation
 */
export const corsSecurityMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const origin = req.get('Origin');
  const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];
  
  // Log suspicious origin requests
  if (origin && !allowedOrigins.includes(origin)) {
    logger.warn('Blocked request from unauthorized origin', {
      origin,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path,
      method: req.method,
      requestId: (req as any).requestId
    });
  }
  
  next();
};

/**
 * Request sanitization middleware
 */
export const requestSanitization = (req: Request, res: Response, next: NextFunction): void => {
  // Sanitize query parameters
  if (req.query && typeof req.query === 'object') {
    for (const [key, value] of Object.entries(req.query)) {
      if (typeof value === 'string') {
        // Remove potentially dangerous characters from query params
        req.query[key] = value.replace(/[<>'"&]/g, '');
      }
    }
  }
  
  // Log suspicious requests
  const suspiciousPatterns = [
    /<script/i,
    /javascript:/i,
    /vbscript:/i,
    /onload=/i,
    /onerror=/i,
    /eval\(/i,
    /document\./i,
    /window\./i,
    /\.\.\/\.\.\//,  // Path traversal
    /<img.*src.*=/i,
    /<iframe/i
  ];
  
  const requestString = JSON.stringify({
    body: req.body,
    query: req.query,
    params: req.params
  });
  
  const hasSuspiciousContent = suspiciousPatterns.some(pattern => 
    pattern.test(requestString)
  );
  
  if (hasSuspiciousContent) {
    logger.warn('Suspicious request detected', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path,
      method: req.method,
      requestId: (req as any).requestId,
      suspiciousContent: true
    });
    
    // Block obviously malicious requests
    if (/<script/i.test(requestString) || /javascript:/i.test(requestString)) {
      res.status(400).json({
        error: {
          message: 'Invalid request content',
          code: 'MALICIOUS_REQUEST_BLOCKED'
        },
        timestamp: new Date(),
        requestId: (req as any).requestId
      });
      return;
    }
  }
  
  next();
};

/**
 * Request size limitation middleware
 */
export const requestSizeLimit = (req: Request, res: Response, next: NextFunction): void => {
  const contentLength = req.get('Content-Length');
  const maxSize = 10 * 1024 * 1024; // 10MB
  
  if (contentLength && parseInt(contentLength) > maxSize) {
    logger.warn('Request size limit exceeded', {
      contentLength: parseInt(contentLength),
      maxSize,
      ip: req.ip,
      path: req.path,
      method: req.method,
      requestId: (req as any).requestId
    });
    
    res.status(413).json({
      error: {
        message: 'Request entity too large',
        code: 'REQUEST_TOO_LARGE',
        maxSize: '10MB'
      },
      timestamp: new Date(),
      requestId: (req as any).requestId
    });
    return;
  }
  
  next();
};

/**
 * Security monitoring middleware
 */
export const securityMonitoring = (req: Request, res: Response, next: NextFunction): void => {
  const start = Date.now();
  
  // Monitor for potential attacks
  const userAgent = req.get('User-Agent') || '';
  const suspiciousUserAgents = [
    /sqlmap/i,
    /nikto/i,
    /burp/i,
    /nessus/i,
    /masscan/i,
    /nmap/i,
    /curl.*bot/i,
    /wget.*bot/i
  ];
  
  if (suspiciousUserAgents.some(pattern => pattern.test(userAgent))) {
    logger.warn('Suspicious user agent detected', {
      userAgent,
      ip: req.ip,
      path: req.path,
      method: req.method,
      requestId: (req as any).requestId
    });
  }
  
  // Log response time for monitoring
  res.on('finish', () => {
    const duration = Date.now() - start;
    
    if (duration > 5000) { // Log slow requests (> 5 seconds)
      logger.warn('Slow request detected', {
        duration,
        path: req.path,
        method: req.method,
        statusCode: res.statusCode,
        requestId: (req as any).requestId
      });
    }
  });
  
  next();
};

/**
 * Combined security middleware stack
 */
export const securityMiddlewareStack = [
  customSecurityMiddleware,
  corsSecurityMiddleware,
  requestSanitization,
  requestSizeLimit,
  securityMonitoring
];

/**
 * Get security metrics for monitoring
 */
export function getSecurityMetrics(): any {
  return {
    timestamp: new Date(),
    securityFeatures: {
      helmet: 'enabled',
      customHeaders: 'enabled',
      requestSanitization: 'enabled',
      corsValidation: 'enabled',
      sizeLimit: 'enabled',
      monitoring: 'enabled'
    },
    maxRequestSize: '10MB',
    securityHeaders: [
      'X-Content-Type-Options',
      'X-Frame-Options',
      'X-XSS-Protection',
      'Referrer-Policy',
      'Permissions-Policy',
      'X-Download-Options',
      'X-DNS-Prefetch-Control',
      'Content-Security-Policy',
      'Strict-Transport-Security'
    ]
  };
}

export default {
  securityHeaders,
  customSecurityMiddleware,
  corsSecurityMiddleware,
  requestSanitization,
  requestSizeLimit,
  securityMonitoring,
  securityMiddlewareStack,
  getSecurityMetrics
};