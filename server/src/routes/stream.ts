import { Router, Request, Response } from 'express';
import { AuthenticatedRequest } from '../types/index';
import { authenticate } from '../middleware/auth';
import { connectionManager } from '../services/ConnectionManager';
import { broadcastService } from '../services/BroadcastService';
import { logger } from '../utils/logger';
import { setSecurityHeaders } from '../utils/validation';

const router = Router();

/**
 * Server-Sent Events endpoint for real-time messaging
 * GET /api/stream/events
 */
router.get('/events', authenticate, async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user || !req.session) {
      res.status(401).json({
        error: {
          message: 'Authentication required',
          code: 'NO_AUTH'
        },
        timestamp: new Date()
      });
      return;
    }

    // Set security headers
    setSecurityHeaders(res);

    // Get client info
    const ip_address = req.ip;
    const user_agent = req.get('User-Agent');

    logger.info('SSE connection request', {
      userId: req.user.id,
      username: req.user.username,
      sessionId: req.session.id,
      ip: ip_address,
      userAgent: user_agent
    });

    try {
      // Establish SSE connection
      const connectionId = connectionManager.addSSEConnection(
        req.user,
        req.session,
        res,
        ip_address,
        user_agent
      );

      // Broadcast user joined event
      await broadcastService.broadcastUserJoined(req.user);

      // Handle connection cleanup on client disconnect
      req.on('close', () => {
        logger.info('SSE client disconnected', {
          connectionId,
          userId: req.user!.id,
          username: req.user!.username
        });
      });

      // Keep connection alive until client disconnects
      // The connection will be managed by ConnectionManager

    } catch (connectionError) {
      logger.error('Failed to establish SSE connection', {
        userId: req.user.id,
        error: (connectionError as Error).message
      });

      res.status(503).json({
        error: {
          message: 'Unable to establish real-time connection',
          code: 'CONNECTION_FAILED',
          details: (connectionError as Error).message
        },
        timestamp: new Date()
      });
    }

  } catch (error) {
    logger.error('SSE endpoint error', {
      error: (error as Error).message,
      userId: req.user?.id,
      stack: (error as Error).stack
    });

    if (!res.headersSent) {
      res.status(500).json({
        error: {
          message: 'Internal server error',
          code: 'INTERNAL_ERROR'
        },
        timestamp: new Date()
      });
    }
  }
});

/**
 * Long polling endpoint as fallback for SSE
 * GET /api/stream/poll
 */
router.get('/poll', authenticate, async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user || !req.session) {
      res.status(401).json({
        error: {
          message: 'Authentication required',
          code: 'NO_AUTH'
        },
        timestamp: new Date()
      });
      return;
    }

    // Set security headers
    setSecurityHeaders(res);

    // Get client info
    const ip_address = req.ip;
    const user_agent = req.get('User-Agent');

    logger.debug('Long polling connection request', {
      userId: req.user.id,
      username: req.user.username,
      sessionId: req.session.id,
      ip: ip_address
    });

    try {
      // Set up long polling connection
      const connectionPromise = new Promise<any>((resolve) => {
        connectionManager.addLongPollingConnection(
          req.user!,
          req.session!,
          resolve,
          ip_address,
          user_agent
        );
      });

      // Wait for message or timeout
      const result = await connectionPromise;

      // Send response
      res.json({
        success: true,
        data: result,
        timestamp: new Date()
      });

    } catch (connectionError) {
      logger.error('Failed to establish long polling connection', {
        userId: req.user.id,
        error: (connectionError as Error).message
      });

      res.status(503).json({
        error: {
          message: 'Unable to establish polling connection',
          code: 'POLLING_FAILED',
          details: (connectionError as Error).message
        },
        timestamp: new Date()
      });
    }

  } catch (error) {
    logger.error('Long polling endpoint error', {
      error: (error as Error).message,
      userId: req.user?.id,
      stack: (error as Error).stack
    });

    res.status(500).json({
      error: {
        message: 'Internal server error',
        code: 'INTERNAL_ERROR'
      },
      timestamp: new Date()
    });
  }
});

/**
 * Check connection status
 * GET /api/stream/status
 */
router.get('/status', authenticate, (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      res.status(401).json({
        error: {
          message: 'Authentication required',
          code: 'NO_AUTH'
        },
        timestamp: new Date()
      });
      return;
    }

    const userConnections = connectionManager.getUserConnections(req.user.id);
    const totalConnections = connectionManager.getTotalConnectionCount();
    const activeUsers = broadcastService.getActiveUserCount();
    const queueStatus = broadcastService.getQueueStatus();

    res.json({
      success: true,
      data: {
        user: {
          id: req.user.id,
          username: req.user.username,
          connections: userConnections
        },
        server: {
          total_connections: totalConnections,
          active_users: activeUsers,
          broadcast_queue: queueStatus,
          server_time: new Date(),
          connection_types: ['sse', 'long_polling'],
          max_connections: 15000
        }
      },
      timestamp: new Date()
    });

  } catch (error) {
    logger.error('Stream status endpoint error', {
      error: (error as Error).message,
      userId: req.user?.id
    });

    res.status(500).json({
      error: {
        message: 'Failed to get connection status',
        code: 'STATUS_ERROR'
      },
      timestamp: new Date()
    });
  }
});

/**
 * Disconnect user connections
 * POST /api/stream/disconnect
 */
router.post('/disconnect', authenticate, async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      res.status(401).json({
        error: {
          message: 'Authentication required',
          code: 'NO_AUTH'
        },
        timestamp: new Date()
      });
      return;
    }

    const userConnectionsBefore = connectionManager.getUserConnections(req.user.id);
    
    // Remove all user connections
    connectionManager.removeUserConnections(req.user.id);
    
    // Broadcast user left event
    await broadcastService.broadcastUserLeft(req.user);

    logger.info('User disconnected via API', {
      userId: req.user.id,
      username: req.user.username,
      connectionsRemoved: userConnectionsBefore.length
    });

    res.json({
      success: true,
      data: {
        message: 'Disconnected successfully',
        connections_removed: userConnectionsBefore.length
      },
      timestamp: new Date()
    });

  } catch (error) {
    logger.error('Disconnect endpoint error', {
      error: (error as Error).message,
      userId: req.user?.id
    });

    res.status(500).json({
      error: {
        message: 'Failed to disconnect',
        code: 'DISCONNECT_ERROR'
      },
      timestamp: new Date()
    });
  }
});

/**
 * Send test message (for development/testing)
 * POST /api/stream/test
 */
router.post('/test', authenticate, async (req: AuthenticatedRequest, res: Response) => {
  try {
    if (!req.user) {
      res.status(401).json({
        error: {
          message: 'Authentication required',
          code: 'NO_AUTH'
        },
        timestamp: new Date()
      });
      return;
    }

    const { message = 'Test message', type = 'test' } = req.body;

    // Send test message to user's connections
    const sentCount = connectionManager.sendToUser(req.user.id, type, {
      message,
      sender: 'system',
      timestamp: new Date(),
      test: true
    });

    logger.info('Test message sent', {
      userId: req.user.id,
      username: req.user.username,
      message,
      type,
      sentCount
    });

    res.json({
      success: true,
      data: {
        message: 'Test message sent',
        type,
        sent_to_connections: sentCount
      },
      timestamp: new Date()
    });

  } catch (error) {
    logger.error('Test endpoint error', {
      error: (error as Error).message,
      userId: req.user?.id
    });

    res.status(500).json({
      error: {
        message: 'Failed to send test message',
        code: 'TEST_ERROR'
      },
      timestamp: new Date()
    });
  }
});

/**
 * Get server statistics (admin only)
 * GET /api/stream/admin/stats
 */
router.get('/admin/stats', authenticate, (req: AuthenticatedRequest, res: Response) => {
  try {
    // Simple admin check - in production, use proper role-based auth
    if (!req.user || req.user.username !== 'admin') {
      res.status(403).json({
        error: {
          message: 'Admin access required',
          code: 'INSUFFICIENT_PERMISSIONS'
        },
        timestamp: new Date()
      });
      return;
    }

    const totalConnections = connectionManager.getTotalConnectionCount();
    const connectedUsers = connectionManager.getConnectedUsers();
    const activeUsers = broadcastService.getActiveUserCount();
    const queueStatus = broadcastService.getQueueStatus();

    // Get detailed connection info
    const connectionDetails = connectedUsers.map(userId => {
      return {
        user_id: userId,
        connections: connectionManager.getUserConnections(userId)
      };
    });

    res.json({
      success: true,
      data: {
        overview: {
          total_connections: totalConnections,
          unique_users: connectedUsers.length,
          active_users: activeUsers,
          server_uptime: process.uptime(),
          memory_usage: process.memoryUsage(),
          timestamp: new Date()
        },
        connections: connectionDetails,
        broadcast_queue: queueStatus,
        performance: {
          queue_processing_active: queueStatus.isProcessing,
          queue_backlog: queueStatus.size,
          high_priority_items: queueStatus.highPriority
        }
      },
      timestamp: new Date()
    });

  } catch (error) {
    logger.error('Admin stats endpoint error', {
      error: (error as Error).message,
      userId: req.user?.id
    });

    res.status(500).json({
      error: {
        message: 'Failed to get admin statistics',
        code: 'ADMIN_STATS_ERROR'
      },
      timestamp: new Date()
    });
  }
});

export default router;