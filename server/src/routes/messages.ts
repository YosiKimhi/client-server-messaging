import express from 'express';
import { AuthenticatedRequest, SendMessageRequest, ApiResponse, MessageResponse, PaginatedResponse } from '@/types';
import { MessageService } from '@/services/MessageService';
import { authenticate } from '@/middleware/auth';
import { logger } from '@/utils/logger';
import { sanitizeString } from '@/utils/validation';
import { logAuditEvent } from '@/models/AuditLog';

const router = express.Router();

// Apply authentication middleware to all message routes
router.use(authenticate);

/**
 * POST /api/messages/send
 * Send a new message (encrypted and stored in database)
 */
router.post('/send', async (req: AuthenticatedRequest, res: express.Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: {
          message: 'Authentication required',
          code: 'UNAUTHORIZED'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    // Validate request body
    const { content, message_type, recipient_id, metadata } = req.body;

    if (!content || typeof content !== 'string' || content.trim().length === 0) {
      return res.status(400).json({
        error: {
          message: 'Message content is required and must be a non-empty string',
          code: 'VALIDATION_ERROR',
          field: 'content'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    // Validate message content length (e.g., max 5000 characters)
    if (content.length > 5000) {
      return res.status(400).json({
        error: {
          message: 'Message content exceeds maximum length of 5000 characters',
          code: 'VALIDATION_ERROR',
          field: 'content'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    // Validate message_type if provided
    const validMessageTypes = ['text', 'system', 'notification'];
    if (message_type && !validMessageTypes.includes(message_type)) {
      return res.status(400).json({
        error: {
          message: 'Invalid message type. Must be one of: text, system, notification',
          code: 'VALIDATION_ERROR',
          field: 'message_type'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    // Validate recipient_id if provided (must be a valid UUID format)
    if (recipient_id && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(recipient_id)) {
      return res.status(400).json({
        error: {
          message: 'Invalid recipient ID format',
          code: 'VALIDATION_ERROR',
          field: 'recipient_id'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    // Sanitize content
    const sanitizedContent = sanitizeString(content, 5000);

    // Get client information for audit logging
    const clientIp = req.ip;
    const userAgent = req.headers['user-agent'];

    // Send message using MessageService
    const messageResponse = await MessageService.sendMessage({
      sender_id: req.user.id,
      content: sanitizedContent,
      message_type: message_type || 'text',
      recipient_id,
      metadata: metadata || {},
      ip_address: clientIp,
      user_agent: userAgent
    });

    // Return success response
    return res.status(201).json({
      success: true,
      data: messageResponse,
      timestamp: new Date(),
      message: 'Message sent successfully'
    } as ApiResponse<MessageResponse>);

  } catch (error) {
    const errorMessage = (error as Error).message;
    
    logger.error('Error sending message', {
      error: errorMessage,
      userId: req.user?.id,
      path: req.path,
      method: req.method,
      ip: req.ip
    });

    // Log failed attempt
    if (req.user) {
      await logAuditEvent('message_send_api_error', {
        error: errorMessage,
        user_id: req.user.id,
        path: req.path
      }, {
        user_id: req.user.id,
        resource_type: 'message',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        severity: 'error'
      });
    }

    return res.status(500).json({
      error: {
        message: 'Failed to send message',
        code: 'INTERNAL_ERROR',
        details: process.env.NODE_ENV === 'development' ? { originalError: errorMessage } : undefined
      },
      timestamp: new Date(),
      path: req.path,
      method: req.method
    } as ApiResponse);
  }
});

/**
 * GET /api/messages/history
 * Get message history with pagination and filtering
 */
router.get('/history', async (req: AuthenticatedRequest, res: express.Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: {
          message: 'Authentication required',
          code: 'UNAUTHORIZED'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    // Parse query parameters with defaults
    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string) || 50)); // Max 100 per page
    const message_type = req.query.message_type as string;
    const search = req.query.search as string;

    // Parse date filters
    let start_date: Date | undefined;
    let end_date: Date | undefined;

    if (req.query.start_date) {
      start_date = new Date(req.query.start_date as string);
      if (isNaN(start_date.getTime())) {
        return res.status(400).json({
          error: {
            message: 'Invalid start_date format. Use ISO 8601 format (YYYY-MM-DD or YYYY-MM-DDTHH:mm:ss.sssZ)',
            code: 'VALIDATION_ERROR',
            field: 'start_date'
          },
          timestamp: new Date(),
          path: req.path,
          method: req.method
        } as ApiResponse);
      }
    }

    if (req.query.end_date) {
      end_date = new Date(req.query.end_date as string);
      if (isNaN(end_date.getTime())) {
        return res.status(400).json({
          error: {
            message: 'Invalid end_date format. Use ISO 8601 format (YYYY-MM-DD or YYYY-MM-DDTHH:mm:ss.sssZ)',
            code: 'VALIDATION_ERROR',
            field: 'end_date'
          },
          timestamp: new Date(),
          path: req.path,
          method: req.method
        } as ApiResponse);
      }
    }

    // Validate message_type if provided
    const validMessageTypes = ['text', 'system', 'notification'];
    if (message_type && !validMessageTypes.includes(message_type)) {
      return res.status(400).json({
        error: {
          message: 'Invalid message type. Must be one of: text, system, notification',
          code: 'VALIDATION_ERROR',
          field: 'message_type'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    // Get message history
    const messageHistory = await MessageService.getMessageHistory({
      user_id: req.user.id,
      page,
      limit,
      message_type: message_type as any,
      search: search ? sanitizeString(search, 100) : undefined,
      start_date,
      end_date
    });

    return res.status(200).json({
      success: true,
      data: messageHistory,
      timestamp: new Date(),
      message: 'Message history retrieved successfully'
    } as ApiResponse<PaginatedResponse<MessageResponse>>);

  } catch (error) {
    const errorMessage = (error as Error).message;
    
    logger.error('Error retrieving message history', {
      error: errorMessage,
      userId: req.user?.id,
      path: req.path,
      method: req.method,
      query: req.query
    });

    return res.status(500).json({
      error: {
        message: 'Failed to retrieve message history',
        code: 'INTERNAL_ERROR',
        details: process.env.NODE_ENV === 'development' ? { originalError: errorMessage } : undefined
      },
      timestamp: new Date(),
      path: req.path,
      method: req.method
    } as ApiResponse);
  }
});

/**
 * GET /api/messages/stats
 * Get message statistics for the current user
 */
router.get('/stats', async (req: AuthenticatedRequest, res: express.Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: {
          message: 'Authentication required',
          code: 'UNAUTHORIZED'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    const stats = await MessageService.getMessageStats(req.user.id);

    return res.status(200).json({
      success: true,
      data: stats,
      timestamp: new Date(),
      message: 'Message statistics retrieved successfully'
    } as ApiResponse<typeof stats>);

  } catch (error) {
    const errorMessage = (error as Error).message;
    
    logger.error('Error retrieving message statistics', {
      error: errorMessage,
      userId: req.user?.id,
      path: req.path,
      method: req.method
    });

    return res.status(500).json({
      error: {
        message: 'Failed to retrieve message statistics',
        code: 'INTERNAL_ERROR',
        details: process.env.NODE_ENV === 'development' ? { originalError: errorMessage } : undefined
      },
      timestamp: new Date(),
      path: req.path,
      method: req.method
    } as ApiResponse);
  }
});

/**
 * GET /api/messages/:id
 * Get a specific message by ID
 */
router.get('/:id', async (req: AuthenticatedRequest, res: express.Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: {
          message: 'Authentication required',
          code: 'UNAUTHORIZED'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    const messageId = req.params.id;

    if (!messageId) {
      return res.status(400).json({
        error: {
          message: 'Message ID is required',
          code: 'VALIDATION_ERROR',
          field: 'id'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    // Validate message ID format (UUID)
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(messageId)) {
      return res.status(400).json({
        error: {
          message: 'Invalid message ID format',
          code: 'VALIDATION_ERROR',
          field: 'id'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    const message = await MessageService.getMessageById(messageId, req.user.id);

    if (!message) {
      return res.status(404).json({
        error: {
          message: 'Message not found or access denied',
          code: 'NOT_FOUND'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    return res.status(200).json({
      success: true,
      data: message,
      timestamp: new Date(),
      message: 'Message retrieved successfully'
    } as ApiResponse<MessageResponse>);

  } catch (error) {
    const errorMessage = (error as Error).message;
    
    logger.error('Error retrieving message', {
      error: errorMessage,
      userId: req.user?.id,
      messageId: req.params.id,
      path: req.path,
      method: req.method
    });

    return res.status(500).json({
      error: {
        message: 'Failed to retrieve message',
        code: 'INTERNAL_ERROR',
        details: process.env.NODE_ENV === 'development' ? { originalError: errorMessage } : undefined
      },
      timestamp: new Date(),
      path: req.path,
      method: req.method
    } as ApiResponse);
  }
});

/**
 * DELETE /api/messages/:id
 * Delete a message (soft delete)
 */
router.delete('/:id', async (req: AuthenticatedRequest, res: express.Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: {
          message: 'Authentication required',
          code: 'UNAUTHORIZED'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    const messageId = req.params.id;

    if (!messageId) {
      return res.status(400).json({
        error: {
          message: 'Message ID is required',
          code: 'VALIDATION_ERROR',
          field: 'id'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    // Validate message ID format (UUID)
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(messageId)) {
      return res.status(400).json({
        error: {
          message: 'Invalid message ID format',
          code: 'VALIDATION_ERROR',
          field: 'id'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    const success = await MessageService.deleteMessage(messageId, req.user.id);

    if (!success) {
      return res.status(404).json({
        error: {
          message: 'Message not found or access denied',
          code: 'NOT_FOUND'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    return res.status(200).json({
      success: true,
      data: { deleted: true, message_id: messageId },
      timestamp: new Date(),
      message: 'Message deleted successfully'
    } as ApiResponse<{ deleted: boolean; message_id: string }>);

  } catch (error) {
    const errorMessage = (error as Error).message;
    
    // Check if it's an authorization error
    if (errorMessage.includes('Unauthorized')) {
      return res.status(403).json({
        error: {
          message: 'Unauthorized to delete this message',
          code: 'FORBIDDEN'
        },
        timestamp: new Date(),
        path: req.path,
        method: req.method
      } as ApiResponse);
    }

    logger.error('Error deleting message', {
      error: errorMessage,
      userId: req.user?.id,
      messageId: req.params.id,
      path: req.path,
      method: req.method
    });

    return res.status(500).json({
      error: {
        message: 'Failed to delete message',
        code: 'INTERNAL_ERROR',
        details: process.env.NODE_ENV === 'development' ? { originalError: errorMessage } : undefined
      },
      timestamp: new Date(),
      path: req.path,
      method: req.method
    } as ApiResponse);
  }
});

export default router;