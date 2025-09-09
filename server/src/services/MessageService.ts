import { query, transaction } from '../config/database';
import { Message, MessageResponse, PaginatedResponse, SendMessageRequest } from '../types/index';
import { cryptoService } from './CryptoService';
import { logAuditEvent } from '../models/AuditLog';
import { logger } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';
import { broadcastService } from './BroadcastService';

export interface SendMessageOptions {
  sender_id: string;
  content: string;
  message_type?: 'text' | 'system' | 'notification';
  recipient_id?: string;
  metadata?: Record<string, any>;
  ip_address?: string | undefined;
  user_agent?: string | undefined;
}

export interface GetMessagesOptions {
  user_id: string;
  page?: number;
  limit?: number;
  message_type?: 'text' | 'system' | 'notification';
  search?: string | undefined;
  start_date?: Date | undefined;
  end_date?: Date | undefined;
}

export class MessageService {
  /**
   * Send a message with encryption and audit logging
   */
  public static async sendMessage(options: SendMessageOptions): Promise<MessageResponse> {
    const {
      sender_id,
      content,
      message_type = 'text',
      recipient_id,
      metadata = {},
      ip_address,
      user_agent
    } = options;

    try {
      // Get sender information for validation
      const senderResult = await query(
        'SELECT id, username, public_key FROM users WHERE id = $1 AND is_active = true',
        [sender_id]
      );

      if (senderResult.rows.length === 0) {
        throw new Error('Sender not found or inactive');
      }

      const sender = senderResult.rows[0];

      // Create message hash for integrity verification
      const messageHash = cryptoService.hash(content + sender_id + Date.now());

      // Encrypt the message content for storage
      const encryptedContent = cryptoService.encryptForStorage(content);

      // For broadcast messages, we need to encrypt the AES key for all users
      // For now, we'll store a server-encrypted version and handle individual encryption in real-time
      const serverAesKey = cryptoService.generateSecureToken(32); // Generate AES key
      const encryptedAesKey = cryptoService.encryptForStorage(serverAesKey); // Encrypt with server key

      const messageId = uuidv4();
      const timestamp = new Date();
      const is_broadcast = !recipient_id;

      // Store message in database within transaction
      const result = await transaction(async (client) => {
        // Insert message
        await client.query(
          `INSERT INTO messages (id, sender_id, encrypted_content, aes_key_encrypted, message_hash, 
           timestamp, message_type, is_broadcast, recipient_id, metadata, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
          [
            messageId,
            sender_id,
            encryptedContent,
            encryptedAesKey,
            messageHash,
            timestamp,
            message_type,
            is_broadcast,
            recipient_id,
            JSON.stringify(metadata),
            timestamp
          ]
        );

        // Get the inserted message with sender info
        const messageResult = await client.query(
          `SELECT m.id, m.sender_id, m.encrypted_content, m.aes_key_encrypted, 
                  m.message_hash, m.timestamp, m.message_type, m.metadata,
                  u.username as sender_username
           FROM messages m
           JOIN users u ON m.sender_id = u.id
           WHERE m.id = $1`,
          [messageId]
        );

        return messageResult.rows[0];
      });

      // Create response object
      const messageResponse: MessageResponse = {
        id: result.id,
        sender_id: result.sender_id,
        sender_username: result.sender_username,
        encrypted_content: result.encrypted_content,
        aes_key_encrypted: result.aes_key_encrypted,
        message_hash: result.message_hash,
        timestamp: result.timestamp,
        message_type: result.message_type,
        metadata: typeof result.metadata === 'string' ? JSON.parse(result.metadata) : result.metadata
      };

      // Log audit event
      await logAuditEvent('message_sent', {
        message_id: messageId,
        message_type,
        is_broadcast,
        recipient_id,
        content_length: content.length,
        has_metadata: Object.keys(metadata).length > 0
      }, {
        user_id: sender_id,
        resource_type: 'message',
        resource_id: messageId,
        ip_address,
        user_agent,
        severity: 'info'
      });

      logger.info('Message sent successfully', {
        messageId,
        senderId: sender_id,
        senderUsername: sender.username,
        messageType: message_type,
        isBroadcast: is_broadcast,
        recipientId: recipient_id,
        contentLength: content.length
      });

      // If this is a broadcast message, add it to the broadcast queue
      if (is_broadcast) {
        const messageData: Message = {
          id: messageResponse.id,
          sender_id: messageResponse.sender_id,
          encrypted_content: messageResponse.encrypted_content,
          aes_key_encrypted: messageResponse.aes_key_encrypted,
          message_hash: messageResponse.message_hash,
          timestamp: messageResponse.timestamp,
          message_type: messageResponse.message_type as 'text' | 'system' | 'notification',
          is_broadcast: true,
          recipient_id: undefined,
          metadata: messageResponse.metadata,
          created_at: messageResponse.timestamp
        };

        const senderProfile = {
          id: sender.id,
          username: sender.username,
          email: '', // Not needed for broadcasting
          public_key: sender.public_key,
          is_active: true,
          created_at: new Date(),
          last_login: new Date()
        };

        // Broadcast the message to all connected clients
        await broadcastService.broadcastMessage(messageData, senderProfile);
      }

      return messageResponse;

    } catch (error) {
      // Log failed message attempt
      await logAuditEvent('message_send_failed', {
        error: (error as Error).message,
        sender_id,
        message_type,
        recipient_id
      }, {
        user_id: sender_id,
        resource_type: 'message',
        ip_address,
        user_agent,
        severity: 'error'
      });

      logger.error('Failed to send message', {
        error: (error as Error).message,
        senderId: sender_id,
        messageType: message_type,
        recipientId: recipient_id
      });

      throw error;
    }
  }

  /**
   * Get message history with pagination
   */
  public static async getMessageHistory(options: GetMessagesOptions): Promise<PaginatedResponse<MessageResponse>> {
    const {
      user_id,
      page = 1,
      limit = 50,
      message_type,
      search,
      start_date,
      end_date
    } = options;

    try {
      // Validate user exists and is active
      const userResult = await query(
        'SELECT id FROM users WHERE id = $1 AND is_active = true',
        [user_id]
      );

      if (userResult.rows.length === 0) {
        throw new Error('User not found or inactive');
      }

      const offset = (page - 1) * limit;
      let whereConditions: string[] = ['(m.is_broadcast = true OR m.sender_id = $1 OR m.recipient_id = $1)'];
      let queryParams: any[] = [user_id];
      let paramIndex = 2;

      // Build dynamic WHERE clause
      if (message_type) {
        whereConditions.push(`m.message_type = $${paramIndex++}`);
        queryParams.push(message_type);
      }

      if (start_date) {
        whereConditions.push(`m.timestamp >= $${paramIndex++}`);
        queryParams.push(start_date);
      }

      if (end_date) {
        whereConditions.push(`m.timestamp <= $${paramIndex++}`);
        queryParams.push(end_date);
      }

      // For search, we'll search in decrypted content (note: this is a simplified approach)
      // In production, you might want to implement server-side search indexes
      if (search) {
        whereConditions.push(`(
          u.username ILIKE $${paramIndex++} OR 
          m.message_type ILIKE $${paramIndex++}
        )`);
        queryParams.push(`%${search}%`, `%${search}%`);
        paramIndex += 2;
      }

      const whereClause = whereConditions.join(' AND ');

      // Get total count
      const countQuery = `
        SELECT COUNT(*) 
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE ${whereClause}
      `;
      const countResult = await query(countQuery, queryParams);
      const total = parseInt(countResult.rows[0].count, 10);

      // Get paginated messages
      const messagesQuery = `
        SELECT m.id, m.sender_id, m.encrypted_content, m.aes_key_encrypted,
               m.message_hash, m.timestamp, m.message_type, m.metadata,
               u.username as sender_username
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE ${whereClause}
        ORDER BY m.timestamp DESC
        LIMIT $${paramIndex++} OFFSET $${paramIndex++}
      `;
      queryParams.push(limit, offset);

      const messagesResult = await query(messagesQuery, queryParams);

      const messages: MessageResponse[] = messagesResult.rows.map((row: any) => ({
        id: row.id,
        sender_id: row.sender_id,
        sender_username: row.sender_username,
        encrypted_content: row.encrypted_content,
        aes_key_encrypted: row.aes_key_encrypted,
        message_hash: row.message_hash,
        timestamp: row.timestamp,
        message_type: row.message_type,
        metadata: typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata
      }));

      const totalPages = Math.ceil(total / limit);

      // Log audit event for message retrieval
      await logAuditEvent('messages_retrieved', {
        user_id,
        page,
        limit,
        total,
        message_type,
        has_search: !!search,
        results_count: messages.length
      }, {
        user_id,
        resource_type: 'message',
        severity: 'debug'
      });

      logger.debug('Message history retrieved', {
        userId: user_id,
        page,
        limit,
        total,
        totalPages,
        messagesCount: messages.length
      });

      return {
        data: messages,
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1
        }
      };

    } catch (error) {
      await logAuditEvent('messages_retrieval_failed', {
        error: (error as Error).message,
        user_id,
        page,
        limit
      }, {
        user_id,
        resource_type: 'message',
        severity: 'error'
      });

      logger.error('Failed to retrieve message history', {
        error: (error as Error).message,
        userId: user_id,
        page,
        limit
      });

      throw error;
    }
  }

  /**
   * Get a specific message by ID (with permission check)
   */
  public static async getMessageById(messageId: string, userId: string): Promise<MessageResponse | null> {
    try {
      const result = await query(
        `SELECT m.id, m.sender_id, m.encrypted_content, m.aes_key_encrypted,
                m.message_hash, m.timestamp, m.message_type, m.metadata,
                u.username as sender_username
         FROM messages m
         JOIN users u ON m.sender_id = u.id
         WHERE m.id = $1 AND (m.is_broadcast = true OR m.sender_id = $2 OR m.recipient_id = $2)`,
        [messageId, userId]
      );

      if (result.rows.length === 0) {
        return null;
      }

      const row = result.rows[0];
      
      const message: MessageResponse = {
        id: row.id,
        sender_id: row.sender_id,
        sender_username: row.sender_username,
        encrypted_content: row.encrypted_content,
        aes_key_encrypted: row.aes_key_encrypted,
        message_hash: row.message_hash,
        timestamp: row.timestamp,
        message_type: row.message_type,
        metadata: typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata
      };

      // Log audit event
      await logAuditEvent('message_accessed', {
        message_id: messageId,
        accessed_by: userId
      }, {
        user_id: userId,
        resource_type: 'message',
        resource_id: messageId,
        severity: 'debug'
      });

      return message;

    } catch (error) {
      logger.error('Failed to get message by ID', {
        error: (error as Error).message,
        messageId,
        userId
      });
      throw error;
    }
  }

  /**
   * Delete a message (soft delete by marking as inactive)
   */
  public static async deleteMessage(messageId: string, userId: string): Promise<boolean> {
    try {
      // Check if user owns the message or is an admin
      const messageResult = await query(
        'SELECT sender_id FROM messages WHERE id = $1',
        [messageId]
      );

      if (messageResult.rows.length === 0) {
        throw new Error('Message not found');
      }

      const senderId = messageResult.rows[0].sender_id;
      
      if (senderId !== userId) {
        throw new Error('Unauthorized to delete this message');
      }

      // For this implementation, we'll add a deleted_at column to track deletions
      // For now, we'll use metadata to mark as deleted
      await query(
        `UPDATE messages 
         SET metadata = jsonb_set(
           COALESCE(metadata::jsonb, '{}'::jsonb), 
           '{deleted_at}', 
           to_jsonb(NOW()::text)
         )
         WHERE id = $1`,
        [messageId]
      );

      // Log audit event
      await logAuditEvent('message_deleted', {
        message_id: messageId,
        deleted_by: userId,
        original_sender: senderId
      }, {
        user_id: userId,
        resource_type: 'message',
        resource_id: messageId,
        severity: 'info'
      });

      logger.info('Message deleted', {
        messageId,
        deletedBy: userId,
        originalSender: senderId
      });

      return true;

    } catch (error) {
      await logAuditEvent('message_deletion_failed', {
        error: (error as Error).message,
        message_id: messageId,
        user_id: userId
      }, {
        user_id: userId,
        resource_type: 'message',
        resource_id: messageId,
        severity: 'error'
      });

      logger.error('Failed to delete message', {
        error: (error as Error).message,
        messageId,
        userId
      });

      throw error;
    }
  }

  /**
   * Get message statistics for a user
   */
  public static async getMessageStats(userId: string): Promise<{
    total_sent: number;
    total_received: number;
    total_broadcast: number;
    messages_by_type: Record<string, number>;
  }> {
    try {
      // Get sent messages count
      const sentResult = await query(
        'SELECT COUNT(*) as count FROM messages WHERE sender_id = $1',
        [userId]
      );

      // Get received messages count (direct messages only)
      const receivedResult = await query(
        'SELECT COUNT(*) as count FROM messages WHERE recipient_id = $1',
        [userId]
      );

      // Get broadcast messages count
      const broadcastResult = await query(
        'SELECT COUNT(*) as count FROM messages WHERE is_broadcast = true'
      );

      // Get messages by type
      const typeResult = await query(
        `SELECT message_type, COUNT(*) as count 
         FROM messages 
         WHERE sender_id = $1 OR recipient_id = $1 OR is_broadcast = true
         GROUP BY message_type`,
        [userId]
      );

      const messagesByType = typeResult.rows.reduce((acc: Record<string, number>, row: any) => {
        acc[row.message_type] = parseInt(row.count, 10);
        return acc;
      }, {});

      return {
        total_sent: parseInt(sentResult.rows[0].count, 10),
        total_received: parseInt(receivedResult.rows[0].count, 10),
        total_broadcast: parseInt(broadcastResult.rows[0].count, 10),
        messages_by_type: messagesByType
      };

    } catch (error) {
      logger.error('Failed to get message statistics', {
        error: (error as Error).message,
        userId
      });
      throw error;
    }
  }

  /**
   * Clean up old messages (for maintenance)
   */
  public static async cleanupOldMessages(daysToKeep: number = 365): Promise<number> {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

      const result = await query(
        `UPDATE messages 
         SET metadata = jsonb_set(
           COALESCE(metadata::jsonb, '{}'::jsonb), 
           '{archived_at}', 
           to_jsonb(NOW()::text)
         )
         WHERE timestamp < $1 AND (metadata->'archived_at') IS NULL`,
        [cutoffDate]
      );

      const archivedCount = result.rowCount || 0;

      if (archivedCount > 0) {
        // Log audit event
        await logAuditEvent('messages_archived', {
          archived_count: archivedCount,
          cutoff_date: cutoffDate,
          days_to_keep: daysToKeep
        }, {
          resource_type: 'message',
          severity: 'info'
        });

        logger.info('Old messages archived', {
          archivedCount,
          cutoffDate,
          daysToKeep
        });
      }

      return archivedCount;

    } catch (error) {
      logger.error('Failed to cleanup old messages', {
        error: (error as Error).message,
        daysToKeep
      });
      throw error;
    }
  }
}