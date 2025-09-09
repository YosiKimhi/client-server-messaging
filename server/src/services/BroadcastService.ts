import { EventEmitter } from 'events';
import { logger } from '../utils/logger';
import { connectionManager } from './ConnectionManager';
import { Message, BroadcastMessage, UserProfile } from '../types/index';
import { MessageService } from './MessageService';

/**
 * Broadcast queue item
 */
interface BroadcastQueueItem {
  id: string;
  type: 'message' | 'user_joined' | 'user_left' | 'system';
  data: any;
  targetUsers?: string[]; // If specified, only broadcast to these users
  excludeUsers?: string[]; // Exclude these users from broadcast
  priority: 'high' | 'normal' | 'low';
  created_at: Date;
  retry_count?: number;
}

/**
 * Broadcast Service
 * Handles message broadcasting to all connected clients with queue management
 */
export class BroadcastService extends EventEmitter {
  private static instance: BroadcastService;
  private broadcastQueue: BroadcastQueueItem[] = [];
  private isProcessing = false;
  private processingInterval?: NodeJS.Timeout;
  private activeUsers: Set<string> = new Set();
  
  // Configuration
  private readonly QUEUE_PROCESSING_INTERVAL = 100; // 100ms
  private readonly MAX_QUEUE_SIZE = 10000;
  private readonly MAX_RETRY_ATTEMPTS = 3;
  private readonly BATCH_SIZE = 50; // Process 50 items per batch

  private constructor() {
    super();
    this.startQueueProcessing();
    this.setupConnectionManagerListeners();
  }

  /**
   * Get singleton instance
   */
  public static getInstance(): BroadcastService {
    if (!BroadcastService.instance) {
      BroadcastService.instance = new BroadcastService();
    }
    return BroadcastService.instance;
  }

  /**
   * Broadcast message to all connected users
   */
  public async broadcastMessage(message: Message, senderProfile: UserProfile): Promise<void> {
    try {
      const broadcastData = {
        id: message.id,
        sender_id: message.sender_id,
        sender_username: senderProfile.username,
        encrypted_content: message.encrypted_content,
        aes_key_encrypted: message.aes_key_encrypted,
        message_hash: message.message_hash,
        timestamp: message.timestamp,
        message_type: message.message_type,
        metadata: message.metadata
      };

      await this.queueBroadcast({
        type: 'message',
        data: broadcastData,
        excludeUsers: [message.sender_id], // Don't send back to sender
        priority: 'high'
      });

      logger.info('Message queued for broadcast', {
        messageId: message.id,
        senderId: message.sender_id,
        senderUsername: senderProfile.username,
        messageType: message.message_type,
        queueSize: this.broadcastQueue.length
      });

      // Emit event for other services
      this.emit('message_broadcasted', {
        message_id: message.id,
        sender_id: message.sender_id,
        broadcast_count: this.getActiveUserCount(),
        timestamp: new Date()
      });

    } catch (error) {
      logger.error('Failed to broadcast message', {
        messageId: message.id,
        senderId: message.sender_id,
        error: (error as Error).message
      });
      throw error;
    }
  }

  /**
   * Broadcast user joined event
   */
  public async broadcastUserJoined(user: UserProfile): Promise<void> {
    this.activeUsers.add(user.id);

    await this.queueBroadcast({
      type: 'user_joined',
      data: {
        user_id: user.id,
        username: user.username,
        joined_at: new Date(),
        active_users_count: this.activeUsers.size
      },
      excludeUsers: [user.id],
      priority: 'normal'
    });

    logger.info('User joined event queued for broadcast', {
      userId: user.id,
      username: user.username,
      activeUsers: this.activeUsers.size
    });
  }

  /**
   * Broadcast user left event
   */
  public async broadcastUserLeft(user: UserProfile): Promise<void> {
    this.activeUsers.delete(user.id);

    await this.queueBroadcast({
      type: 'user_left',
      data: {
        user_id: user.id,
        username: user.username,
        left_at: new Date(),
        active_users_count: this.activeUsers.size
      },
      priority: 'normal'
    });

    logger.info('User left event queued for broadcast', {
      userId: user.id,
      username: user.username,
      activeUsers: this.activeUsers.size
    });
  }

  /**
   * Broadcast system message
   */
  public async broadcastSystemMessage(
    message: string,
    type: 'info' | 'warning' | 'error' = 'info',
    targetUsers?: string[]
  ): Promise<void> {
    await this.queueBroadcast({
      type: 'system',
      data: {
        message,
        type,
        timestamp: new Date(),
        server_info: {
          active_users: this.activeUsers.size,
          total_connections: connectionManager.getTotalConnectionCount()
        }
      },
      targetUsers,
      priority: type === 'error' ? 'high' : 'normal'
    });

    logger.info('System message queued for broadcast', {
      message,
      type,
      targetUsers: targetUsers?.length || 'all',
      activeUsers: this.activeUsers.size
    });
  }

  /**
   * Send direct message to specific user
   */
  public async sendDirectMessage(userId: string, type: string, data: any): Promise<boolean> {
    try {
      const sentCount = connectionManager.sendToUser(userId, type, data);
      
      if (sentCount > 0) {
        logger.debug('Direct message sent', {
          userId,
          type,
          sentCount
        });
        return true;
      } else {
        logger.warn('Failed to send direct message - user not connected', {
          userId,
          type
        });
        return false;
      }
    } catch (error) {
      logger.error('Error sending direct message', {
        userId,
        type,
        error: (error as Error).message
      });
      return false;
    }
  }

  /**
   * Queue broadcast item
   */
  private async queueBroadcast(params: {
    type: 'message' | 'user_joined' | 'user_left' | 'system';
    data: any;
    targetUsers?: string[];
    excludeUsers?: string[];
    priority: 'high' | 'normal' | 'low';
  }): Promise<void> {
    // Check queue size limit
    if (this.broadcastQueue.length >= this.MAX_QUEUE_SIZE) {
      // Remove oldest low priority items
      this.broadcastQueue = this.broadcastQueue.filter(item => item.priority !== 'low');
      
      if (this.broadcastQueue.length >= this.MAX_QUEUE_SIZE) {
        logger.warn('Broadcast queue full, dropping oldest items', {
          queueSize: this.broadcastQueue.length,
          maxSize: this.MAX_QUEUE_SIZE
        });
        this.broadcastQueue.splice(0, Math.floor(this.MAX_QUEUE_SIZE * 0.1)); // Remove 10%
      }
    }

    const queueItem: BroadcastQueueItem = {
      id: `broadcast_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type: params.type,
      data: params.data,
      targetUsers: params.targetUsers,
      excludeUsers: params.excludeUsers,
      priority: params.priority,
      created_at: new Date(),
      retry_count: 0
    };

    // Insert based on priority
    if (params.priority === 'high') {
      this.broadcastQueue.unshift(queueItem);
    } else {
      this.broadcastQueue.push(queueItem);
    }
  }

  /**
   * Start queue processing
   */
  private startQueueProcessing(): void {
    this.processingInterval = setInterval(() => {
      if (!this.isProcessing && this.broadcastQueue.length > 0) {
        this.processQueue();
      }
    }, this.QUEUE_PROCESSING_INTERVAL);
  }

  /**
   * Process broadcast queue
   */
  private async processQueue(): Promise<void> {
    if (this.isProcessing || this.broadcastQueue.length === 0) {
      return;
    }

    this.isProcessing = true;

    try {
      // Process items in batches
      const batch = this.broadcastQueue.splice(0, this.BATCH_SIZE);
      
      for (const item of batch) {
        await this.processBroadcastItem(item);
      }

      if (batch.length > 0) {
        logger.debug('Processed broadcast batch', {
          batchSize: batch.length,
          remainingInQueue: this.broadcastQueue.length
        });
      }

    } catch (error) {
      logger.error('Error processing broadcast queue', {
        error: (error as Error).message,
        queueSize: this.broadcastQueue.length
      });
    } finally {
      this.isProcessing = false;
    }
  }

  /**
   * Process individual broadcast item
   */
  private async processBroadcastItem(item: BroadcastQueueItem): Promise<void> {
    try {
      let sentCount = 0;

      if (item.targetUsers) {
        // Send to specific users
        for (const userId of item.targetUsers) {
          if (!item.excludeUsers || !item.excludeUsers.includes(userId)) {
            sentCount += connectionManager.sendToUser(userId, item.type, item.data);
          }
        }
      } else {
        // Broadcast to all
        const connectedUsers = connectionManager.getConnectedUsers();
        
        for (const userId of connectedUsers) {
          if (!item.excludeUsers || !item.excludeUsers.includes(userId)) {
            sentCount += connectionManager.sendToUser(userId, item.type, item.data);
          }
        }
      }

      // Log successful broadcast
      if (sentCount > 0) {
        logger.debug('Broadcast item processed', {
          itemId: item.id,
          type: item.type,
          sentCount,
          priority: item.priority
        });
      } else if (item.retry_count! < this.MAX_RETRY_ATTEMPTS) {
        // Retry failed broadcasts
        item.retry_count = (item.retry_count || 0) + 1;
        this.broadcastQueue.push(item);
        
        logger.warn('Broadcast failed, queued for retry', {
          itemId: item.id,
          type: item.type,
          retryCount: item.retry_count
        });
      } else {
        logger.warn('Broadcast failed after max retries', {
          itemId: item.id,
          type: item.type,
          maxRetries: this.MAX_RETRY_ATTEMPTS
        });
      }

    } catch (error) {
      logger.error('Error processing broadcast item', {
        itemId: item.id,
        type: item.type,
        error: (error as Error).message
      });

      // Retry on error if under limit
      if ((item.retry_count || 0) < this.MAX_RETRY_ATTEMPTS) {
        item.retry_count = (item.retry_count || 0) + 1;
        this.broadcastQueue.push(item);
      }
    }
  }

  /**
   * Setup connection manager event listeners
   */
  private setupConnectionManagerListeners(): void {
    connectionManager.on('user_connected', (data) => {
      this.activeUsers.add(data.user_id);
      
      // Send welcome message to the connected user
      this.sendDirectMessage(data.user_id, 'welcome', {
        message: 'Connected to secure messaging system',
        connection_id: data.connection_id,
        connection_type: data.connection_type,
        server_time: new Date(),
        active_users: this.activeUsers.size
      });
    });

    connectionManager.on('user_disconnected', (data) => {
      this.activeUsers.delete(data.user_id);
    });
  }

  /**
   * Get active user count
   */
  public getActiveUserCount(): number {
    return this.activeUsers.size;
  }

  /**
   * Get broadcast queue status
   */
  public getQueueStatus(): {
    size: number;
    highPriority: number;
    normalPriority: number;
    lowPriority: number;
    isProcessing: boolean;
  } {
    const priorities = {
      high: 0,
      normal: 0,
      low: 0
    };

    for (const item of this.broadcastQueue) {
      priorities[item.priority]++;
    }

    return {
      size: this.broadcastQueue.length,
      highPriority: priorities.high,
      normalPriority: priorities.normal,
      lowPriority: priorities.low,
      isProcessing: this.isProcessing
    };
  }

  /**
   * Clear broadcast queue
   */
  public clearQueue(): void {
    this.broadcastQueue = [];
    logger.info('Broadcast queue cleared');
  }

  /**
   * Shutdown broadcast service
   */
  public shutdown(): void {
    logger.info('Shutting down BroadcastService');

    if (this.processingInterval) {
      clearInterval(this.processingInterval);
    }

    this.isProcessing = false;
    this.clearQueue();
    this.activeUsers.clear();
    this.removeAllListeners();
  }
}

// Export singleton instance
export const broadcastService = BroadcastService.getInstance();