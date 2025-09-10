import { Response } from 'express';
import { EventEmitter } from 'events';
import { logger } from '../utils/logger';
import { ConnectionInfo, UserProfile, ActiveSession } from '../types/index';

/**
 * SSE Connection interface
 */
export interface SSEConnection {
  id: string;
  user_id: string;
  username: string;
  response: Response;
  connected_at: Date;
  last_activity: Date;
  ip_address?: string;
  user_agent?: string;
  heartbeat_interval?: NodeJS.Timeout;
}

/**
 * Long polling connection interface
 */
export interface LongPollingConnection {
  id: string;
  user_id: string;
  username: string;
  resolve: (value: any) => void;
  timeout: NodeJS.Timeout;
  connected_at: Date;
  last_activity: Date;
  ip_address?: string;
  user_agent?: string;
}

/**
 * Connection Manager Service
 * Handles up to 10,000+ concurrent connections using SSE and long polling
 */
export class ConnectionManager extends EventEmitter {
  private static instance: ConnectionManager;
  private sseConnections: Map<string, SSEConnection> = new Map();
  private longPollingConnections: Map<string, LongPollingConnection> = new Map();
  private userConnectionMapping: Map<string, string[]> = new Map(); // user_id -> connection_ids
  private cleanupInterval?: NodeJS.Timeout;
  
  // Configuration
  private readonly MAX_CONNECTIONS = 15000; // Allow for some overhead
  private readonly HEARTBEAT_INTERVAL = 30000; // 30 seconds
  private readonly CLEANUP_INTERVAL = 60000; // 1 minute
  private readonly LONG_POLLING_TIMEOUT = 30000; // 30 seconds
  
  private constructor() {
    super();
    this.startCleanupInterval();
    
    // Monitor connection counts
    setInterval(() => {
      this.logConnectionStats();
    }, 30000); // Log stats every 30 seconds
  }

  /**
   * Get singleton instance
   */
  public static getInstance(): ConnectionManager {
    if (!ConnectionManager.instance) {
      ConnectionManager.instance = new ConnectionManager();
    }
    return ConnectionManager.instance;
  }

  /**
   * Add SSE connection
   */
  public addSSEConnection(
    user: UserProfile,
    session: ActiveSession,
    response: Response,
    ip_address?: string,
    user_agent?: string
  ): string {
    const connectionId = `sse_${user.id}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // Check connection limits
    if (this.getTotalConnectionCount() >= this.MAX_CONNECTIONS) {
      logger.warn('Maximum connection limit reached', {
        total: this.getTotalConnectionCount(),
        max: this.MAX_CONNECTIONS,
        userId: user.id
      });
      throw new Error('Maximum connection limit reached');
    }

    // Remove any existing connections for this user if needed
    this.removeUserConnections(user.id);

    const connection: SSEConnection = {
      id: connectionId,
      user_id: user.id,
      username: user.username,
      response,
      connected_at: new Date(),
      last_activity: new Date(),
      ip_address,
      user_agent
    };

    // Set up SSE headers with proper CORS configuration
    const corsOrigin = process.env.CORS_ORIGIN || 'http://localhost:5173';
    response.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': corsOrigin,
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Headers': 'Cache-Control, Authorization, Content-Type',
      'X-Accel-Buffering': 'no' // Disable nginx buffering
    });

    // Send initial connection success message
    this.sendSSEMessage(response, 'connected', {
      connection_id: connectionId,
      server_time: new Date(),
      message: 'Connected to real-time messaging'
    });

    // Set up heartbeat
    connection.heartbeat_interval = setInterval(() => {
      this.sendSSEHeartbeat(response);
      connection.last_activity = new Date();
    }, this.HEARTBEAT_INTERVAL);

    // Handle connection close
    response.on('close', () => {
      this.removeSSEConnection(connectionId);
    });

    response.on('error', (error) => {
      logger.error('SSE connection error', {
        connectionId,
        userId: user.id,
        error: error.message
      });
      this.removeSSEConnection(connectionId);
    });

    // Store connection
    this.sseConnections.set(connectionId, connection);
    this.addUserConnectionMapping(user.id, connectionId);

    logger.info('SSE connection established', {
      connectionId,
      userId: user.id,
      username: user.username,
      totalConnections: this.getTotalConnectionCount(),
      ip_address
    });

    this.emit('user_connected', {
      connection_id: connectionId,
      user_id: user.id,
      username: user.username,
      connection_type: 'sse',
      timestamp: new Date()
    });

    return connectionId;
  }

  /**
   * Add long polling connection
   */
  public addLongPollingConnection(
    user: UserProfile,
    session: ActiveSession,
    resolve: (value: any) => void,
    ip_address?: string,
    user_agent?: string
  ): string {
    const connectionId = `poll_${user.id}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // Check connection limits
    if (this.getTotalConnectionCount() >= this.MAX_CONNECTIONS) {
      logger.warn('Maximum connection limit reached for long polling', {
        total: this.getTotalConnectionCount(),
        max: this.MAX_CONNECTIONS,
        userId: user.id
      });
      resolve({
        error: 'Maximum connection limit reached'
      });
      return connectionId;
    }

    const timeout = setTimeout(() => {
      this.removeLongPollingConnection(connectionId);
      resolve({
        type: 'timeout',
        timestamp: new Date()
      });
    }, this.LONG_POLLING_TIMEOUT);

    const connection: LongPollingConnection = {
      id: connectionId,
      user_id: user.id,
      username: user.username,
      resolve,
      timeout,
      connected_at: new Date(),
      last_activity: new Date(),
      ip_address,
      user_agent
    };

    this.longPollingConnections.set(connectionId, connection);
    this.addUserConnectionMapping(user.id, connectionId);

    logger.debug('Long polling connection established', {
      connectionId,
      userId: user.id,
      username: user.username,
      totalConnections: this.getTotalConnectionCount()
    });

    return connectionId;
  }

  /**
   * Remove SSE connection
   */
  public removeSSEConnection(connectionId: string): void {
    const connection = this.sseConnections.get(connectionId);
    if (!connection) {
      return;
    }

    // Clear heartbeat interval
    if (connection.heartbeat_interval) {
      clearInterval(connection.heartbeat_interval);
    }

    // Close response if still open
    try {
      if (!connection.response.destroyed && !connection.response.writableEnded) {
        connection.response.end();
      }
    } catch (error) {
      logger.debug('Error closing SSE response', {
        connectionId,
        error: (error as Error).message
      });
    }

    this.sseConnections.delete(connectionId);
    this.removeUserConnectionMapping(connection.user_id, connectionId);

    logger.info('SSE connection removed', {
      connectionId,
      userId: connection.user_id,
      username: connection.username,
      totalConnections: this.getTotalConnectionCount()
    });

    this.emit('user_disconnected', {
      connection_id: connectionId,
      user_id: connection.user_id,
      username: connection.username,
      connection_type: 'sse',
      timestamp: new Date()
    });
  }

  /**
   * Remove long polling connection
   */
  public removeLongPollingConnection(connectionId: string): void {
    const connection = this.longPollingConnections.get(connectionId);
    if (!connection) {
      return;
    }

    clearTimeout(connection.timeout);
    this.longPollingConnections.delete(connectionId);
    this.removeUserConnectionMapping(connection.user_id, connectionId);

    logger.debug('Long polling connection removed', {
      connectionId,
      userId: connection.user_id,
      username: connection.username,
      totalConnections: this.getTotalConnectionCount()
    });
  }

  /**
   * Remove all connections for a user
   */
  public removeUserConnections(userId: string): void {
    const connectionIds = this.userConnectionMapping.get(userId) || [];
    
    for (const connectionId of connectionIds) {
      if (connectionId.startsWith('sse_')) {
        this.removeSSEConnection(connectionId);
      } else if (connectionId.startsWith('poll_')) {
        this.removeLongPollingConnection(connectionId);
      }
    }

    this.userConnectionMapping.delete(userId);
  }

  /**
   * Get user connections
   */
  public getUserConnections(userId: string): ConnectionInfo[] {
    const connectionIds = this.userConnectionMapping.get(userId) || [];
    const connections: ConnectionInfo[] = [];

    for (const connectionId of connectionIds) {
      if (connectionId.startsWith('sse_')) {
        const conn = this.sseConnections.get(connectionId);
        if (conn) {
          connections.push({
            id: conn.id,
            user_id: conn.user_id,
            username: conn.username,
            connected_at: conn.connected_at,
            last_activity: conn.last_activity,
            ip_address: conn.ip_address,
            user_agent: conn.user_agent
          });
        }
      } else if (connectionId.startsWith('poll_')) {
        const conn = this.longPollingConnections.get(connectionId);
        if (conn) {
          connections.push({
            id: conn.id,
            user_id: conn.user_id,
            username: conn.username,
            connected_at: conn.connected_at,
            last_activity: conn.last_activity,
            ip_address: conn.ip_address,
            user_agent: conn.user_agent
          });
        }
      }
    }

    return connections;
  }

  /**
   * Get all connected users
   */
  public getConnectedUsers(): string[] {
    return Array.from(this.userConnectionMapping.keys());
  }

  /**
   * Get total connection count
   */
  public getTotalConnectionCount(): number {
    return this.sseConnections.size + this.longPollingConnections.size;
  }

  /**
   * Get active connection count (for monitoring)
   */
  public getActiveConnectionCount(): number {
    return this.getTotalConnectionCount();
  }

  /**
   * Check if the connection manager is healthy
   */
  public isHealthy(): boolean {
    const totalConnections = this.getTotalConnectionCount();
    const isWithinLimits = totalConnections < this.MAX_CONNECTIONS;
    const hasCleanupInterval = !!this.cleanupInterval;
    
    return isWithinLimits && hasCleanupInterval;
  }

  /**
   * Send message to SSE connection
   */
  public sendSSEMessage(response: Response, type: string, data: any): boolean {
    try {
      if (response.destroyed || response.writableEnded) {
        return false;
      }

      const message = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
      response.write(message);
      return true;
    } catch (error) {
      logger.debug('Failed to send SSE message', {
        error: (error as Error).message,
        type
      });
      return false;
    }
  }

  /**
   * Send heartbeat to SSE connection
   */
  private sendSSEHeartbeat(response: Response): void {
    this.sendSSEMessage(response, 'heartbeat', {
      timestamp: new Date(),
      server_time: Date.now()
    });
  }

  /**
   * Send message to user (SSE and long polling)
   */
  public sendToUser(userId: string, type: string, data: any): number {
    const connectionIds = this.userConnectionMapping.get(userId) || [];
    let sentCount = 0;

    for (const connectionId of connectionIds) {
      if (connectionId.startsWith('sse_')) {
        const connection = this.sseConnections.get(connectionId);
        if (connection && this.sendSSEMessage(connection.response, type, data)) {
          connection.last_activity = new Date();
          sentCount++;
        }
      } else if (connectionId.startsWith('poll_')) {
        const connection = this.longPollingConnections.get(connectionId);
        if (connection) {
          connection.resolve({
            type,
            data,
            timestamp: new Date()
          });
          this.removeLongPollingConnection(connectionId);
          sentCount++;
        }
      }
    }

    return sentCount;
  }

  /**
   * Broadcast message to all connections
   */
  public broadcastToAll(type: string, data: any): number {
    let sentCount = 0;

    // Send to SSE connections
    for (const connection of this.sseConnections.values()) {
      if (this.sendSSEMessage(connection.response, type, data)) {
        connection.last_activity = new Date();
        sentCount++;
      }
    }

    // Send to long polling connections
    for (const connection of this.longPollingConnections.values()) {
      connection.resolve({
        type,
        data,
        timestamp: new Date()
      });
      this.removeLongPollingConnection(connection.id);
      sentCount++;
    }

    return sentCount;
  }

  /**
   * Add user connection mapping
   */
  private addUserConnectionMapping(userId: string, connectionId: string): void {
    if (!this.userConnectionMapping.has(userId)) {
      this.userConnectionMapping.set(userId, []);
    }
    this.userConnectionMapping.get(userId)!.push(connectionId);
  }

  /**
   * Remove user connection mapping
   */
  private removeUserConnectionMapping(userId: string, connectionId: string): void {
    const connections = this.userConnectionMapping.get(userId);
    if (connections) {
      const index = connections.indexOf(connectionId);
      if (index !== -1) {
        connections.splice(index, 1);
      }
      if (connections.length === 0) {
        this.userConnectionMapping.delete(userId);
      }
    }
  }

  /**
   * Start cleanup interval for stale connections
   */
  private startCleanupInterval(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanupStaleConnections();
    }, this.CLEANUP_INTERVAL);
  }

  /**
   * Cleanup stale connections
   */
  private cleanupStaleConnections(): void {
    const now = new Date();
    const maxAge = 5 * 60 * 1000; // 5 minutes
    let cleanedCount = 0;

    // Cleanup SSE connections
    for (const [connectionId, connection] of this.sseConnections) {
      if (now.getTime() - connection.last_activity.getTime() > maxAge ||
          connection.response.destroyed ||
          connection.response.writableEnded) {
        this.removeSSEConnection(connectionId);
        cleanedCount++;
      }
    }

    // Cleanup long polling connections
    for (const [connectionId, connection] of this.longPollingConnections) {
      if (now.getTime() - connection.last_activity.getTime() > maxAge) {
        this.removeLongPollingConnection(connectionId);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      logger.info('Cleaned up stale connections', {
        cleanedCount,
        totalConnections: this.getTotalConnectionCount()
      });
    }
  }

  /**
   * Log connection statistics
   */
  private logConnectionStats(): void {
    const stats = {
      total: this.getTotalConnectionCount(),
      sse: this.sseConnections.size,
      longPolling: this.longPollingConnections.size,
      users: this.userConnectionMapping.size,
      maxConnections: this.MAX_CONNECTIONS,
      utilizationPercent: Math.round((this.getTotalConnectionCount() / this.MAX_CONNECTIONS) * 100)
    };

    logger.info('Connection statistics', stats);
  }

  /**
   * Shutdown connection manager
   */
  public shutdown(): void {
    logger.info('Shutting down ConnectionManager');

    // Clear cleanup interval
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    // Close all SSE connections
    for (const connectionId of this.sseConnections.keys()) {
      this.removeSSEConnection(connectionId);
    }

    // Close all long polling connections
    for (const connectionId of this.longPollingConnections.keys()) {
      this.removeLongPollingConnection(connectionId);
    }

    this.removeAllListeners();
  }
}

// Export singleton instance
export const connectionManager = ConnectionManager.getInstance();