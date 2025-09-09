import { query } from '@/config/database';
import { AuditLog } from '@/types';
import { logger } from '@/utils/logger';
import { v4 as uuidv4 } from 'uuid';

export class AuditLogModel {
  /**
   * Create a new audit log entry
   */
  public static async create(auditData: {
    user_id?: string | undefined;
    action: string;
    resource_type?: string | undefined;
    resource_id?: string | undefined;
    details: Record<string, any>;
    ip_address?: string | undefined;
    user_agent?: string | undefined;
    severity?: 'debug' | 'info' | 'warn' | 'error' | 'critical';
  }): Promise<AuditLog> {
    try {
      const id = uuidv4();
      const timestamp = new Date();
      const severity = auditData.severity || 'info';

      const result = await query(
        `INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, details, ip_address, user_agent, timestamp, severity)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING *`,
        [
          id,
          auditData.user_id,
          auditData.action,
          auditData.resource_type,
          auditData.resource_id,
          JSON.stringify(auditData.details),
          auditData.ip_address,
          auditData.user_agent,
          timestamp,
          severity
        ]
      );

      const auditLog = result.rows[0] as AuditLog;

      // Parse the details JSON string back to object
      if (auditLog.details && typeof auditLog.details === 'string') {
        auditLog.details = JSON.parse(auditLog.details as string);
      }

      logger.debug('Audit log entry created', {
        auditId: auditLog.id,
        action: auditLog.action,
        severity: auditLog.severity,
        userId: auditLog.user_id
      });

      return auditLog;

    } catch (error) {
      logger.error('Failed to create audit log entry', {
        error: (error as Error).message,
        action: auditData.action,
        userId: auditData.user_id
      });
      throw error;
    }
  }

  /**
   * Get audit logs with pagination and filtering
   */
  public static async getAuditLogs(options: {
    page?: number;
    limit?: number;
    user_id?: string;
    action?: string;
    resource_type?: string;
    severity?: string;
    start_date?: Date;
    end_date?: Date;
  } = {}): Promise<{
    logs: AuditLog[];
    total: number;
    page: number;
    totalPages: number;
  }> {
    try {
      const {
        page = 1,
        limit = 50,
        user_id,
        action,
        resource_type,
        severity,
        start_date,
        end_date
      } = options;

      const offset = (page - 1) * limit;
      let whereConditions: string[] = [];
      let queryParams: any[] = [];
      let paramIndex = 1;

      // Build dynamic WHERE clause
      if (user_id) {
        whereConditions.push(`user_id = $${paramIndex++}`);
        queryParams.push(user_id);
      }

      if (action) {
        whereConditions.push(`action = $${paramIndex++}`);
        queryParams.push(action);
      }

      if (resource_type) {
        whereConditions.push(`resource_type = $${paramIndex++}`);
        queryParams.push(resource_type);
      }

      if (severity) {
        whereConditions.push(`severity = $${paramIndex++}`);
        queryParams.push(severity);
      }

      if (start_date) {
        whereConditions.push(`timestamp >= $${paramIndex++}`);
        queryParams.push(start_date);
      }

      if (end_date) {
        whereConditions.push(`timestamp <= $${paramIndex++}`);
        queryParams.push(end_date);
      }

      const whereClause = whereConditions.length > 0 
        ? `WHERE ${whereConditions.join(' AND ')}` 
        : '';

      // Get total count
      const countQuery = `SELECT COUNT(*) FROM audit_logs ${whereClause}`;
      const countResult = await query(countQuery, queryParams);
      const total = parseInt(countResult.rows[0].count, 10);

      // Get paginated results
      const dataQuery = `
        SELECT id, user_id, action, resource_type, resource_id, details, 
               ip_address, user_agent, timestamp, severity
        FROM audit_logs 
        ${whereClause}
        ORDER BY timestamp DESC
        LIMIT $${paramIndex++} OFFSET $${paramIndex++}
      `;
      queryParams.push(limit, offset);

      const dataResult = await query(dataQuery, queryParams);
      
      const logs: AuditLog[] = dataResult.rows.map((row: any) => ({
        ...row,
        details: typeof row.details === 'string' ? JSON.parse(row.details) : row.details
      }));

      const totalPages = Math.ceil(total / limit);

      return {
        logs,
        total,
        page,
        totalPages
      };

    } catch (error) {
      logger.error('Failed to get audit logs', {
        error: (error as Error).message,
        options
      });
      throw error;
    }
  }

  /**
   * Get recent security events (high severity)
   */
  public static async getSecurityEvents(limit: number = 50): Promise<AuditLog[]> {
    try {
      const result = await query(
        `SELECT id, user_id, action, resource_type, resource_id, details,
                ip_address, user_agent, timestamp, severity
         FROM audit_logs 
         WHERE severity IN ('warn', 'error', 'critical')
         ORDER BY timestamp DESC 
         LIMIT $1`,
        [limit]
      );

      const logs: AuditLog[] = result.rows.map((row: any) => ({
        ...row,
        details: typeof row.details === 'string' ? JSON.parse(row.details) : row.details
      }));

      return logs;

    } catch (error) {
      logger.error('Failed to get security events', {
        error: (error as Error).message,
        limit
      });
      throw error;
    }
  }

  /**
   * Clean up old audit logs (older than specified days)
   */
  public static async cleanupOldLogs(daysToKeep: number = 90): Promise<number> {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

      const result = await query(
        'DELETE FROM audit_logs WHERE timestamp < $1',
        [cutoffDate]
      );

      const deletedCount = result.rowCount || 0;

      if (deletedCount > 0) {
        logger.info('Cleaned up old audit logs', {
          deletedCount,
          cutoffDate,
          daysToKeep
        });
      }

      return deletedCount;

    } catch (error) {
      logger.error('Failed to cleanup old audit logs', {
        error: (error as Error).message,
        daysToKeep
      });
      throw error;
    }
  }
}

/**
 * Helper function to create audit log entries with consistent format
 */
export async function logAuditEvent(
  action: string,
  details: Record<string, any>,
  options: {
    user_id?: string | undefined;
    resource_type?: string | undefined;
    resource_id?: string | undefined;
    ip_address?: string | undefined;
    user_agent?: string | undefined;
    severity?: 'debug' | 'info' | 'warn' | 'error' | 'critical';
  } = {}
): Promise<void> {
  try {
    await AuditLogModel.create({
      action,
      details,
      ...options
    });
  } catch (error) {
    // Don't throw errors from audit logging to avoid disrupting the main flow
    logger.error('Failed to log audit event', {
      error: (error as Error).message,
      action,
      userId: options.user_id
    });
  }
}