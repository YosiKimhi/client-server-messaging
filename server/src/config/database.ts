import { Pool, PoolClient, PoolConfig } from 'pg';
import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger';
import { config } from './environment';

export interface DatabaseConfig extends PoolConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  ssl?: boolean | object;
  max: number;
  min: number;
  idleTimeoutMillis: number;
  connectionTimeoutMillis: number;
}

// Database configuration from environment config
const dbConfig: DatabaseConfig = {
  host: config.database.host,
  port: config.database.port,
  database: config.database.database,
  user: config.database.user,
  password: config.database.password,
  ssl: config.database.ssl,
  max: config.database.pool.max,
  min: config.database.pool.min,
  idleTimeoutMillis: config.database.pool.idleTimeoutMillis,
  connectionTimeoutMillis: config.database.pool.connectionTimeoutMillis,
  query_timeout: config.database.pool.queryTimeoutMillis,
  statement_timeout: config.database.pool.statementTimeoutMillis,
};

// Create the connection pool
export const pool = new Pool(dbConfig);

// Pool event handlers for monitoring and logging
pool.on('connect', (client: PoolClient) => {
  logger.debug('Database client connected', {
    totalCount: pool.totalCount,
    idleCount: pool.idleCount,
    waitingCount: pool.waitingCount
  });
});

pool.on('acquire', (client: PoolClient) => {
  logger.debug('Database client acquired from pool', {
    totalCount: pool.totalCount,
    idleCount: pool.idleCount,
    waitingCount: pool.waitingCount
  });
});

pool.on('remove', (client: PoolClient) => {
  logger.debug('Database client removed from pool', {
    totalCount: pool.totalCount,
    idleCount: pool.idleCount,
    waitingCount: pool.waitingCount
  });
});

pool.on('error', (err: Error, client?: PoolClient) => {
  logger.error('Unexpected database pool error', {
    error: err.message,
    stack: err.stack
  });
  
  // Don't exit the application on pool errors
  // The pool will automatically try to reconnect
});

// Database connection health check
export async function checkDatabaseConnection(): Promise<boolean> {
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    logger.info('Database connection healthy');
    return true;
  } catch (error) {
    logger.error('Database connection failed', { error: (error as Error).message });
    return false;
  }
}

// Database query helper with automatic connection handling
export async function query(
  text: string,
  params?: any[],
  timeoutMs?: number
): Promise<any> {
  const start = Date.now();
  const client = await pool.connect();
  
  try {
    // Set query timeout if specified
    if (timeoutMs) {
      await client.query(`SET statement_timeout = ${timeoutMs}`);
    }
    
    const result = await client.query(text, params);
    const duration = Date.now() - start;
    
    logger.debug('Database query executed', {
      query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
      params: params?.length || 0,
      duration: `${duration}ms`,
      rowCount: result.rowCount
    });
    
    return result;
  } catch (error) {
    const duration = Date.now() - start;
    logger.error('Database query failed', {
      query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
      params: params?.length || 0,
      duration: `${duration}ms`,
      error: (error as Error).message
    });
    throw error;
  } finally {
    client.release();
  }
}

// Transaction helper
export async function transaction<T>(
  callback: (client: PoolClient) => Promise<T>
): Promise<T> {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    logger.debug('Database transaction started');
    
    const result = await callback(client);
    
    await client.query('COMMIT');
    logger.debug('Database transaction committed');
    
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    logger.debug('Database transaction rolled back', { 
      error: (error as Error).message 
    });
    throw error;
  } finally {
    client.release();
  }
}

// Run database migrations
export async function runMigrations(): Promise<void> {
  const migrationsDir = path.join(__dirname, '../../migrations');
  
  try {
    // Create migrations tracking table if it doesn't exist
    await query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version VARCHAR(255) PRIMARY KEY,
        applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);
    
    // Get list of applied migrations
    const appliedMigrations = await query(
      'SELECT version FROM schema_migrations ORDER BY version'
    );
    const appliedVersions = new Set(
      appliedMigrations.rows.map((row: any) => row.version)
    );
    
    // Get list of migration files
    const migrationFiles = fs
      .readdirSync(migrationsDir)
      .filter(file => file.endsWith('.sql'))
      .sort();
    
    logger.info(`Found ${migrationFiles.length} migration files`);
    
    // Run unapplied migrations
    for (const file of migrationFiles) {
      const version = path.basename(file, '.sql');
      
      if (!appliedVersions.has(version)) {
        logger.info(`Applying migration: ${file}`);
        
        const migrationPath = path.join(migrationsDir, file);
        const migrationSql = fs.readFileSync(migrationPath, 'utf8');
        
        await transaction(async (client) => {
          await client.query(migrationSql);
          await client.query(
            'INSERT INTO schema_migrations (version) VALUES ($1)',
            [version]
          );
        });
        
        logger.info(`Migration ${file} applied successfully`);
      }
    }
    
    logger.info('All migrations completed');
  } catch (error) {
    logger.error('Migration failed', { error: (error as Error).message });
    throw error;
  }
}

// Get database pool statistics
export function getPoolStats() {
  return {
    totalCount: pool.totalCount,
    idleCount: pool.idleCount,
    waitingCount: pool.waitingCount
  };
}

// Graceful shutdown
export async function closeDatabaseConnection(): Promise<void> {
  try {
    await pool.end();
    logger.info('Database connection pool closed');
  } catch (error) {
    logger.error('Error closing database connection pool', {
      error: (error as Error).message
    });
    throw error;
  }
}

// Initialize database connection and run migrations
export async function initializeDatabase(): Promise<void> {
  try {
    logger.info('Initializing database connection...', dbConfig);
    
    // Test the connection
    const isHealthy = await checkDatabaseConnection();
    if (!isHealthy) {
      throw new Error('Database connection health check failed');
    }
    
    // Run migrations if in development or if explicitly requested
    if (process.env.NODE_ENV === 'development' || process.env.RUN_MIGRATIONS === 'true') {
      await runMigrations();
    }
    
    logger.info('Database initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize database', {
      error: (error as Error).message,
      stack: (error as Error).stack
    });
    throw error;
  }
}