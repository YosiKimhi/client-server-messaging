import { initializeDatabase, closeDatabaseConnection, pool } from '../config/database';
import { logger } from '../utils/logger';

/**
 * Simple script to clear all messages from the database
 * Useful for starting fresh with new encryption keys
 */
async function clearMessages(): Promise<void> {
  try {
    logger.info('Clearing all messages from database...');
    
    // Initialize database connection
    await initializeDatabase();
    
    // Clear messages table
    const result = await pool.query('DELETE FROM messages');
    
    logger.info(`Cleared ${result.rowCount} messages from database`);
    logger.info('Messages cleared successfully!');
    
  } catch (error) {
    logger.error('Failed to clear messages', {
      error: (error as Error).message,
      stack: (error as Error).stack
    });
    throw error;
  } finally {
    await closeDatabaseConnection();
  }
}

// Run if this file is executed directly
if (require.main === module) {
  clearMessages()
    .then(() => {
      logger.info('Clear messages process completed');
      process.exit(0);
    })
    .catch((error) => {
      logger.error('Clear messages process failed', {
        error: error.message,
        stack: error.stack
      });
      process.exit(1);
    });
}

export { clearMessages };