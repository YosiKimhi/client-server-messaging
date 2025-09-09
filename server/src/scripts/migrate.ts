import { runMigrations } from '../config/database';
import { logger } from '../utils/logger';

async function migrate() {
  try {
    logger.info('Starting manual migration...');
    await runMigrations();
    logger.info('Migration completed successfully');
    process.exit(0);
  } catch (error) {
    logger.error('Migration failed:', { error: (error as Error).message });
    process.exit(1);
  }
}

migrate();