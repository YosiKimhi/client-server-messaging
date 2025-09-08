import dotenv from 'dotenv';
import { logger } from './utils/logger';
import { initializeDatabase } from './config/database';

// Load environment variables
dotenv.config();

const PORT = parseInt(process.env.PORT || '3001', 10);
const HOST = process.env.HOST || 'localhost';

async function startServer() {
  try {
    logger.info('Starting server initialization...');
    
    // Initialize database connection and run migrations
    await initializeDatabase();
    
    // Basic HTTP server for Hour 0-4 (Express app will be added in Hour 4-8)
    const http = require('http');
    const server = http.createServer((req: any, res: any) => {
      if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'healthy',
          timestamp: new Date().toISOString(),
          message: 'Server is running - Hour 0-4 setup complete'
        }));
      } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Route not found',
          message: 'Server setup complete. Authentication routes will be added in Hour 4-8.'
        }));
      }
    });
    
    server.listen(PORT, HOST, () => {
      logger.info(`Server running on http://${HOST}:${PORT}`);
      logger.info('Hour 0-4: Project Setup & Database - COMPLETE');
      logger.info('Ready for Hour 4-8: Authentication System');
    });
    
    // Graceful shutdown
    process.on('SIGTERM', () => {
      logger.info('SIGTERM received, shutting down gracefully');
      server.close(() => {
        process.exit(0);
      });
    });
    
    process.on('SIGINT', () => {
      logger.info('SIGINT received, shutting down gracefully');
      server.close(() => {
        process.exit(0);
      });
    });
    
  } catch (error) {
    logger.error('Failed to start server', {
      error: (error as Error).message,
      stack: (error as Error).stack
    });
    process.exit(1);
  }
}

// Start the server
startServer().catch((error) => {
  logger.error('Server startup failed', { error: error.message });
  process.exit(1);
});