const app = require('./app');
const mongoose = require('mongoose');
const { logger } = require('./utils/logger');

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/crud-api';

// Database connection
const connectDB = async () => {
    try {
        const conn = await mongoose.connect(MONGODB_URI);

        logger.info(`MongoDB connected: ${conn.connection.host}`);
    } catch (error) {
        logger.error('Database connection error:', error);
        process.exit(1);
    }
};

// Graceful shutdown
const gracefulShutdown = (signal) => {
    logger.info(`Received ${signal}. Shutting down gracefully...`);

    server.close(() => {
        logger.info('HTTP server closed.');

        mongoose.connection.close(false, () => {
            logger.info('MongoDB connection closed.');
            process.exit(0);
        });
    });

    // Force close after 10 seconds
    setTimeout(() => {
        logger.error('Could not close connection in time, forcefully shutting down');
        process.exit(1);
    }, 10000);
};

// Handle unhandled promise rejections
process.on('unhandledRejection', (err, promise) => {
    logger.error('Unhandled Promise Rejection:', err);
    server.close(() => {
        process.exit(1);
    });
});

// Handle uncaught exception
process.on('uncaughtException', (err) => {
    logger.error('Uncaugh Exception:', err);
    process.exit(1);
});

// Graceful shhutdown handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start server
const startServer = async () => {
    await connectDB();

    const server = app.listen(PORT, () => {
        logger.info(`Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
    });

    global.server = server;
};

startServer();