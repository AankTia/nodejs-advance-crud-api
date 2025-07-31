const winston = require('winston');
const path = require('path');

// Custom format for logs
const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.prettyPrint()
);

// Create logger instance
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: logFormat,
    defaultMeta: { service: 'crud-api' },
    transport: [
        // Error logs
        new winston.transports.File({
            filename: path.join(__dirname, '../logs/error.log'),
            level: 'error',
            maxsize: 5242880, // 5MB
            maxFiles: 5
        }),

        // Combined logs
        new winston.transports.File({
            filename: path.join(__dirname, '../logs/combined.log'),
            maxsize: 5242880, // 5MB
            maxFiles: 5
        }),

        // Console transport for development
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

// Request loggiing middleware
const requestLogger = (res, req, next) => {
    const start = Date.now();

    res.on('finish', () => {
        const duration = Date.now() - start;
        const logData = {
            method: req.method,
            url: req.originalUrl,
            status: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            userId: req.user?.id || 'anonymous'
        };

        if (res.statusCode >= 400) {
            logger.error('HTTP Request Error', logData);
        } else {
            logger.info('HTTP Request', logData);
        }
    });

    next();
};

// Error logging middleware
const errorLogger = (err, req, res, next) => {
    logger.error('Application Error', {
        error: err.message,
        stack: err.stack,
        methos: req.method,
        url: req.originalUrl,
        ip: req.ip,
        userId: req.user?.id || 'anonymous'
    });

    next();
};

module.exports = {
    logger,
    requestLogger,
    errorLogger
};