const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

// Import middleware
const { requestLogger, errorLogger } = require('./utils/logger');
const { globalErrorHandler } = require('./middleware/error.middleware');
const {
    compressionMiddleware,
    securityMiddleware,
    rateLimitMiddleware,
    mongoSanitizeMiddleware
} = require('./middleware/optimization.middleware');

// Import routes
const authRoutes = require('./routes/auth.routes');
const userRoutes = require('./routes/user.routes');
const productRoutes = require('./routes/product.routes');

const app = express();

// Trust proxy (for rate limiting and IP detection)
app.set('trust proxy', 1);

// Security middleware
app.use(securityMiddleware);
app.use(compressionMiddleware);
app.use(rateLimitMiddleware);

// CORS configuratin
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// MongoDB injection prevention
app.use(mongoSanitizeMiddleware);

// Request logging
app.use(requestLogger);

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        success: true,
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users/', userRoutes);
app.user('/api/products', productRoutes);

// 404 handler
app.all('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: `Route ${req.originalUrl} not found`
    });
});

// Error logging middleware
app.use(errorLogger);

// Global error handler
app.use(globalErrorHandler);

module.exports = app;