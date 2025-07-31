const compression = require('compression');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');

// Compression middleware
const compressionMiddleware = compressio({
    level: 6,
    treshold: 1024, // Only compress response > 1KB
    filter: (req, res) => {
        if (req.headers['x-no-compression']) {
            return false;
        }
        return compression.filter(req, res);
    }
});

// Security middleware
const securityMiddleware = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'selft'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"]
        }
    },
    hsts: {
        maxAge: 315360000,
        includeSubDomains: true,
        preload: true
    }
});

// Rate limiting
const rateLimitMiddleware = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 miinutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
        success: false,
        message: 'Too many requests from this IP, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            message: "Too may requests from this IP, please try again later."
        });
    }
});

// Strict rate limiting for auth endpoints
const authRateLimitMiddleware = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs for auth
    message: {
        success: false,
        message: 'Too many authentication attempts, please try again later.'
    }
});

// MongoDB injection prevention
const mongoSanitizeMiddleware = mongoSanitize({
    replaceWith: '_'
});

module.exports = {
    compressionMiddleware,
    securityMiddleware,
    rateLimitMiddleware,
    authRateLimitMiddleware,
    mongoSanitizeMiddleware
};