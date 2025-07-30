const jwt = require('jsonwebtoken');
const User = require('../models/User');
const authService = require('../services/auth.service');

const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(400).json({
                success: false,
                message: 'Access token required'
            });
        }

        const token = authHeader.split(' ')[1];

        // Check if token is blacklisted (implement Redis check)
        // const isBlacklisted = await redisClient.get(`blacklist_${token}`);
        // if (isBlacklisted) {
        //     return res.status(401).json({
        //         success: false,
        //         message: 'Token is invalid'
        //     });
        // }

        const decoded = await authService.verifyToken(token, process.env.JWT_ACCESS_SECRET);

        if (decoded.type !== 'access') {
            return res.status(401).json({
                success: false,
                message: 'Invalid token type'
            });
        }

        const user = await User.findById(decoded.userId);

        if (!user || user.status !== 'active') {
            return res.status(401).json({
                success: false,
                message: 'User not found or inactive'
            });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: 'Invalid or expired token'
        });
    }
};

const authorize = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: 'Insufficient permissions'
            });
        }

        next();
    };
};

module.exports = { authenticate, authorize };