const { validationResult } = require('express-validator');
const authService = require('../services/auth.service');
const { AppError } = require('../middleware/error.middleware');

class AuthController {
    async register(req, res, next) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    succes: false,
                    message: 'Validation errors',
                    errors: errors.array()
                });
            }

            const result = await authService.register(req.body);

            res.status(201).json({
                succes: true,
                message: 'User registered successfully',
                ...result
            });
        } catch (error) {
            next(new AppError(error.message, 400));
        }
    }

    async login(req, res, next) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation errors',
                    errors: errors.array()
                });
            }

            const { email, password } = req.body;
            const ipAddress = req.ip;
            const userAgent = req.get('User-Agent');

            const result = await authService.login(email, password, ipAddress, userAgent);

            res.json({
                success: true,
                message: 'Login successful',
                ...result
            })
        } catch (error) {
            next(new AppError(error.message, 401));
        }
    }

    async refreshToken(req, res, next) {
        try {
            const { refreshToken } = req.body;

            if (!refreshToken) {
                return next(new AppError('Refresh token is required', 400));
            }

            const result = await authService.refreshToken(refreshToken);

            res.json({
                success: true,
                messahe: 'Token refreshed successfully',
                ...result
            });
        } catch (error) {
            next(new AppError(error.message, 401));
        }
    }

    async logout(req, res, next) {
        try {
            const token = req.headers.authorization?.split(' ')[1];

            await authService.logout(token);

            res.json({
                success: true,
                message: 'Logged out successfully'
            });
        } catch (error) {
            next(new AppError(error.message, 500));
        }
    }

    async forgotPassword(req, res, next) {
        try {
            const { email } = req.body;

            if (!email) {
                return next(new AppError('Email is required', 400))
            }

            await authService.forgotPassword(email);

            res.json({
                success: true,
                message: 'Password reset email sent'
            });
        } catch (error) {
            next(new AppError(error.message, 400));
        }
    }

    async resetPassword(req, res, next) {
        try {
            const { token, password } = req.body;

            if (!token || !password) {
                return next(new AppError('Token and password are required', 400));
            }

            await authService.resetPassword(token, password);

            res.json({
                success: true,
                message: 'Password reset successful'
            });
        } catch (error) {
            next(new AppError(error.message, 400));
        }
    }

    async verifyEmail(req, res, next) {
        try {
            const { token } = req.body;

            if (!token) {
                return next(new AppError('Verification token is required', 400));
            }

            await authService.verifyEmail(token);

            res.json({
                success: true,
                message: 'Email verified successfully'
            });
        } catch (error) {
            next(new AppError(error.message, 400));
        }
    }
}

module.exports = new AuthController();