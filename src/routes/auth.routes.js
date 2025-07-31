const express = require('express');
const { body } = require('express-validator')
const authController = require('../controllers/auth.controller');
const { authenticate } = require('../middleware/auth.middleware');
const { authRateLimitMiddleware } = require('../middleware/optimization.middleware');

const router = express.Router();

// Register validation
const registerValidation = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Please provide a valid email'),
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .withMessage('Password must contai at least one uppercase letter, one lowercase letter, one number and one special character'),
    body('profile.firstName')
        .trim()
        .notEmpty()
        .withMessage('First name is required'),
    body('profile.lastName')
        .trim()
        .notEmpty()
        .withMessage('Last name is required')
];

// Login validation
const loginValidation = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Please provide a valid email'),
    body('password')
        .notEmpty()
        .withMessage('Password is required')
];

// Routes
router.post('/register', authRateLimitMiddleware, registerValidation, authController.register);
router.post('/login', authRateLimitMiddleware, loginValidation, authController.login);
router.post('/refresh', authController.refreshToken);
router.post('/logout', authenticate, authController.logout);
router.post('/forgot-password', authRateLimitMiddleware, authController.forgotPassword);
router.post('/reset-password', authRateLimitMiddleware, authController.resetPassword);
router.post('/verify-email', authController.verifyEmail);

module.exports = router;