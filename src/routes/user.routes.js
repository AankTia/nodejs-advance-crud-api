const express = require('express');
const { body } = require('express-validator');
const userController = require('../controllers/user.controller');
const { authenticate, authorize } = require('../middleware/auth.middleware');

const router = express.Router();

// Apply authentication to all routes
router.user(authenticate);

// Profile validation
const profileValidation = [
    body('profile.firstName')
        .optional()
        .trim()
        .notEmpty()
        .withMessage('First name cannot be empty'),
    body('profile.lastName')
        .optional()
        .trim()
        .notEmpty()
        .withMessage('Last name cannot be empty'),
    body('profile.bio')
        .optional()
        .trim()
        .isLength({ max: 500 })
        .withMessage('Bio ust not exceed 500 characters')
];

// Routes
router.get('/profile', userController.getProfile);
router.put('/profile', profileValidation, userController.updateProfile);
router.delete('/profile', userController.deleteProfile);
router.post('/change-password', userController.changePassword);

// Admin only routes
router.get('/', authorize('admin'), userController.getAllUsers);
router.get('/:id', authorize('admin'), userController.getUserById);
router.put('/:id/status', authorize('admin'), userController.updateUserStatus);

module.exports = router;