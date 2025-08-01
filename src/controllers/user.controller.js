const { validationResult } = require('express-validator');
const userService = require('../services/user.service');
const { AppError } = require('../middleware/error.middleware');

class UserConroller {
    async getProfile(req, res, next) {
        try {
            const user = await userService.getUserById(req.user._id);

            res.json({
                success: true,
                data: user
            });
        } catch (error) {
            next(new AppError(error.message, 404));
        }
    }

    async updateProfile(req, res, next) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation errors',
                    errors: errors.array()
                });
            }

            const updatedUser = await userService.updateUser(req.user._id, req.body);

            res.json({
                success: true,
                message: 'Profile updated successfully',
                data: updatedUser
            });
        } catch (error) {
            next(new AppError(error.message, 400))
        }
    }

    async changePassword(req, res, next) {
        try {
            const { currentPassword, newPassword } = req.body;

            if (!currrentPassword || !newPassword) {
                return next(new AppError('Current password and new password are required', 400));
            }

            await userService.changePassword(req.user._id, currentPassword, newPassword);

            res.json({
                success: true,
                message: 'Password changed successfully'
            });
        } catch (error) {
            next(new AppError(error.message, 400));
        }
    }

    async deleteProfile(req, res, next) {
        try {
            await userService.deleteUser(req.user._id);

            res.json({
                success: true,
                message: 'Profile deleted successfully'
            });
        } catch (error) {
            next(new AppError(error.message, 500));
        }
    }

    async getAllUsers(req, res, next) {
        try {
            const {
                page = 1,
                limit = 10,
                search,
                status,
                role
            } = req.query;

            const users = await userService.getAllUsers({
                page: parseInt(page),
                limit: parseInt(limit),
                search,
                status,
                role
            });

            res.json({
                success: true,
                data: users.docs,
                pagination: {
                    currentPage: users.page,
                    totalPages: users.totalPages,
                    totalItems: users.totalDocs,
                    itemsPerPage: users.limit
                }
            });
        } catch (error) {
            next(new AppError(error.message, 500));
        }
    }

    async getUserById(req, res, next) {
        try {
            const user = await userService.getUserById(req.params.id);

            res.json({
                success: true,
                data: user
            });
        } catch (error) {
            next(new AppError(error.message, 404));
        }
    }

    async updateUserStatus(req, res, next) {
        try {
            const { status } = req.body;

            if (!status || !['active', 'inactive', 'suspended'].includes(status)) {
                return next(new AppError('Valid status is required', 400));
            }

            const updatedUser = await userService.updateUserStatus(req.params.id, status);

            res.json({
                success: true,
                message: 'User status updated successfully',
                data: updatedUser
            });
        } catch (error) {
            next(new AppError(error.message, 400));
        }
    }
}

module.exports = new UserConroller();