const User = require('../models/User');
const bcrypt = require('bcryptjs');

class UserService {
    async getUserById(userId) {
        const user = await User.findById(userId).select('-password');

        if (!user) {
            throw new Error('User not found');
        }

        return user;
    }

    async updateUser(userId, updateData) {
        const user = await User.findByIdAndUpdate(
            userId,
            { $set: updateData },
            { $new: true, runValidators: true }
        ).select('-password');

        if (!user) {
            throw new Error('User not found');
        }

        return user;
    }

    async changePassword(userId, currentPassword, newPassword) {
        const user = await User.findById(userId).select('+password');

        if (!user) {
            throw new Error('User not found');
        }

        const isCurrentPasswordValid = await user.comparePassword(currentPassword);

        if (!isCurrentPasswordValid) {
            throw new Error('Current password is incorrect');
        }

        user.password = newPassword;
        await user.save();

        return { message: 'Password changed successfully' };
    }

    async deleteUser(userId) {
        const user = await User.findByIdAndDelete(userId);

        if (!user) {
            throw new Error('User not found');
        }

        return { message: 'User deleted successfully' };
    }

    async getAllUsers(options) {
        const { page, limit, search, status, role } = options;

        const filter = {};

        if (search) {
            filter.$text = { $search: search };
        }

        if (status) {
            filter.status = status;
        }

        if (role) {
            filter.role = role;
        }

        const paginateOptions = {
            page,
            limit,
            select: '-password',
            sort: { createdAt: -1 }
        };

        return await User.paginate(filter, paginateOptions);
    }

    async updateUserStatus(userId, status) {
        const user = await User.findByIdAndUpdate(
            userId,
            { status },
            { new: true, runValidators: true }
        ).select('-password');

        if (!user) {
            throw new Error('User not found');
        }

        return user;
    }
}

module.exports = new UserService();