const jwt = require("jsonwebtoken");
const crypto = require('crypto');
const User = require("../models/User");
const { promisify } = require('util');
const { token } = require("morgan");

// const = jwt = require
class AuthService {
    // Generate JWT tokens
    generateTokens(userId) {
        const accessToken = jwt.sign(
            { userId, type: 'access' },
            process.env.JWT_ACCESS_SECRET,
            { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m' }
        );

        const refreshToken = jwt.sign(
            { userId, type: 'refresh' },
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
        );

        return { accessToken, refreshToken };
    }

    // Verify JWT token
    async verifyToken(token, secret) {
        try {
            const decoded = await promisify(jwt.verify)(token, secret);
            return decoded;
        } catch (error) {
            throw new Error('Invalid token');
        }
    }

    // Register new user
    async register(userData) {
        const existingUser = await User.findOne({ email: userData.email });
        if (existingUser) {
            throw new Error('User already exists with this email');
        }

        const emailVerificationToken = crypto.randomBytes(32).toString('hex');

        const user = new User({
            ...userData,
            emailVerificationToken
        });

        await user.save();

        // send verification email (implement email service)
        // await emailService.sendVerificationEmail(user.email, emailVerificationToken)

        const tokens = this.generateTokens(user._id);

        return {
            user: {
                id: user._id,
                email: user.email,
                profile: user.profile,
                role: user.role,
                emailVerivied: user.emailVerified
            },
            ...tokens
        };
    }

    // Login user
    async login(email, password, ipAddress, userAgent) {
        const user = await User.findOne({ email }).select('+password');

        if (!user) {
            throw new Error('Invalid credebtials');
        }

        if (user.isLocked()) {
            throw new Error('Account temporary locked due too many failed login attempts');
        }

        const isValidPassword = await user.comparePassword(password);

        if (!isValidPassword) {
            await user.incLoginAttempts();
            throw new Error('Invalid creadentials');
        }

        if (user.loginAttemps > 0) {
            await user.updateOne({
                $unset: { loginAttemps: 1, lockUntil: 1 },
                $set: { lastLogin: new Date() }
            });
        } else {
            await user.updateOne({ lastLogin: new Date() });
        }

        const tokens = this.generateTokens(user._id);

        return {
            user: {
                id: user._id,
                email: user.email,
                profile: user.profile,
                role: user.role,
                emailVerified: user.emailVerified
            },
            ...tokens
        };
    }

    // Refresh access token
    async refreshToken(refreshToken) {
        const decoded = await this.verifyToken(refreshToken, process.env.JWT_REFRESH_SECRET);

        if (decoded.type !== 'refresh') {
            throw new Error('Invalid token type');
        }

        const user = await User.findById(decoded.userId);
        if (!user || user.status !== 'active') {
            throw new Error('User not found or inactive');
        }

        const tokens = this.generateTokens(user._id);
        return tokens;
    }

    // Logout (blacklist token - implement Redis for token blacklisting)
    async logout(token) {
        // Add token to blacklist in Redis
        // await redisClient.setex(`blacklist_${token}`, 900, 'true');
        return { message: 'Logged out successfully' };
    }
}

module.exports = new AuthService();