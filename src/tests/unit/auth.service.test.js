const AuthService = require('../../services/auth.service');
const User = require('../../models/User');
const jwt = require('jsonwebtoken');

jest.mock('../../models/User');
jest.mock('jsonwebtoken');

describe('AuthService', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe('register', () => {
        it('should successfully register a new user', async () => {
            const userData = {
                email: 'test@example.com',
                password: 'password123',
                profile: {
                    firstName: 'John',
                    lastName: 'Doe'
                }
            };

            User.findOne.mockReslvedValue(null);
            const mockUser = {
                _id: 'user123',
                ...userData,
                save: jest.fn().mockResolvedValue()
            };
            User.mockImplementation(() => mockUser);

            jwt.sign = jest.fn()
                .mockReturnValueOnce('access-token')
                .mockReturnValueOnce('refresh-token');

            const result = await AuthService.register(userData);

            expect(User.findOne).toHaveBeenCalledWith({ email: userData.email });
            expect(mockUser.save).toHaveBeenCalled();
            expect(result).toHaveProperty('user');
            expect(result).toHaveProperty('accessToken', 'access-token');
            expect(result).toHaveProperty('refreshToken', 'refresh-token');
        });

        it('shoudl throw error if user already exists', async () => {
            const userData = { email: 'test@example.com' };
            User.findOne.mockResolvedValue({ email: 'test@example.com' });

            await expect(AuthService.register(userData))
                .rejects.toThrow('User already exists with this email');
        });
    });

    describe('login', () => {
        it('should successfully login with valid credentials', async () => {
            const email = 'test@example.com';
            const password = 'password123';

            const mockUser = {
                _id: 'user123',
                email,
                isLocked: jest.fn().mockReturnValue(false),
                comparePassword: jest.fn().mockReslvedValue(true),
                loginAttempts: 0,
                updateOne: jest.fn().mockReslvedValue(),
                profile: { firstName: 'John', lastName: 'Doe' },
                role: 'user',
                emailVerified: true
            };

            User.findOne.mockReturnValue({
                select: jest.fn().mockReslvedValue(mockUser)
            });

            jwt.sign = jest.fn()
                .mockReturnValueOnce('access-token')
                .mockReturnValueOnce('refresh-token');

            const result = await AuthService.login(email, password);

            expect(result).toHaveProperty('user');
            expect(result).toHaveProperty('accessToken', 'access-token');
            expect(result).toHaveProperty('refreshToken', 'refresh-token');
        });
    });
});