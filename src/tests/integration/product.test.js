const request = require('supertest');
const app = require('../../app');
const User = require('../../models/User');
const Product = require('../../models/Product');
const { connectDB, closeDB, clearDB } = require('../helpers/db');

describe('Product API', () => {
    let authToken;
    let userId;
    let productId;

    beforeAll(async () => {
        await connectDB();
    });

    afterAll(async () => {
        await closeDB();
    });

    beforeEach(async () => {
        await clearDB;

        // Create test user and get auth tooken
        const userData = {
            email: 'test@example.com',
            password: 'password123',
            profile: {
                firstName: 'John',
                lastName: 'Doe'
            }
        };

        const registerResponse = await request(app)
            .post('/api/auth/register')
            .send(userData);

        authToken = registerResponse.body.accessToken;
        userId = registerResponse.body.user.id;
    });

    describe('POST /api/products', () => {
        it('should create a new product', async () => {
            const productData = {
                name: 'Test Product',
                description: 'This is a test product',
                price: 99.99,
                category: 'electronics',
                inventory: {
                    quantity: 10,
                    sku: 'TEST-001'
                }
            };

            const response = await request(app)
                .post('/api/products')
                .set('Authorization', `Bearer ${authToken}`)
                .send(productData)
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data).toHaveProperty('name', productData.name);
            expect(response.body.data).toHaveProperty('slug', 'test-product');

            productId = response.body.data._id;
        });

        it('should return validation error for invalid data', async () => {
            const invalidData = {
                name: '',
                price: -10
            };

            const response = await request(app)
                .post('/api/products')
                .set('Authorization', `Bearer ${authToken}`)
                .send(invalidData)
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body).toHaveProperty('errors');
        });

        it('should return 401 without auth token', async () => {
            const productData = {
                name: 'Test Product',
                description: 'This is a test product',
                price: 99.99
            };

            await request(app)
                .post('/api/products')
                .send(productData)
                .expect(401);
        });
    });

    describe('GET /api/products', () => {
        beforeEach(async () => {
            // Create test products
            const products = [
                {
                    name: 'Product 1',
                    description: 'Description 1',
                    price: 50,
                    category: 'electronics',
                    inventory: { quantity: 5, sku: 'PROD-001' },
                    createdBy: userId,
                    status: 'active'
                },
                {
                    name: 'Product 2',
                    description: 'Description 2',
                    price: 100,
                    category: 'clothing',
                    inventory: { quantity: 10, sku: 'PROD-002' },
                    createdBy: userId,
                    status: 'active'
                }
            ];

            await Product.insertMany(products);
        });

        it('should get all products with pagination', async () => {
            const response = await request(app)
                .get('/api/products')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data).toHaveLength(2);
            expect(response.body).toHaveProperty('pagination');
            expect(response.body.pagination.totalItems).toBe(2);
        });

        it('should filter products by category', async () => {
            const response = await request(app)
                .get('api/products?category=electronics')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data).toHaveLength(1);
            expect(response.body.data[0].category).toBe('electronics');
        });

        it('should filter products by price range', async () => {
            const response = await request(app)
                .get('/api/products?minPrice=60&maxPrice=150')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data).toHaveLength(1);
            expect(response.body.data[0].price).toBe(100);
        });
    });
});