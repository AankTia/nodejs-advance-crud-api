const { body, query } = require('express-validator');

const createProductValidator = [
    body('name')
        .trim()
        .notEmpty()
        .withMessage('Product name is required')
        .isLength({ max: 200 })
        .withMessage('Product name mus not exceed 200 characters'),

    body('description')
        .trim()
        .notEmpty()
        .withMessage('Product description is required')
        .isLength({ max: 2000 })
        .withMessage('Description must not be exceed 2000 characters'),

    body('price')
        .isFloat({ min: 0 })
        .withMessage('Price must be a positive number'),

    body('comparePrice')
        .optional()
        .isFloat({ min: 0 })
        .withMessage('Compare price must be a positive number')
        .custom((value, { req }) => {
            if (value && value <= req.body.price) {
                throw new Error('COmpare price must be greater than regular price');
            }
            return true
        }),

    body('category')
        .isIn(['electronics', 'clothing', 'books', 'home', 'sports'])
        .withMessage('Invalid category'),

    body('inventory.quantity')
        .isInt({ min: 0 })
        .withMessage('Quantity must be a non-negative integer'),

    body('inventory.sku')
        .trim()
        .notEmpty()
        .withMessage('SKU is required')
        .matches(/^[A-Z0-9-]+$/)
        .withMessage('SKU must contain only uppercase letters, numbers, and hyphens'),

    body('tags')
        .optional()
        .isArray()
        .withMessage('Tags mus be an array'),

    body('tags.*')
        .optional()
        .trim()
        .isLength({ min: 1, max: 50 })
        .withMessage('Each tag mus be between 1 and 50 characters')
];

const reviewValidator = [
    body('rating')
        .isInt({ min: 1, max: 5 })
        .withMessage('Rating must be an integer between 1 and 5'),
    body('comment')
        .optional()
        .trim()
        .isLength({ max: 1000 })
        .withMessage('Comment must not exceed 1000 characters')
];

const updateReviewValidator = [
    body('rating')
        .optional()
        .isInt({ min: 1, max: 5 })
        .withMessage('Rating must be an integer between 1 and 5'),
    body('comment')
        .optional()
        .trim()
        .isLength({ max: 1000 })
        .withMessage('Comment must not exceed 1000 characters')
];

const updateProductValidator = [
    body('name')
        .optional()
        .trim()
        .notEmpty()
        .withMessage('Product name cannot be empty')
        .isLength({ max: 200 })
        .withMessage('Product name must not exceed 200 characters'),

    body('price')
        .optional()
        .isFloat({ min: 0 })
        .withMessage('Proe must be a positive number'),

    // Add other validation rules as needed
];

const getProductsValidator = [
    query('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Page must be a positive integer'),

    query('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('Limit must be between 1 and 100'),

    query('minPrice')
        .optional()
        .isFloat({ min: 0 })
        .withMessage('Minimum price must be non-negative'),

    query('maxPrice')
        .optional()
        .isFloat({ min: 0 })
        .withMessage('Maximum price must be non-negative'),

    query('category')
        .optional()
        .isIn(['electronics', 'clothing', 'books', 'home', 'sports'])
        .withMessage('Invalid category'),

    query('sort')
        .optional()
        .isIn('name', '-name', 'price', '-price', 'createdAt', '-createdAt', 'ratings.average', '-ratings.average')
        .withMessage('Invalid sort parameter')
];

module.exports = {
    createProductValidator,
    updateProductValidator,
    getProductsValidator,
    reviewValidator,
    updateReviewValidator
};