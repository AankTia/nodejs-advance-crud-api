const express = require('express');
const productController = require('../controllers/product.controller');
const { authenticate, authorize } = require('../middleware/auth.middleware');
const {
    createProductValidator,
    updateProductValidator,
    getProductValidator
} = require('../validators/product.validator');
const cacheService = require('../utils/cache');

const router = express.Router();

// Pubolic routes
router.get('/', getProductValidator, cacheService.middleware(300), productController.getProducts);
router.get('/:id', cacheService.middleware(600), productController.getProduct);
router.get('/slug/:slug', cacheService.middleware(600), productController.getProductBySlug);

// Protected routes (require authentication)
router.use(authenticate);

router.post('/', createProductValidator, productController.createProduct);
router.put('/:id', updateProductValidator, productController.updateProduct);
router.delete('/:id', productController.deleteProduct);

// Review routes
router.post('/:id/reviews', productController.addReview);
router.put('/:id/reviews/:reviewId', productController.updateReview);
router.delete('/:id/reviews/:reviewId', productController.deleteReview);

// Admin only routes
router.patch('/:id/status', authorize('admin'), productController.updateProductStatus);
router.get('/admin/analytics', authorize('admin'), productController.getProductAnalytics);

module.exports = router;