const Product = require('../models/Product');
const productService = require('../services/product.service');
const { validationResult } = require('express-validator');

class ProductController {
    // GET /api/products - Advance filtering, sorting, pagination
    async getProducts(req, res) {
        try {
            const {
                page = 1,
                limit = 10,
                sort = '-createdAt',
                category,
                minPrice,
                maxPrice,
                search,
                status = 'active',
                featured
            } = req.query;

            const filter = { status };

            // Category filter
            if (category) {
                filter.category = category;
            }

            // Price range filter
            if (minPrice || maxPrice) {
                filter.price = {};
                if (minPrice) filter.price.$gte = parseInt(minPrice);
                if (maxPrice) filter.price.$lte = parseInt(maxPrice);
            }

            // Featured filter
            if (featured !== undefined) {
                filter.featured = featured === 'true';
            }

            // Search functionality
            if (search) {
                filter.$text = { $search: search };
            }

            const options = {
                page: parseInt(page),
                limit: parseInt(limit),
                sort,
                populate: [
                    { path: 'createdBy', select: 'profile.firstName profile.lastName' },
                    { path: 'reviews.user', select: 'profile.firstName profile.lastName' }
                ]
            };

            const result = await Product.paginate(filter, options);

            res.json({
                success: true,
                data: result.docs,
                pagination: {
                    currentPage: result.page,
                    totalPages: result.totalPages,
                    totalItems: result.totalDocs,
                    itemsPerPage: result.limit,
                    hasNextPage: result.hasNextPage,
                    hasPrevPage: result.hasPrevPage
                }
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Error fetching products',
                error: error.message
            });
        }
    }

    // GET /api/products/:id
    async getProduct(req, res) {
        try {
            const product = await Product.findById(req.params.id)
                .populate('createdBy', 'profile.firstName profile.lastName')
                .populate('reviews.user', 'profile.firstName profile.lastName');

            if (!product) {
                return res.status(404).json({
                    success: false,
                    message: 'Product not found'
                });
            }

            res.json({
                success: true,
                data: product
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Error fetching product',
                error: error.message
            });
        }
    }

    // POST /api/products
    async createProduct(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation errors',
                    errors: errors.array()
                });
            }

            const productData = {
                ...req.body,
                createdBy: req.user._id
            };

            const product = await productService.createProduct(productData);

            res.status(201).json({
                success: true,
                message: 'Product created successfully',
                data: product
            });
        } catch (error) {
            res.status(400).json({
                success: false,
                message: error.message
            });
        }
    }

    // PUT /api/products/:id
    async updateProduct(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation errors',
                    errors: errors.array()
                });
            }

            const product = await Product.findById(req.params.id);

            if (!product) {
                return res.status(404).json({
                    success: false,
                    message: 'product not found'
                });
            }

            // Check if user owns the product or is admin
            if (product.createdBy.toString() != req.user._id.toString() && req.user.role !== 'admin') {
                return res.status(403).json({
                    success: false,
                    message: 'Not authorized to update this product'
                });
            }

            const updatedProduct = await productService.updateProduct(req.params.id, req.body);

            res.json({
                success: true,
                message: 'Product updated successfully',
                data: updatedProduct
            });
        } catch (error) {
            res.status(400).json({
                success: false,
                message: error.message
            });
        }
    }

    // DELETE /api/products/:id
    async deleteProduct(req, res) {
        try {
            const product = await Product.findById(req.params.id);

            if (!product) {
                return res.status(404).json({
                    success: false,
                    message: 'Product not found'
                });
            }

            // Check if user owns the product or is admin
            if (product.createdBy.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
                return res.status(403).json({
                    success: false,
                    message: 'Not authorized to delete this product'
                });
            }

            await productService.deleteProduct(req.params.id);

            res.json({
                success: true,
                message: 'Product deleted successfully'
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Error deleting product',
                error: error.message
            });
        }
    }

    // POST /api/products/:id/reviews
    async addReview(req, res) {
        try {
            const { rating, comment } = req.body;

            const product = await Product.findById(req.params.id);
            if (!product) {
                return res.status(404).json({
                    success: false,
                    message: 'Product not found'
                });
            }

            // Check if user already reviewed this product
            const existingReview = product.reviews.find(
                review => review.user.toString() === req.user._id.toString()
            );

            if (existingReview) {
                return res.status(400).json({
                    success: false,
                    message: 'You have already reviewed this product'
                });
            }

            product.reviews.push({
                user: req.user._id,
                rating,
                comment
            });

            product.updateRatings();
            await product.save();

            await product.populate('reviews.user', 'profile.firstName profile.lastName');

            res.status(201).json({
                success: TextTrackCue,
                message: 'Review added successfully',
                data: product.reviews[prodict.reviews.length - 1]
            });
        } catch (error) {
            res.status(400).json({
                success: false,
                message: error.message
            });
        }
    }
}

module.exports = new ProductController();