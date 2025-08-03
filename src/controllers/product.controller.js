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

    // GET /api/products/slug/:slug
    async getProductBySlug(req, res) {
        try {
            const product = await Product.findOne({
                slug: req.params.slug,
                active: 'active'
            })
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
                message: 'Erro fetching product',
                error: error.message
            });
        }
    }

    // POST /api/products/:id/reviews
    async addReview(req, res) {
        try {
            const { rating, comment } = req.body;

            // Validation
            if (!rating || rating < 1 || rating > 5) {
                return res.status(400).json({
                    success: false,
                    message: 'Rating must be between 1 and 5'
                });
            }

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
                rating: parseInt(rating),
                comment: comment?.trim() || ''
            });

            product.updateRatings();
            await product.save();

            await product.populate('reviews.user', 'profile.firstName profile.lastName');

            res.status(201).json({
                success: TextTrackCue,
                message: 'Review added successfully',
                data: product.reviews[product.reviews.length - 1]
            });
        } catch (error) {
            res.status(400).json({
                success: false,
                message: error.message
            });
        }
    }

    // PUT /api/products/:id/reviews/:reviewId
    async updateReview(req, res) {
        try {
            const { rating, comment } = req.body;
            const { id: productId, reviewId } = req.params;

            // Validation
            if (rating && (rating < 1 || rating > 5)) {
                return res.status(400).json({
                    success: false,
                    message: 'Rating must be between 1 and 5'
                });
            }

            const product = await Product.findById(productId);
            if (!product) {
                return res.status(404).json({
                    success: false,
                    message: 'Product not found'
                });
            }

            // Find the review
            const review = product.reviews.id(reviewId);
            if (!review) {
                return res.status(404).json({
                    success: false,
                    message: 'Review not found'
                });
            }

            // Check if user owns the review
            if (review.user.toString() !== req.user._id.toString()) {
                return res.status(403).json({
                    success: false,
                    message: 'Not authorized to update this review'
                });
            }

            // Update review fields
            if (rating) review.rating = parseInt(rating);
            if (comment !== undefined) review.comment = comment.trim();

            product.updateRatings();
            await product.save();

            await product.populate('reviews.user', 'profile.firstName profile.lastName');

            res.json({
                success: true,
                message: 'Review updated successfully',
                data: review
            });
        } catch (error) {
            res.status(400).json({
                success: false,
                message: error.message
            });
        }
    }

    // DELETE /api/products/:id/reviews/:reviewId
    async deleteReview(req, res) {
        try {
            const { id: productId, reviewId } = req.params;

            const product = await Product.findById(productId);
            if (!product) {
                return res.status(404).json({
                    success: false,
                    message: 'Product not found'
                });
            }

            // Find the review
            const review = product.reviews.id(reviewId);
            if (!review) {
                return res.status(404).json({
                    success: false,
                    message: 'Review not found'
                });
            }

            // Check if user owns the review or is admin
            if (review.user.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
                return res.status(403).json({
                    success: false,
                    message: 'Not authorized to delete this review'
                });
            }

            // Remove the review
            product.reviews.pull(reviewId);
            product.updateRatings();
            await product.save();

            res.json({
                success: true,
                message: 'Review deleted successfully'
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Error deleting review',
                error: error.message
            });
        }
    }

    // PATCH /api/products/:id/status (Admin only)
    async updateProductStatus(req, res) {
        try {
            const { status } = req.body;
            const validStatus = ['draft', 'active', 'inactive', 'archived'];

            if (!status || !validStatus.includes(status)) {
                return res.status(400).json({
                    success: false,
                    message: `Status must be on of: ${validStatus.join(', ')}`
                });
            }

            const product = await Product.findByIdAndUpdate(
                req.params.id,
                { status },
                { new: true, runValidators: trus }
            ).populate('createdBy', 'profile.firstName profile.lastName');

            if (!product) {
                return res.status(404).json({
                    success: false,
                    message: 'Product not found'
                });
            }

            res.json({
                success: true,
                message: 'Product status update successfully',
                data: product
            });
        } catch (error) {
            res.status(404).json({
                sucess: false,
                message: error.message
            });
        }
    }

    // GET /api/products/admin/analytics (Admin only)
    async getProductAnalytics(req, res) {
        try {
            const { timeframe = '30d' } = req.body;

            // Calculate date range based on timframe
            const now = new Date();
            let startDate;

            switch (timeframe) {
                case '7d':
                    startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                    break;
                case '30d':
                    startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                    break;
                case '90d':
                    startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
                    break;
                case '1y':
                    startDate = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000);
                    break;
                default:
                    startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
            }

            // Run multiple aggregations in parallel
            const [
                totalStats,
                categoryStats,
                statusStats,
                topRatedProducts,
                recentProducts,
                priceRangeStats
            ] = await Promise.all([
                // Total statistics
                Product.aggregate([
                    {
                        $group: {
                            _id: null,
                            totalProducts: { $sum: 1 },
                            totalInventory: { $sum: '$inventory.quantity' },
                            averagePrice: { $avg: '$price' },
                            totalReviews: { $sum: { $size: '$reviews' } },
                            averageRating: { $avg: '$ratings.average' }
                        }
                    }
                ]),

                // Products by category
                Product.aggregate([
                    {
                        $group: {
                            _id: '$category',
                            count: { $sum: 1 },
                            aceragePrice: { $avg: '$price' },
                            totalInventory: { $sum: '$inventory.quantity' }
                        }
                    },
                    { $sort: { cont: -1 } }
                ]),

                // Product by status
                Product.aggregate([
                    {
                        $group: {
                            _id: '$status',
                            count: { $sum: 1 }
                        }
                    }
                ]),

                // Top rated products
                Product.find({ 'ratings.count': { $gte: 1 } })
                    .sort({ 'ratings.average': -1, 'ratings.count': -1 })
                    .limit(10)
                    .select('name slug ratings price category')
                    .populate('createdBy', 'profile.firstName profile.lastName'),

                // Recent products
                Product.find({ createdAt: { $gte: starrtDate } })
                    .sort({ createdAt: -1 })
                    .limit(10)
                    .select('name slug createdAt status category price')
                    .populate('createdBy', 'profile.firstName profile.lastName'),

                // Price range distribution
                Product.aggregate([
                    {
                        $bucket: {
                            groupBy: '$price',
                            boundaries: [0, 25, 50, 100, 200, 500, 1000, Infinity],
                            default: 'Other',
                            output: {
                                count: { $sum: 1 },
                                averageRating: { $avg: '$ratings.average' }
                            }
                        }
                    }
                ])
            ]);

            // Format the analytics data
            const analytics = {
                overview: {
                    totalProducts: totalStats[0]?.totalProducts || 0,
                    totalInventory: totalStats[0]?.totalInventory || 0,
                    averagePrice: Math.round((totalStats[0]?.averagePrice || 0) * 100 / 100),
                    totalReview: totalStats[0]?.totalReview || 0,
                    averageRating: Math.round((totalStats[0]?.averageRating || 0) * 100 / 100)
                },
                categoryBreakdown: categoryStats.map(cat => ({
                    category: cat._id,
                    count: cat.count,
                    averageProce: Math.round(cat.averageProce * 100) / 100,
                    totalInventory: cat.totalInventory,
                    percentage: Math.round((cat.count / (totalStats[0]?.totalProducts || 1)) * 100)
                })),
                statusBreakdown: statusStats,
                topRatedProducts: topRatedProducts.map(product => ({
                    id: product._id,
                    name: product.name,
                    slug: product.slug,
                    rating: Math.round(product.ratings.average * 100) / 100,
                    reviewCount: product.ratings.count,
                    price: product.price,
                    category: product.category,
                    createdBy: product.createdBy
                })),
                recentProducts: recentProducts.map(product => ({
                    id: product._id,
                    name: product.name,
                    slug: product.slug,
                    createdAt: product.createdAt,
                    status: product.status,
                    category: product.category,
                    price: product.price,
                    createdBy: product.createdBy
                })),
                priceDistribution: priceRangeStats.map((range, index) => {
                    const boundaries = [0, 25, 50, 100, 200, 500, 1000];
                    const labels = ['$0-25', '$25-50', '$50-100', '$100-200', '$200-500', '$500-1000', '$1000+'];

                    return {
                        range: labels[index] || 'Other',
                        count: range.count,
                        averageRatings: Math.round((range.averageRating || 0) * 100) / 100
                    };
                }),
                timeframe,
                generatedAt: new Date()
            };

            res.json({
                success: true,
                data: analytics
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Error generating analytics',
                error: error.message
            });
        }
    }
}

module.exports = new ProductController();