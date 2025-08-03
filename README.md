# Advanced Node.js CRUD API Tutorial

This comprehensive tutorial covers building a production-ready Node.js CRUD API with advanced features including authentication, validation, error handling, logging, testing, and deployment strategies.

## Table of Contents
1. [Project Setup](#project-setup)
2. [Database Design & Models](#database-design--models)
3. [Authentication & Authorization](#authentication--authorization)
4. [Advanced CRUD Operations](#advanced-crud-operations)
5. [Validation & Error Handling](#validation--error-handling)
6. [Middleware & Security](#middleware--security)
7. [Testing Strategy](#testing-strategy)
8. [Performance Optimization](#performance-optimization)
9. [Deployment & DevOps](#deployment--devops)

## Project Setup

### Initialize Project Structure
```bash
mkdir advanced-node-crud-api
cd advanced-node-crud-api
npm init -y

# Install dependencies
npm install express mongoose bcryptjs jsonwebtoken joi helmet cors morgan compression dotenv express-rate-limit
npm install -D nodemon jest supertest eslint prettier
```

### Project Structure
```
src/
├── config/
│   ├── database.js
│   ├── redis.js
│   └── config.js
├── controllers/
│   ├── auth.controller.js
│   ├── user.controller.js
│   └── product.controller.js
├── middleware/
│   ├── auth.middleware.js
│   ├── validation.middleware.js
│   ├── error.middleware.js
│   └── rate-limit.middleware.js
├── models/
│   ├── User.js
│   ├── Product.js
│   └── AuditLog.js
├── routes/
│   ├── auth.routes.js
│   ├── user.routes.js
│   └── product.routes.js
├── services/
│   ├── auth.service.js
│   ├── user.service.js
│   ├── product.service.js
│   └── email.service.js
├── utils/
│   ├── logger.js
│   ├── cache.js
│   └── helpers.js
├── validators/
│   ├── auth.validator.js
│   └── product.validator.js
└── tests/
    ├── unit/
    └── integration/
```

## Database Design & Models

### User Model with Advanced Features
```javascript
// src/models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    index: true
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    select: false // Don't include in queries by default
  },
  profile: {
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    avatar: { type: String },
    bio: { type: String, maxlength: 500 }
  },
  role: {
    type: String,
    enum: ['user', 'admin', 'moderator'],
    default: 'user'
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'suspended'],
    default: 'active'
  },
  emailVerified: { type: Boolean, default: false },
  emailVerificationToken: String,
  passwordResetToken: String,
  passwordResetExpires: Date,
  lastLogin: Date,
  loginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: String
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for full name
userSchema.virtual('profile.fullName').get(function() {
  return `${this.profile.firstName} ${this.profile.lastName}`;
});

// Index for text search
userSchema.index({
  'profile.firstName': 'text',
  'profile.lastName': 'text',
  email: 'text'
});

// Pre-save middleware for password hashing
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Instance method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Instance method to check if account is locked
userSchema.methods.isLocked = function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

// Static method to handle failed login attempts
userSchema.methods.incLoginAttempts = function() {
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { loginAttempts: 1, lockUntil: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = {
      lockUntil: Date.now() + 2 * 60 * 60 * 1000 // Lock for 2 hours
    };
  }
  
  return this.updateOne(updates);
};

module.exports = mongoose.model('User', userSchema);
```

### Product Model with Advanced Features
```javascript
// src/models/Product.js
const mongoose = require('mongoose');

const reviewSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
  comment: { type: String, maxlength: 1000 },
  helpful: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
}, { timestamps: true });

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  slug: {
    type: String,
    unique: true,
    lowercase: true
  },
  description: {
    type: String,
    required: true,
    maxlength: 2000
  },
  price: {
    type: Number,
    required: true,
    min: 0
  },
  comparePrice: {
    type: Number,
    min: 0
  },
  category: {
    type: String,
    required: true,
    enum: ['electronics', 'clothing', 'books', 'home', 'sports']
  },
  tags: [String],
  images: [{
    url: String,
    alt: String,
    isPrimary: { type: Boolean, default: false }
  }],
  inventory: {
    quantity: { type: Number, required: true, min: 0 },
    sku: { type: String, unique: true, required: true },
    trackQuantity: { type: Boolean, default: true }
  },
  seo: {
    metaTitle: String,
    metaDescription: String,
    keywords: [String]
  },
  status: {
    type: String,
    enum: ['draft', 'active', 'inactive', 'archived'],
    default: 'draft'
  },
  featured: { type: Boolean, default: false },
  reviews: [reviewSchema],
  ratings: {
    average: { type: Number, default: 0 },
    count: { type: Number, default: 0 }
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
productSchema.index({ name: 'text', description: 'text', tags: 'text' });
productSchema.index({ category: 1, status: 1 });
productSchema.index({ price: 1 });
productSchema.index({ 'ratings.average': -1 });
productSchema.index({ createdAt: -1 });

// Virtual for discount percentage
productSchema.virtual('discountPercentage').get(function() {
  if (this.comparePrice && this.comparePrice > this.price) {
    return Math.round(((this.comparePrice - this.price) / this.comparePrice) * 100);
  }
  return 0;
});

// Pre-save middleware to generate slug
productSchema.pre('save', function(next) {
  if (this.isModified('name')) {
    this.slug = this.name
      .toLowerCase()
      .replace(/[^a-zA-Z0-9]/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '');
  }
  next();
});

// Method to update ratings
productSchema.methods.updateRatings = function() {
  if (this.reviews.length > 0) {
    const totalRating = this.reviews.reduce((sum, review) => sum + review.rating, 0);
    this.ratings.average = totalRating / this.reviews.length;
    this.ratings.count = this.reviews.length;
  } else {
    this.ratings.average = 0;
    this.ratings.count = 0;
  }
};

module.exports = mongoose.model('Product', productSchema);
```

## Authentication & Authorization

### Advanced Authentication Service
```javascript
// src/services/auth.service.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const { promisify } = require('util');

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

    // Send verification email (implement email service)
    // await emailService.sendVerificationEmail(user.email, emailVerificationToken);

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

  // Login user
  async login(email, password, ipAddress, userAgent) {
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) {
      throw new Error('Invalid credentials');
    }

    if (user.isLocked()) {
      throw new Error('Account temporarily locked due to too many failed login attempts');
    }

    const isValidPassword = await user.comparePassword(password);
    
    if (!isValidPassword) {
      await user.incLoginAttempts();
      throw new Error('Invalid credentials');
    }

    if (user.loginAttempts > 0) {
      await user.updateOne({
        $unset: { loginAttempts: 1, lockUntil: 1 },
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
```

### Authentication Middleware
```javascript
// src/middleware/auth.middleware.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const authService = require('../services/auth.service');

const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Access token required'
      });
    }

    const token = authHeader.split(' ')[1];
    
    // Check if token is blacklisted (implement Redis check)
    // const isBlacklisted = await redisClient.get(`blacklist_${token}`);
    // if (isBlacklisted) {
    //   return res.status(401).json({
    //     success: false,
    //     message: 'Token is invalid'
    //   });
    // }

    const decoded = await authService.verifyToken(token, process.env.JWT_ACCESS_SECRET);
    
    if (decoded.type !== 'access') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token type'
      });
    }

    const user = await User.findById(decoded.userId);
    
    if (!user || user.status !== 'active') {
      return res.status(401).json({
        success: false,
        message: 'User not found or inactive'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions'
      });
    }

    next();
  };
};

module.exports = { authenticate, authorize };
```

## Advanced CRUD Operations

### Product Controller with Advanced Features
```javascript
// src/controllers/product.controller.js
const Product = require('../models/Product');
const productService = require('../services/product.service');
const { validationResult } = require('express-validator');

class ProductController {
  // GET /api/products - Advanced filtering, sorting, pagination
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
        if (minPrice) filter.price.$gte = parseFloat(minPrice);
        if (maxPrice) filter.price.$lte = parseFloat(maxPrice);
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
          message: 'Product not found'
        });
      }

      // Check if user owns the product or is admin
      if (product.createdBy.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
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
        status: 'active' 
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
        message: 'Error fetching product',
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
        success: true,
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
      const validStatuses = ['draft', 'active', 'inactive', 'archived'];

      if (!status || !validStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          message: `Status must be one of: ${validStatuses.join(', ')}`
        });
      }

      const product = await Product.findByIdAndUpdate(
        req.params.id,
        { status },
        { new: true, runValidators: true }
      ).populate('createdBy', 'profile.firstName profile.lastName');

      if (!product) {
        return res.status(404).json({
          success: false,
          message: 'Product not found'
        });
      }

      res.json({
        success: true,
        message: 'Product status updated successfully',
        data: product
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        message: error.message
      });
    }
  }

  // GET /api/products/admin/analytics (Admin only)
  async getProductAnalytics(req, res) {
    try {
      const { timeframe = '30d' } = req.query;
      
      // Calculate date range based on timeframe
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
              averagePrice: { $avg: '$price' },
              totalInventory: { $sum: '$inventory.quantity' }
            }
          },
          { $sort: { count: -1 } }
        ]),

        // Products by status
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
        Product.find({ createdAt: { $gte: startDate } })
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
          averagePrice: Math.round((totalStats[0]?.averagePrice || 0) * 100) / 100,
          totalReviews: totalStats[0]?.totalReviews || 0,
          averageRating: Math.round((totalStats[0]?.averageRating || 0) * 100) / 100
        },
        categoryBreakdown: categoryStats.map(cat => ({
          category: cat._id,
          count: cat.count,
          averagePrice: Math.round(cat.averagePrice * 100) / 100,
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
            averageRating: Math.round((range.averageRating || 0) * 100) / 100
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
```

## Validation & Error Handling

### Advanced Validation Middleware
```javascript
// src/validators/product.validator.js
const { body, query } = require('express-validator');

const createProductValidator = [
  body('name')
    .trim()
    .notEmpty()
    .withMessage('Product name is required')
    .isLength({ max: 200 })
    .withMessage('Product name must not exceed 200 characters'),
    
  body('description')
    .trim()
    .notEmpty()
    .withMessage('Product description is required')
    .isLength({ max: 2000 })
    .withMessage('Description must not exceed 2000 characters'),
    
  body('price')
    .isFloat({ min: 0 })
    .withMessage('Price must be a positive number'),
    
  body('comparePrice')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Compare price must be a positive number')
    .custom((value, { req }) => {
      if (value && value <= req.body.price) {
        throw new Error('Compare price must be greater than regular price');
      }
      return true;
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
    .withMessage('Tags must be an array'),
    
  body('tags.*')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Each tag must be between 1 and 50 characters')
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
    .withMessage('Price must be a positive number'),
    
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
    .isIn(['name', '-name', 'price', '-price', 'createdAt', '-createdAt', 'ratings.average', '-ratings.average'])
    .withMessage('Invalid sort parameter')
];

module.exports = {
  createProductValidator,
  updateProductValidator,
  getProductsValidator,
  reviewValidator,
  updateReviewValidator
};
```

### Global Error Handler
```javascript
// src/middleware/error.middleware.js
const logger = require('../utils/logger');

class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

const handleCastErrorDB = (err) => {
  const message = `Invalid ${err.path}: ${err.value}`;
  return new AppError(message, 400);
};

const handleDuplicateFieldsDB = (err) => {
  const value = err.errmsg.match(/(["'])(\\?.)*?\1/)[0];
  const message = `Duplicate field value: ${value}. Please use another value!`;
  return new AppError(message, 400);
};

const handleValidationErrorDB = (err) => {
  const errors = Object.values(err.errors).map(el => el.message);
  const message = `Invalid input data. ${errors.join('. ')}`;
  return new AppError(message, 400);
};

const handleJWTError = () =>
  new AppError('Invalid token. Please log in again!', 401);

const handleJWTExpiredError = () =>
  new AppError('Your token has expired! Please log in again.', 401);

const sendErrorDev = (err, res) => {
  res.status(err.statusCode).json({
    success: false,
    error: err,
    message: err.message,
    stack: err.stack
  });
};

const sendErrorProd = (err, res) => {
  // Operational, trusted error: send message to client
  if (err.isOperational) {
    res.status(err.statusCode).json({
      success: false,
      message: err.message
    });
  } else {
    // Programming or other unknown error: don't leak error details
    logger.error('ERROR 💥', err);
    
    res.status(500).json({
      success: false,
      message: 'Something went wrong!'
    });
  }
};

const globalErrorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(err, res);
  } else {
    let error = { ...err };
    error.message = err.message;

    if (error.name === 'CastError') error = handleCastErrorDB(error);
    if (error.code === 11000) error = handleDuplicateFieldsDB(error);
    if (error.name === 'ValidationError') error = handleValidationErrorDB(error);
    if (error.name === 'JsonWebTokenError') error = handleJWTError();
    if (error.name === 'TokenExpiredError') error = handleJWTExpiredError();

    sendErrorProd(error, res);
  }
};

module.exports = { AppError, globalErrorHandler };
```

## Testing Strategy

### Unit Tests Example
```javascript
// src/tests/unit/auth.service.test.js
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

      User.findOne.mockResolvedValue(null);
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

    it('should throw error if user already exists', async () => {
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
        comparePassword: jest.fn().mockResolvedValue(true),
        loginAttempts: 0,
        updateOne: jest.fn().mockResolvedValue(),
        profile: { firstName: 'John', lastName: 'Doe' },
        role: 'user',
        emailVerified: true
      };

      User.findOne.mockReturnValue({
        select: jest.fn().mockResolvedValue(mockUser)
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
```

### Integration Tests Example
```javascript
// src/tests/integration/product.test.js
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
    await clearDB();
    
    // Create test user and get auth token
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
        .expect(201);

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
        .get('/api/products?category=electronics')
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
```

## Performance Optimization

### Caching Strategy
```javascript
// src/utils/cache.js
const redis = require('redis');
const client = redis.createClient({
  host: process.env.REDIS_HOST || 'localhost',
  port: process.env.REDIS_PORT || 6379,
  password: process.env.REDIS_PASSWORD
});

client.on('error', (err) => {
  console.error('Redis Client Error:', err);
});

class CacheService {
  async get(key) {
    try {
      const data = await client.get(key);
      return data ? JSON.parse(data) : null;
    } catch (error) {
      console.error('Cache get error:', error);
      return null;
    }
  }

  async set(key, data, expireInSeconds = 3600) {
    try {
      await client.setex(key, expireInSeconds, JSON.stringify(data));
      return true;
    } catch (error) {
      console.error('Cache set error:', error);
      return false;
    }
  }

  async del(key) {
    try {
      await client.del(key);
      return true;
    } catch (error) {
      console.error('Cache delete error:', error);
      return false;
    }
  }

  async flush() {
    try {
      await client.flushall();
      return true;
    } catch (error) {
      console.error('Cache flush error:', error);
      return false;
    }
  }

  // Cache middleware
  middleware(expireInSeconds = 3600) {
    return async (req, res, next) => {
      const key = `cache:${req.originalUrl || req.url}`;
      
      try {
        const cachedData = await this.get(key);
        
        if (cachedData) {
          return res.json(cachedData);
        }

        // Store original json method
        const originalJson = res.json;
        
        // Override json method to cache response
        res.json = function(data) {
          // Cache successful responses only
          if (res.statusCode === 200 && data.success) {
            CacheService.set(key, data, expireInSeconds);
          }
          
          // Call original json method
          originalJson.call(this, data);
        };

        next();
      } catch (error) {
        console.error('Cache middleware error:', error);
        next();
      }
    };
  }
}

module.exports = new CacheService();
```

### Database Optimization Middleware
```javascript
// src/middleware/optimization.middleware.js
const compression = require('compression');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');

// Compression middleware
const compressionMiddleware = compression({
  level: 6,
  threshold: 1024, // Only compress responses > 1KB
  filter: (req, res) => {
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  }
});

// Security middleware
const securityMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});

// Rate limiting
const rateLimitMiddleware = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: 'Too many requests from this IP, please try again later.'
    });
  }
});

// Strict rate limiting for auth endpoints
const authRateLimitMiddleware = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs for auth
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later.'
  }
});

// MongoDB injection prevention
const mongoSanitizeMiddleware = mongoSanitize({
  replaceWith: '_'
});

module.exports = {
  compressionMiddleware,
  securityMiddleware,
  rateLimitMiddleware,
  authRateLimitMiddleware,
  mongoSanitizeMiddleware
};
```

## Logging & Monitoring

### Advanced Logger
```javascript
// src/utils/logger.js
const winston = require('winston');
const path = require('path');

// Custom format for logs
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.prettyPrint()
);

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { service: 'crud-api' },
  transports: [
    // Error logs
    new winston.transports.File({
      filename: path.join(__dirname, '../logs/error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    
    // Combined logs
    new winston.transports.File({
      filename: path.join(__dirname, '../logs/combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    
    // Console transport for development
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Request logging middleware
const requestLogger = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id || 'anonymous'
    };
    
    if (res.statusCode >= 400) {
      logger.error('HTTP Request Error', logData);
    } else {
      logger.info('HTTP Request', logData);
    }
  });
  
  next();
};

// Error logging middleware
const errorLogger = (err, req, res, next) => {
  logger.error('Application Error', {
    error: err.message,
    stack: err.stack,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userId: req.user?.id || 'anonymous'
  });
  
  next(err);
};

module.exports = {
  logger,
  requestLogger,
  errorLogger
};
```

## Main Application Setup

### Express App Configuration
```javascript
// src/app.js
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

// Import middleware
const { requestLogger, errorLogger } = require('./utils/logger');
const { globalErrorHandler } = require('./middleware/error.middleware');
const {
  compressionMiddleware,
  securityMiddleware,
  rateLimitMiddleware,
  mongoSanitizeMiddleware
} = require('./middleware/optimization.middleware');

// Import routes
const authRoutes = require('./routes/auth.routes');
const userRoutes = require('./routes/user.routes');
const productRoutes = require('./routes/product.routes');

const app = express();

// Trust proxy (for rate limiting and IP detection)
app.set('trust proxy', 1);

// Security middleware
app.use(securityMiddleware);
app.use(compressionMiddleware);
app.use(rateLimitMiddleware);

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// MongoDB injection prevention
app.use(mongoSanitizeMiddleware);

// Request logging
app.use(requestLogger);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    success: true,
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/products', productRoutes);

// 404 handler
app.all('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`
  });
});

// Error logging middleware
app.use(errorLogger);

// Global error handler
app.use(globalErrorHandler);

module.exports = app;
```

## Route Files Implementation

Here are the missing route files that need to be created:

### Authentication Routes
```javascript
// src/routes/auth.routes.js
const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/auth.controller');
const { authenticate } = require('../middleware/auth.middleware');
const { authRateLimitMiddleware } = require('../middleware/optimization.middleware');

const router = express.Router();

// Registration validation
const registerValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number and one special character'),
  body('profile.firstName')
    .trim()
    .notEmpty()
    .withMessage('First name is required'),
  body('profile.lastName')
    .trim()
    .notEmpty()
    .withMessage('Last name is required')
];

// Login validation
const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

// Routes
router.post('/register', authRateLimitMiddleware, registerValidation, authController.register);
router.post('/login', authRateLimitMiddleware, loginValidation, authController.login);
router.post('/refresh', authController.refreshToken);
router.post('/logout', authenticate, authController.logout);
router.post('/forgot-password', authRateLimitMiddleware, authController.forgotPassword);
router.post('/reset-password', authRateLimitMiddleware, authController.resetPassword);
router.post('/verify-email', authController.verifyEmail);

module.exports = router;
```

### User Routes
```javascript
// src/routes/user.routes.js
const express = require('express');
const { body } = require('express-validator');
const userController = require('../controllers/user.controller');
const { authenticate, authorize } = require('../middleware/auth.middleware');

const router = express.Router();

// Apply authentication to all routes
router.use(authenticate);

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
    .withMessage('Bio must not exceed 500 characters')
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
```

### Product Routes
```javascript
// src/routes/product.routes.js
const express = require('express');
const productController = require('../controllers/product.controller');
const { authenticate, authorize } = require('../middleware/auth.middleware');
const { 
  createProductValidator, 
  updateProductValidator, 
  getProductsValidator,
  reviewValidator,
  updateReviewValidator
} = require('../validators/product.validator');
const cacheService = require('../utils/cache');

const router = express.Router();

// Public routes
router.get('/', getProductsValidator, cacheService.middleware(300), productController.getProducts);
router.get('/:id', cacheService.middleware(600), productController.getProduct);
router.get('/slug/:slug', cacheService.middleware(600), productController.getProductBySlug);

// Protected routes (require authentication)
router.use(authenticate);

router.post('/', createProductValidator, productController.createProduct);
router.put('/:id', updateProductValidator, productController.updateProduct);
router.delete('/:id', productController.deleteProduct);

// Review routes
router.post('/:id/reviews', reviewValidator, productController.addReview);
router.put('/:id/reviews/:reviewId', updateReviewValidator, productController.updateReview);
router.delete('/:id/reviews/:reviewId', productController.deleteReview);

// Admin only routes
router.patch('/:id/status', authorize('admin'), productController.updateProductStatus);
router.get('/admin/analytics', authorize('admin'), productController.getProductAnalytics);

module.exports = router;
```

## Controller Files Implementation

### Authentication Controller
```javascript
// src/controllers/auth.controller.js
const { validationResult } = require('express-validator');
const authService = require('../services/auth.service');
const { AppError } = require('../middleware/error.middleware');

class AuthController {
  async register(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation errors',
          errors: errors.array()
        });
      }

      const result = await authService.register(req.body);

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        ...result
      });
    } catch (error) {
      next(new AppError(error.message, 400));
    }
  }

  async login(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation errors',
          errors: errors.array()
        });
      }

      const { email, password } = req.body;
      const ipAddress = req.ip;
      const userAgent = req.get('User-Agent');

      const result = await authService.login(email, password, ipAddress, userAgent);

      res.json({
        success: true,
        message: 'Login successful',
        ...result
      });
    } catch (error) {
      next(new AppError(error.message, 401));
    }
  }

  async refreshToken(req, res, next) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return next(new AppError('Refresh token is required', 400));
      }

      const result = await authService.refreshToken(refreshToken);

      res.json({
        success: true,
        message: 'Token refreshed successfully',
        ...result
      });
    } catch (error) {
      next(new AppError(error.message, 401));
    }
  }

  async logout(req, res, next) {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      
      await authService.logout(token);

      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (error) {
      next(new AppError(error.message, 500));
    }
  }

  async forgotPassword(req, res, next) {
    try {
      const { email } = req.body;
      
      if (!email) {
        return next(new AppError('Email is required', 400));
      }

      await authService.forgotPassword(email);

      res.json({
        success: true,
        message: 'Password reset email sent'
      });
    } catch (error) {
      next(new AppError(error.message, 400));
    }
  }

  async resetPassword(req, res, next) {
    try {
      const { token, password } = req.body;

      if (!token || !password) {
        return next(new AppError('Token and password are required', 400));
      }

      await authService.resetPassword(token, password);

      res.json({
        success: true,
        message: 'Password reset successful'
      });
    } catch (error) {
      next(new AppError(error.message, 400));
    }
  }

  async verifyEmail(req, res, next) {
    try {
      const { token } = req.body;

      if (!token) {
        return next(new AppError('Verification token is required', 400));
      }

      await authService.verifyEmail(token);

      res.json({
        success: true,
        message: 'Email verified successfully'
      });
    } catch (error) {
      next(new AppError(error.message, 400));
    }
  }
}

module.exports = new AuthController();
```

### User Controller
```javascript
// src/controllers/user.controller.js
const { validationResult } = require('express-validator');
const userService = require('../services/user.service');
const { AppError } = require('../middleware/error.middleware');

class UserController {
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
      next(new AppError(error.message, 400));
    }
  }

  async changePassword(req, res, next) {
    try {
      const { currentPassword, newPassword } = req.body;

      if (!currentPassword || !newPassword) {
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

module.exports = new UserController();
```

## Service Files Implementation

### User Service
```javascript
// src/services/user.service.js
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
      { new: true, runValidators: true }
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
```

### Product Service
```javascript
// src/services/product.service.js
const Product = require('../models/Product');

class ProductService {
  async createProduct(productData) {
    const product = new Product(productData);
    await product.save();
    
    await product.populate('createdBy', 'profile.firstName profile.lastName');
    
    return product;
  }

  async updateProduct(productId, updateData) {
    const product = await Product.findByIdAndUpdate(
      productId,
      { $set: updateData },
      { new: true, runValidators: true }
    ).populate('createdBy', 'profile.firstName profile.lastName');

    if (!product) {
      throw new Error('Product not found');
    }

    return product;
  }

  async deleteProduct(productId) {
    const product = await Product.findByIdAndDelete(productId);
    
    if (!product) {
      throw new Error('Product not found');
    }

    return { message: 'Product deleted successfully' };
  }

  async updateProductStatus(productId, status) {
    const product = await Product.findByIdAndUpdate(
      productId,
      { status },
      { new: true, runValidators: true }
    );

    if (!product) {
      throw new Error('Product not found');
    }

    return product;
  }
}

module.exports = new ProductService();
```

### Server Entry Point
```javascript
// src/server.js
const app = require('./app');
const mongoose = require('mongoose');
const { logger } = require('./utils/logger');

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/crud-api';

// Database connection
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    logger.info(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    logger.error('Database connection error:', error);
    process.exit(1);
  }
};

// Graceful shutdown
const gracefulShutdown = (signal) => {
  logger.info(`Received ${signal}. Shutting down gracefully...`);
  
  server.close(() => {
    logger.info('HTTP server closed.');
    
    mongoose.connection.close(false, () => {
      logger.info('MongoDB connection closed.');
      process.exit(0);
    });
  });
  
  // Force close after 10 seconds
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

// Handle unhandled promise rejections
process.on('unhandledRejection', (err, promise) => {
  logger.error('Unhandled Promise Rejection:', err);
  server.close(() => {
    process.exit(1);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', err);
  process.exit(1);
});

// Graceful shutdown handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start server
const startServer = async () => {
  await connectDB();
  
  const server = app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
  });
  
  global.server = server;
};

startServer();
```

## Deployment & DevOps

### Docker Configuration
```dockerfile
# Dockerfile
FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy app source
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodeuser -u 1001

# Create logs directory
RUN mkdir -p logs && chown -R nodeuser:nodejs logs

USER nodeuser

EXPOSE 3000

CMD ["node", "src/server.js"]
```

### Docker Compose for Development
```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
      - MONGODB_URI=mongodb://mongo:27017/crud-api
      - REDIS_HOST=redis
    volumes:
      - ./src:/usr/src/app/src
      - ./logs:/usr/src/app/logs
    depends_on:
      - mongo
      - redis
    command: npm run dev

  mongo:
    image: mongo:5.0
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db
    environment:
      - MONGO_INITDB_DATABASE=crud-api

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  mongo_data:
  redis_data:
```

### Package.json Scripts
```json
{
  "name": "advanced-node-crud-api",
  "version": "1.0.0",
  "scripts": {
    "start": "node src/server.js",
    "dev": "nodemon src/server.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "lint": "eslint . --ext .js",
    "lint:fix": "eslint . --ext .js --fix",
    "format": "prettier --write .",
    "build:docker": "docker build -t crud-api .",
    "docker:dev": "docker-compose -f docker-compose.dev.yml up",
    "docker:prod": "docker-compose up"
  },
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^7.5.0",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "joi": "^17.9.2",
    "helmet": "^7.0.0",
    "cors": "^2.8.5",
    "morgan": "^1.10.0",
    "compression": "^1.7.4",
    "dotenv": "^16.3.1",
    "express-rate-limit": "^6.10.0",
    "express-mongo-sanitize": "^2.2.0",
    "winston": "^3.10.0",
    "express-validator": "^7.0.1",
    "redis": "^4.6.7"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "jest": "^29.6.2",
    "supertest": "^6.3.3",
    "eslint": "^8.47.0",
    "prettier": "^3.0.2"
  }
}
```

### Environment Variables Template
```bash
# .env.example
NODE_ENV=development
PORT=3000

# Database
MONGODB_URI=mongodb://localhost:27017/crud-api

# JWT
JWT_ACCESS_SECRET=your-super-secret-jwt-access-key
JWT_REFRESH_SECRET=your-super-secret-jwt-refresh-key
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Email (optional)
EMAIL_FROM=noreply@yourapp.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# Security
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001

# Logging
LOG_LEVEL=info
```

## Best Practices Summary

### Security Checklist
- ✅ Input validation and sanitization
- ✅ SQL/NoSQL injection prevention
- ✅ Rate limiting
- ✅ CORS configuration
- ✅ Helmet for security headers
- ✅ JWT token security
- ✅ Password hashing with bcrypt
- ✅ Account lockout mechanism
- ✅ Error message sanitization

### Performance Optimization
- ✅ Database indexing
- ✅ Query optimization
- ✅ Caching with Redis
- ✅ Response compression
- ✅ Pagination
- ✅ Connection pooling

### Code Quality
- ✅ ESLint configuration
- ✅ Prettier formatting
- ✅ Unit testing
- ✅ Integration testing
- ✅ Error handling
- ✅ Logging
- ✅ Code organization

### Production Readiness
- ✅ Environment configuration
- ✅ Docker containerization
- ✅ Health check endpoints
- ✅ Graceful shutdown
- ✅ Process monitoring
- ✅ Logging and monitoring

This tutorial provides a solid foundation for building production-ready Node.js CRUD APIs with advanced features and best practices.