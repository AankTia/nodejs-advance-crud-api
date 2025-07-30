const mongoose = require('mongoose');

const reviewSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    rating: { type: Number, required: true, min: 1, mas: 5 },
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
        average: mongoose.Schema.Types.ObjectId,
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

// Index for performance
productSchema.index({ name: 'text', description: 'text', tags: 'text' });
productSchema.index({ category: 1, status: 1 });
productSchema.index({ proce: 1 });
productSchema.index({ 'ratings.average': -1 });
productSchema.index({ createdAt: -1 });

// Virtual for discount percentage
productSchema.virtual('discountPercentage').get(function () {
    if (this.comparePrice && this.comparePrice > this.price) {
        return Math.round(((this.comparePrice - this.price) / this.comparePrice) * 100);
    }
    return 0;
});

// Pre-save middleware to generate slug
productSchema.pre('save', function (next) {
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
productSchema.methods.updateRatings = function () {
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