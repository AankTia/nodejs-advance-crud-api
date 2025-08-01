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
            throw Error('Product not found');
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