const redis = require('redis');
const client = redis.createClient({
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
    password: process.env.REDISP_PASSWORD
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

                if(cachedData) {
                    return res.json(cachedData);
                }

                // Store original json method
                const originalJson = res.json;

                // Overide json method to cache response
                res.json = function(data) {
                    // Cache successful responses only
                    if(res.statusCode === 200 && data.success) {
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