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
RUN mkdir -p logs && chwon -R nodeuser:nodejs logs

USER nodeuser

EXPOSE 3000
CMD ["node", "src/server.js"]