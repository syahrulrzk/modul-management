# Use Node.js LTS version as base image
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application code
COPY . .

# Create directories that will be mounted as volumes
RUN mkdir -p uploads modules

# Expose port
EXPOSE 3000

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

# Change ownership of app directory
RUN chown -R nextjs:nodejs /app
# Set proper permissions for directories that will be mounted as volumes
RUN chown -R nextjs:nodejs /app/uploads /app/modules
USER nextjs

# Copy entrypoint script with executable permissions
COPY --chmod=755 entrypoint.sh /entrypoint.sh

# Use entrypoint script
ENTRYPOINT ["/entrypoint.sh"]