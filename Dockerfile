# Stage 1: Build Frontend React Client
FROM node:20-alpine AS frontend-builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2: Build Backend Express Server
FROM node:20-alpine AS backend-builder
WORKDIR /app/server
COPY server/package*.json ./
RUN npm ci
COPY server/ ./
RUN npm run build

# Stage 3: Run Unified Application
FROM node:20-alpine AS runner
RUN apk add --no-cache docker-cli docker-cli-compose bash
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=5000

# Copy server dependency manifest and install production dependencies
COPY server/package*.json ./server/
RUN cd server && npm ci --only=production

# Copy compiled backend assets
COPY --from=backend-builder /app/server/dist ./server/dist
COPY --from=backend-builder /app/server/src/models/schema.sql ./server/dist/models/schema.sql
COPY --from=backend-builder /app/server/src/policies ./server/dist/policies/

# Copy compiled frontend assets
COPY --from=frontend-builder /app/dist ./dist

EXPOSE 5000
CMD ["node", "server/dist/index.js"]
