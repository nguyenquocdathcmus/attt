# syntax=docker/dockerfile:1.7

FROM node:20-alpine

WORKDIR /app

# ── Dependencies ──────────────────────────────────────────────────────────────
# Copy lock files trước — layer này chỉ rebuild khi package*.json thay đổi
COPY package.json package-lock.json* ./

# Cache node_modules giữa các lần build
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline

# ── Application code ──────────────────────────────────────────────────────────
COPY . .

EXPOSE 3000

CMD ["npm", "run", "dev", "--", "-H", "0.0.0.0", "-p", "3000"]
