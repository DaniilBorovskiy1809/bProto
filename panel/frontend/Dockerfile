# Builds the panel's static bundle. The result is copied into a shared volume
# by the `frontend` service in docker-compose.yml; Caddy serves it from /srv.
FROM node:20-alpine AS build
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json vite.config.ts index.html ./
COPY src ./src
RUN pnpm build

FROM alpine:3.20
COPY --from=build /app/dist /app/dist
