# syntax=docker/dockerfile:1

# Production image for the CyberNorf console.
#
# One image is built and used twice in compose.prod.yaml: the `migrate` service
# runs `prisma migrate deploy` from it and the `app` service serves traffic with
# it. Sharing the image is deliberate: the schema and the code that expects that
# schema can never drift apart during a deploy.
#
# Dev dependencies stay installed because the Prisma CLI is one of them and it
# is what applies migrations. The trade-off is a larger image; a self-hosted
# console that serves a handful of operators does not benefit from splitting it.

FROM node:24-bookworm-slim AS base
ENV NEXT_TELEMETRY_DISABLED=1
ENV npm_config_update_notifier=false
WORKDIR /app

# Dependencies are installed once and reused by every later stage so the build
# does not repeat the slowest step.
FROM base AS deps
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM base AS builder
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# The build never touches a real secret: instrumentation.ts runs when the server
# starts, not during `next build`. The placeholders below only satisfy the
# config loaders, are scoped to this single RUN, and are not persisted in the
# image environment:
#   - BETTER_AUTH_SECRET: in case a prerendered page calls getAuthSecret().
#   - DATABASE_URL: `npm run build` starts with `prisma generate`, and
#     prisma.config.ts resolves the URL while loading. Generation reads the
#     schema only and never opens a connection.
RUN BETTER_AUTH_SECRET=build-only-placeholder-value-never-used-at-runtime \
    DATABASE_URL=postgresql://build:build@127.0.0.1:5432/cybernorf?schema=public \
    npm run build

FROM base AS runner
ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

COPY --from=deps /app/node_modules ./node_modules
COPY --from=builder /app/.next ./.next
# The Prisma client is generated into src/ at build time, so it has to travel
# with the build output that imports it.
COPY --from=builder /app/src/generated ./src/generated
COPY package.json package-lock.json next.config.ts prisma.config.ts tsconfig.json ./
COPY prisma ./prisma

# The image runs as the unprivileged `node` user that the base image provides.
USER node

EXPOSE 3000

# `next start` is the built server; no compilation happens in the container at
# runtime, so a read-only root filesystem works apart from /tmp and .next/cache.
CMD ["npx", "next", "start", "--port", "3000"]
