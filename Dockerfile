# syntax=docker/dockerfile:1

FROM node:22-bookworm-slim AS builder
WORKDIR /app

COPY package.json package-lock.json* tsconfig.json ./
COPY packages/zk/package.json packages/zk/package.json
COPY packages/node/package.json packages/node/package.json
COPY packages/client/package.json packages/client/package.json

RUN if [ -f package-lock.json ]; then npm ci --ignore-scripts; else npm install --ignore-scripts; fi

COPY packages ./packages
RUN npm run typecheck

FROM node:22-bookworm-slim AS runtime
RUN groupadd --system --gid 1001 nuverther && \
    useradd --system --uid 1001 --gid nuverther --home /app --shell /usr/sbin/nologin nuverther

WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder --chown=nuverther:nuverther /app/node_modules ./node_modules
COPY --from=builder --chown=nuverther:nuverther /app/package.json ./package.json
COPY --from=builder --chown=nuverther:nuverther /app/tsconfig.json ./tsconfig.json
COPY --from=builder --chown=nuverther:nuverther /app/packages ./packages

USER nuverther

EXPOSE 3000 4100
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.NUVERTHER_PORT || process.env.PORT || 3000) + '/healthz').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

ENTRYPOINT ["npx", "tsx", "packages/node/src/cli.ts"]
