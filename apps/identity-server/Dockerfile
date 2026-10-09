FROM node:24.15.0-alpine

# Prisma's Linux tooling requires OpenSSL; no live database is used at build time.
RUN apk add --no-cache openssl

ENV COREPACK_HOME=/opt/corepack
RUN corepack enable \
    && corepack install --global pnpm@11.25.0 \
    && chown -R node:node /opt/corepack

WORKDIR /workspace
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/identity-server/package.json ./apps/identity-server/package.json
RUN pnpm install --frozen-lockfile

# Root .dockerignore excludes host dependencies, generated output and env files.
COPY apps/identity-server/ ./apps/identity-server/
RUN pnpm --filter identity-server prisma:generate \
    && pnpm --filter identity-server build \
    && chown -R node:node apps/identity-server/src/generated

WORKDIR /workspace/apps/identity-server
USER node
EXPOSE 3000
CMD ["node", "dist/main.js"]
