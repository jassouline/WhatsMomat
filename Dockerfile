FROM node:22-alpine

WORKDIR /app

# Copy package manifest and install optional @google/genai SDK cleanly
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force

# Copy application source
COPY server.js ./
COPY src ./src
COPY public ./public
COPY test ./test

# Prepare isolated persistent SQLite WAL directory owned by non-root user
RUN mkdir -p /app/data && chown -R node:node /app && chmod 700 /app/data

USER node

ENV NODE_ENV=production
ENV PORT=3000
ENV DB_PATH=whatsmomat.sqlite

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/api/healthz || exit 1

CMD ["node", "server.js"]
