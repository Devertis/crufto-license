FROM node:20-alpine

WORKDIR /app

# Install production dependencies against the committed lockfile.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.mjs ./

# Licenses are persisted here; mount a volume so they survive redeploys.
RUN mkdir -p /data && chown -R node:node /data /app
VOLUME ["/data"]

USER node
ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

CMD ["node", "server.mjs"]
