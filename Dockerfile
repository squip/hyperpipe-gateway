FROM node:22-bookworm-slim

WORKDIR /app/public-gateway

# If you still have other native addons that need compilation,
# leave this block in; otherwise you can remove it.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      python3 \
      pkg-config \
      libsodium-dev && \
    rm -rf /var/lib/apt/lists/*

COPY hyperpipe-bridge /app/hyperpipe-bridge
COPY hyperpipe-gateway/package*.json ./
RUN npm install --omit=dev

COPY hyperpipe-gateway/src ./src
COPY hyperpipe-gateway/bin ./bin
COPY hyperpipe-gateway/README.md ./README.md

ENV NODE_PATH=/app/public-gateway/node_modules
EXPOSE 4430
CMD ["node", "src/index.mjs"]
