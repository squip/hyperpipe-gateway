FROM node:22-bookworm-slim

WORKDIR /app/public-gateway

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      python3 \
      pkg-config \
      libsodium-dev && \
    rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm install --omit=dev

COPY src ./src
COPY bin ./bin
COPY README.md ./README.md

ENV NODE_PATH=/app/public-gateway/node_modules
EXPOSE 4430
CMD ["node", "src/index.mjs"]
