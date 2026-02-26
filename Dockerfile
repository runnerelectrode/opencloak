FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --production 2>/dev/null || true

COPY . .

# Vault data directory
ENV OPENCLOAK_DATA_DIR=/data
RUN mkdir -p /data && chmod 700 /data

EXPOSE 3422

CMD ["node", "server.mjs"]
