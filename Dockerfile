FROM node:22-slim
WORKDIR /app

# Trivy CLI: the worker runs it in client mode against the trivy service.
# Keep this tag the same as the trivy image in docker-compose.yml (client and server must match).
COPY --from=aquasec/trivy:0.58.1 /usr/local/bin/trivy /usr/local/bin/trivy
# Trivy needs system CA certificates to pull images from registries over HTTPS.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci

COPY prisma ./prisma
COPY prisma.config.ts tsconfig.json ./
COPY src ./src
# generate does not connect to the database, but prisma.config.ts expects the variable to be set.
RUN DATABASE_URL=postgresql://build:build@localhost/build npx prisma generate && npm run build

EXPOSE 3000
CMD ["node", "dist/index.js"]
