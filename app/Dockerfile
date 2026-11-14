# Orion.ai frontend — builds the Vite/React static bundle and drops it into
# the `frontend_build` named volume that nginx serves from (see docker-compose.yml).
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Runtime stage: no Node needed at runtime, just copies the already-built
# bundle into the mounted volume on container start, then exits.
FROM alpine:3.20
WORKDIR /app
COPY --from=build /app/dist /dist_build
CMD ["sh", "-c", "cp -r /dist_build/. /app/dist/ && echo 'orion-frontend: build copied to frontend_build volume'"]
