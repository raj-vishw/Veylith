# syntax=docker/dockerfile:1
FROM node:24-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:24-alpine AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
# next.config rewrites are resolved at build time, so the internal API address is baked in here.
ARG API_INTERNAL_URL=http://api:8000
ENV API_INTERNAL_URL=${API_INTERNAL_URL}
COPY --from=deps /app/node_modules node_modules
COPY . .
RUN npm run build

FROM node:24-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN addgroup -S veylith && adduser -S veylith -G veylith
COPY --from=build --chown=veylith:veylith /app/.next/standalone ./
COPY --from=build --chown=veylith:veylith /app/.next/static ./.next/static
USER veylith
EXPOSE 3000
CMD ["node", "server.js"]
