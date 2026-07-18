# Next.js dashboard - production build.
# setup.sh copies this into frontend/dashboard/ before `docker compose build`.
FROM node:20-slim

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
# The browser calls the backend at http://127.0.0.1:8000 (see src/lib/api.ts default),
# so no build-time API URL is needed.
RUN npm run build

EXPOSE 3000
CMD ["npm", "start"]
