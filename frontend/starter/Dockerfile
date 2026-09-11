# Next.js dashboard - production build.
# setup.sh copies this into frontend/dashboard/ before `docker compose build`.
FROM node:20-slim

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
ENV BACKEND_URL=http://backend:8000
RUN npm run build

EXPOSE 3000
CMD ["npm", "start"]
