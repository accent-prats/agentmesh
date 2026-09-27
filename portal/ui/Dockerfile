# Build stage
FROM node:20-alpine AS build
WORKDIR /app

# Build args (injected at build time)
ARG VITE_PORTAL_URL=http://portal.local
ARG VITE_GROWTHBOOK_API_HOST=
ARG VITE_GROWTHBOOK_CLIENT_KEY=
ENV VITE_PORTAL_URL=$VITE_PORTAL_URL
ENV VITE_GROWTHBOOK_API_HOST=$VITE_GROWTHBOOK_API_HOST
ENV VITE_GROWTHBOOK_CLIENT_KEY=$VITE_GROWTHBOOK_CLIENT_KEY

COPY package.json ./
RUN npm install

COPY . .
RUN npm run build

# Serve stage — lightweight nginx
FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
