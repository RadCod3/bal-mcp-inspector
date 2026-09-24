# Build the static bundle
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# Serve the bundle and proxy API calls to the backend
FROM nginxinc/nginx-unprivileged:1.30-alpine
# Base URL of the inspector backend, e.g. http://backend:8080 or https://inspector-api.example.com
ENV BACKEND_URL=http://localhost:8080
# Render the config into /tmp so the container works with a read-only root filesystem
ENV NGINX_ENVSUBST_OUTPUT_DIR=/tmp
USER root
RUN apk upgrade --no-cache \
    && rm /etc/nginx/conf.d/default.conf \
    && sed -i 's|include /etc/nginx/conf.d/\*.conf;|include /tmp/default.conf;|' /etc/nginx/nginx.conf
COPY docker/default.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
# Choreo requires a non-root UID between 10000 and 20000
USER 10014
EXPOSE 8080
