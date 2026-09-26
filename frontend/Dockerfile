# ---- build ----
FROM node:20-slim AS build
WORKDIR /app

# Copy manifests first so the dependency layer caches independently of source.
COPY package.json package-lock.json* ./
RUN npm ci 2>/dev/null || npm install

COPY . .
RUN npm run build

# ---- runtime ----
FROM nginx:1.27-alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/templates/default.conf.template

# BACKEND_ORIGIN is substituted into the template by the stock nginx image
# entrypoint (envsubst on /etc/nginx/templates/*.template) at container start,
# so the same image works against any backend address.
ENV BACKEND_ORIGIN=http://backend:8000
ENV NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx/conf.d
# Restrict substitution to this one variable so nginx runtime variables
# ($host, $uri, $remote_addr, ...) are left untouched by envsubst.
ENV NGINX_ENVSUBST_FILTER=BACKEND_ORIGIN

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1/ >/dev/null 2>&1 || exit 1
