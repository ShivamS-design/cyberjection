# Cyberjection web dashboard image: builds the Vite/React static bundle,
# then serves it (plus proxies `/api/` to the backend) with nginx. Two
# stages so the final image contains only compiled static assets and
# nginx -- no Node.js runtime, no node_modules.
#
# Build:  docker build -t cyberjection-dashboard:0.10.0 .
# Run:    docker run --rm -p 3000:80 \
#           -e API_UPSTREAM=http://cyberjection-api:8000 \
#           cyberjection-dashboard:0.10.0
#
# See ../../docker-compose.yml for how this is wired to the API service
# in the full stack.

FROM node:20-slim AS builder

WORKDIR /build
COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:1.27-alpine AS runtime

COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY --from=builder /build/dist /usr/share/nginx/html

# nginx's own docker-entrypoint.sh (already the image's ENTRYPOINT) runs
# envsubst over every file in /etc/nginx/templates/ before starting, so
# `${API_UPSTREAM}` in nginx.conf resolves from this environment variable
# at container start -- no image rebuild needed to point a deployment at
# a different backend host.
ENV API_UPSTREAM=http://cyberjection-api:8000

EXPOSE 80
