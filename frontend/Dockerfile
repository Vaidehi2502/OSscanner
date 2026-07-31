# SentinelOS frontend. Multi-stage build: compile the React app, then
# serve the static bundle via nginx with /api/* proxied to the backend
# container (see nginx.conf and the "backend" service in the top-level
# docker-compose.yml).
FROM node:20-slim AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# CRA inlines REACT_APP_* vars into the JS bundle at build time, not
# runtime - so this has to be a build arg, not a container env var.
ARG REACT_APP_API_KEY=
ENV REACT_APP_API_KEY=$REACT_APP_API_KEY
RUN npm run build

FROM nginx:1.27-alpine

COPY --from=build /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
