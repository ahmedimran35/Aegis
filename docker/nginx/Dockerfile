# P-FIX (M-32): multi-stage build that bakes the React/Vite dashboard
# into the nginx image at build time. Eliminates the
# dashboard-mount-staleness class of bugs where the host's
# dashboard/dist diverges from what the aegis binary was built against.
FROM node:20-alpine AS frontend
WORKDIR /app
COPY dashboard/package.json dashboard/package-lock.json* ./
RUN npm ci
COPY dashboard/ .
RUN npm run build

FROM nginx:alpine
# Replace the default nginx content with the freshly built dashboard.
COPY --from=frontend /app/dist /usr/share/nginx/html
RUN rm -f /etc/nginx/conf.d/default.conf
