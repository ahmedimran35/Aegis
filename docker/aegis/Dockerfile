FROM node:20-alpine AS frontend

WORKDIR /app
COPY dashboard/package.json dashboard/package-lock.json* ./
RUN npm ci
COPY dashboard/ .
RUN npm run build

FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Build with version metadata. Override at build time:
#   docker build --build-arg VERSION=$(git describe) --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ARG VERSION=dev
ARG BUILD_TIME=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w -X main.version=${VERSION} -X main.buildTimeStr=${BUILD_TIME}" -o /aegis ./cmd/waf-engine/

FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata wget
RUN adduser -D -u 1000 aegis
RUN mkdir -p /var/lib/aegis && chown aegis:aegis /var/lib/aegis
COPY --from=builder /aegis /usr/local/bin/aegis
COPY --from=frontend /app/dist /app/dashboard/dist
COPY config.yaml /etc/aegis/config.yaml

# Download GeoLite2-Country at build time. Requires BuildKit for secret
# mounting; pass via `docker buildx build --secret id=maxmind,src=...`
# or compose `secrets:` block. If the secret is not provided, the image
# still builds with a stub mmdb (GeoIP disabled at runtime until the
# operator mounts the real DB).
# syntax=docker/dockerfile:1.4
ARG MAXMIND_LICENSE_KEY=""
RUN --mount=type=secret,id=maxmind \
    if [ -f /run/secrets/maxmind ]; then \
        KEY="$(cat /run/secrets/maxmind)" && \
        wget -q "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${KEY}&suffix=tar.gz" -O /tmp/geoip.tar.gz && \
        mkdir -p /tmp/geoip && tar -xzf /tmp/geoip.tar.gz -C /tmp/geoip --strip-components=1 && \
        cp /tmp/geoip/GeoLite2-Country.mmdb /var/lib/aegis/GeoLite2-Country.mmdb && \
        rm -rf /tmp/geoip /tmp/geoip.tar.gz; \
    else \
        echo "no maxmind secret — GeoIP disabled at runtime" && \
        touch /var/lib/aegis/GeoLite2-Country.mmdb; \
    fi
RUN chown -R aegis:aegis /var/lib/aegis /app

WORKDIR /app
EXPOSE 8080

# P-FIX: AEGIS_CONFIG points to the config we copied. Without this, the
# binary defaults to "config.yaml" relative to the working dir and fails
# to start because /app does not contain a config file.
ENV AEGIS_CONFIG=/etc/aegis/config.yaml
ENV AEGIS_HOME=/var/lib/aegis

USER aegis
ENTRYPOINT ["aegis"]
