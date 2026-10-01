# syntax=docker/dockerfile:1

FROM golang:1.26.6-alpine3.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/edns .

FROM alpine:3.24
RUN apk add --no-cache ca-certificates su-exec libcap \
    && addgroup -S nonroot && adduser -S -G nonroot nonroot \
    && mkdir -p /data && chown nonroot:nonroot /data
COPY --from=build /out/edns /edns
# Let nonroot bind privileged ports: Fly.io doesn't rewrite UDP destination
# ports, so DNS must listen on :53 itself there.
RUN setcap cap_net_bind_service=+ep /edns
COPY entrypoint.sh /entrypoint.sh
# CertMagic certificate storage (CERT_DIR); mount a volume here to persist certs.
VOLUME ["/data"]
# DNS (udp+tcp), HTTP, HTTPS. Override the listen addresses via env as needed.
EXPOSE 53/udp 53/tcp 8080/tcp 8443/tcp
# Starts as root only to fix ownership of a freshly mounted /data volume
# (e.g. Fly.io volumes mount root-owned), then drops to nonroot.
ENTRYPOINT ["/entrypoint.sh"]
