# syntax=docker/dockerfile:1

FROM rust:1.99.0-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
# Build the dependencies on their own first, so this layer is cached until
# Cargo.lock changes.
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src
COPY src src
COPY public public
# Statically linked against musl, so it runs on the plain Alpine below.
RUN touch src/main.rs && cargo build --release --locked && cp target/release/edns /edns

FROM alpine:3.24
RUN apk add --no-cache ca-certificates su-exec libcap \
    && addgroup -S nonroot && adduser -S -G nonroot nonroot \
    && mkdir -p /data && chown nonroot:nonroot /data
COPY --from=build /edns /edns
# Let nonroot bind privileged ports: Fly.io doesn't rewrite UDP destination
# ports, so DNS must listen on :53 itself there.
RUN setcap cap_net_bind_service=+ep /edns
COPY entrypoint.sh /entrypoint.sh
# Certificate storage (CERT_DIR); mount a volume here to persist certs.
VOLUME ["/data"]
# DNS (udp+tcp), HTTP, HTTPS. Override the listen addresses via env as needed.
EXPOSE 53/udp 53/tcp 8080/tcp 8443/tcp
# Starts as root only to fix ownership of a freshly mounted /data volume
# (e.g. Fly.io volumes mount root-owned), then drops to nonroot.
ENTRYPOINT ["/entrypoint.sh"]
