# Multi-stage build for the control panel backend.
FROM rust:1.88-slim AS build
WORKDIR /src
COPY panel/backend/Cargo.toml panel/backend/Cargo.lock* ./
COPY panel/backend/src ./src
COPY panel/backend/migrations ./migrations
RUN cargo build --release --locked || cargo build --release

FROM debian:stable-slim
RUN useradd -r -u 10001 panel && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/panel /usr/local/bin/panel
USER panel
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/panel"]
