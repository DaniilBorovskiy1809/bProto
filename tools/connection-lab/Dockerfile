FROM rust:bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=secret,id=lab_ca,target=/run/secrets/lab-ca \
    if [ -f /run/secrets/lab-ca ]; then export CARGO_HTTP_CAINFO=/run/secrets/lab-ca; fi; \
    cargo build --locked --release -j 2 -p vpn-server -p vpn-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 iproute2 nftables iputils-ping tcpdump ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/vpn-server /usr/local/bin/vpn-server
COPY --from=build /build/target/release/bproto /usr/local/bin/bproto
COPY tools/connection_lab.py tools/connection-lab/container_entry.py /app/
ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python3", "/app/container_entry.py"]
