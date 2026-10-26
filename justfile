# bProto build entry points. `just` + `xtask`, no second task runner.
#
#   just check      # fmt + clippy, the CI gate
#   just test       # unit + integration tests
#   just build      # server + cli release binaries
#   just android    # AAR for the Android client (needs cargo-ndk + NDK)
#   just ios        # xcframework for the iOS client (macOS only)
#   just panel      # run the control panel backend
#   just frontend   # build the control panel frontend

set shell := ["bash", "-uc"]

default: check

check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

test-all:
    cargo test --workspace -- --include-ignored

build:
    cargo build --release -p vpn-server -p vpn-cli

run-server:
    cargo run --release -p vpn-server -- --config crates/vpn-server/config/server.toml

check-config:
    cargo run -p vpn-server -- --check-config --config crates/vpn-server/config/server.toml

android:
    cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 build -p bproto \
        --features jni --release
    # step 2 (AAR packaging) is done by build_app.sh --android until xtask lands

ios:
    # the xcframework is built by build_app.sh --ios on macOS; there is no
    # xtask crate in this workspace yet
    ./build_app.sh --ios

panel:
    cd panel/backend && cargo run --release

migrate:
    cd panel/backend && sqlx migrate run

frontend:
    cd panel/frontend && pnpm install && pnpm build

release: build frontend
