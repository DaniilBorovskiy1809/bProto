#!/usr/bin/env bash
#
# build_app.sh — build every bProto artifact into ./dist
#
#   ./build_app.sh                 release binaries + C-ABI libs + control panel
#   ./build_app.sh --debug         debug profile instead of release
#   ./build_app.sh --check         run the CI gate (fmt + clippy + tests)
#   ./build_app.sh --android       cross-compile libbproto.so for Android
#                                   (--features jni), fill apps/android jniLibs
#                                   and assemble the debug APK into dist/apk/
#   ./build_app.sh --ios           also cross-compile libbproto.a for iOS (macOS)
#   ./build_app.sh --no-apk        skip the APK step
#   ./build_app.sh --no-panel      skip the control panel (backend + frontend)
#   ./build_app.sh --no-ffi        skip the C-ABI library
#
# Output layout:
#   dist/bin/vpn-server          server
#   dist/bin/bproto              client CLI
#   dist/lib/libbproto.so        C-ABI shared library (Android / desktop)
#   dist/lib/libbproto.a         C-ABI static library (iOS / linking)
#   dist/panel/panel             control panel backend
#   dist/panel/dist/             control panel frontend (static, serve with any web server)
#   dist/android/jniLibs/...     Android .so per ABI (with --android)
#   dist/apk/bproto-*-debug.apk  installable Android APK (with --android)
#   dist/ios/libbproto*.a        iOS static libraries (with --ios)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

DIST="$REPO_ROOT/dist"
PROFILE="release"
CARGO_FLAGS=()
WANT_CHECK=0
WANT_PANEL=1
WANT_FFI=1
WANT_ANDROID=0
WANT_IOS=0
WANT_APK=1
MIN_RUST="1.88"

# ---------------------------------------------------------------------------
# output helpers
# ---------------------------------------------------------------------------
if [ -t 2 ]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
    C_RESET=''; C_BOLD=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''
fi

step() { printf '%s==>%s %s%s%s\n' "$C_BLUE" "$C_RESET" "$C_BOLD" "$*" "$C_RESET" >&2; }
ok()   { printf '%s  ok%s %s\n' "$C_GREEN" "$C_RESET" "$*" >&2; }
warn() { printf '%swarn%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '%serr %s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

usage() {
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"
    exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# arguments
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --debug)     PROFILE="debug"; shift ;;
        --release)   PROFILE="release"; shift ;;
        --check)     WANT_CHECK=1; shift ;;
        --android)   WANT_ANDROID=1; shift ;;
        --ios)       WANT_IOS=1; shift ;;
        --no-apk)    WANT_APK=0; shift ;;
        --no-panel)  WANT_PANEL=0; shift ;;
        --no-ffi)    WANT_FFI=0; shift ;;
        -h|--help)   usage 0 ;;
        *)           die "unknown option: $1 (try --help)" ;;
    esac
done

if [ "$PROFILE" = "release" ]; then
    CARGO_FLAGS+=(--release)
fi

# ---------------------------------------------------------------------------
# toolchain checks
# ---------------------------------------------------------------------------
command -v cargo >/dev/null 2>&1 || die "cargo not found; install Rust from https://rustup.rs"

RUSTC_VERSION="$(rustc --version | awk '{print $2}')"
version_ge() { # $1 >= $2
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}
version_ge "$RUSTC_VERSION" "$MIN_RUST" \
    || die "Rust $RUSTC_VERSION is too old; bProto needs $MIN_RUST+ (edition 2024, let-chains)"

step "bProto build  (profile=$PROFILE, rustc=$RUSTC_VERSION)"

# ---------------------------------------------------------------------------
# CI gate
# ---------------------------------------------------------------------------
if [ "$WANT_CHECK" = 1 ]; then
    step "quality gate"
    cargo fmt --all --check
    ok "cargo fmt"
    cargo clippy --workspace --all-targets -- -D warnings
    ok "cargo clippy"
    cargo test --workspace
    ok "cargo test"
    # The JNI tier is feature-gated, so the default pass never compiles it.
    cargo clippy -p bproto --features jni --all-targets -- -D warnings
    cargo test -p bproto --features jni
    ok "cargo test (jni)"
fi

# ---------------------------------------------------------------------------
# Rust binaries + C-ABI library
# ---------------------------------------------------------------------------
CRATES=(vpn-server vpn-cli)
[ "$WANT_FFI" = 1 ] && CRATES+=(bproto)

step "cargo build ${CRATES[*]}"
cargo build "${CARGO_FLAGS[@]}" $(for c in "${CRATES[@]}"; do printf ' -p %s' "$c"; done)
ok "rust artifacts"

TARGET_DIR="$REPO_ROOT/target/$PROFILE"

# ---------------------------------------------------------------------------
# stage into dist/
# ---------------------------------------------------------------------------
step "staging dist/"
rm -rf "$DIST/bin" "$DIST/lib" "$DIST/panel" "$DIST/apk"
mkdir -p "$DIST/bin" "$DIST/lib"

install -m0755 "$TARGET_DIR/vpn-server" "$DIST/bin/vpn-server"
install -m0755 "$TARGET_DIR/bproto"     "$DIST/bin/bproto"
ok "dist/bin/{vpn-server,bproto}"

if [ "$WANT_FFI" = 1 ]; then
    for lib in libbproto.so libbproto.dylib libbproto.a; do
        [ -f "$TARGET_DIR/$lib" ] && install -m0644 "$TARGET_DIR/$lib" "$DIST/lib/$lib"
    done
    [ -n "$(ls -A "$DIST/lib" 2>/dev/null)" ] || warn "no libbproto.* produced"
    ok "dist/lib/ ($(ls "$DIST/lib" 2>/dev/null | tr '\n' ' '))"
fi

# ---------------------------------------------------------------------------
# control panel
# ---------------------------------------------------------------------------
build_panel_backend() {
    step "cargo build panel backend"
    ( cd "$REPO_ROOT/panel/backend" && cargo build "${CARGO_FLAGS[@]}" )
    mkdir -p "$DIST/panel"
    install -m0755 "$REPO_ROOT/panel/backend/target/$PROFILE/panel" "$DIST/panel/panel"
    ok "dist/panel/panel"
}

build_panel_frontend() {
    local fe="$REPO_ROOT/panel/frontend"

    if ! command -v node >/dev/null 2>&1; then
        warn "node not found: skipping the panel frontend (backend still built)"
        return 0
    fi

    step "build panel frontend"
    (
        cd "$fe"
        if [ ! -d node_modules ]; then
            if command -v pnpm >/dev/null 2>&1; then
                pnpm install --frozen-lockfile 2>/dev/null || pnpm install
            elif command -v npm >/dev/null 2>&1; then
                npm install
            else
                die "neither pnpm nor npm found"
            fi
        fi

        # Prefer the locally installed toolchain: it is what the lockfile pins.
        if [ -x node_modules/.bin/tsc ] && [ -x node_modules/.bin/vite ]; then
            ./node_modules/.bin/tsc -b
            ./node_modules/.bin/vite build
        elif command -v pnpm >/dev/null 2>&1; then
            pnpm build
        else
            npm run build
        fi
    )
    mkdir -p "$DIST/panel"
    rm -rf "$DIST/panel/dist"
    cp -r "$fe/dist" "$DIST/panel/dist"
    ok "dist/panel/dist/"
}

if [ "$WANT_PANEL" = 1 ] && [ -d "$REPO_ROOT/panel/backend" ]; then
    build_panel_backend
    build_panel_frontend
fi

# ---------------------------------------------------------------------------
# mobile cross-compilation (opt-in)
# ---------------------------------------------------------------------------
if [ "$WANT_ANDROID" = 1 ]; then
    step "android (cargo-ndk, --features jni)"
    # `cargo ndk` finds the subcommand in ~/.cargo/bin even when PATH does not.
    if ! cargo ndk --version >/dev/null 2>&1; then
        die "cargo-ndk not found; run: cargo install cargo-ndk && rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android"
    fi
    if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -z "${ANDROID_NDK_ROOT:-}" ] && [ -z "${NDK_HOME:-}" ]; then
        warn "no ANDROID_NDK_HOME set: cargo-ndk will look for the NDK under \$ANDROID_HOME/ndk"
    fi
    for t in arm64-v8a armeabi-v7a x86_64; do
        case "$t" in
            arm64-v8a)   rustup target list --installed | grep -qx aarch64-linux-android || rustup target add aarch64-linux-android ;;
            armeabi-v7a) rustup target list --installed | grep -qx armv7-linux-androideabi  || rustup target add armv7-linux-androideabi ;;
            x86_64)      rustup target list --installed | grep -qx x86_64-linux-android    || rustup target add x86_64-linux-android ;;
        esac
    done
    rm -rf "$DIST/android"
    cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
        -o "$DIST/android/jniLibs" build -p bproto --features jni "${CARGO_FLAGS[@]}"
    ok "dist/android/jniLibs/ ($(find "$DIST/android/jniLibs" -name '*.so' | wc -l) ABIs)"

    # Drop them where the Gradle project expects them so the APK step below
    # (or a plain `./gradlew assembleDebug`) can package them.
    JNI_DEST="$REPO_ROOT/apps/android/app/src/main/jniLibs"
    mkdir -p "$JNI_DEST"
    cp -r "$DIST/android/jniLibs/." "$JNI_DEST/"
    ok "apps/android/app/src/main/jniLibs/ filled"

    # ---------------------------------------------------------------------
    # APK. The Gradle wrapper is not committed (it is a binary), so accept
    # either one the developer generated or a `gradle` on PATH.
    # ---------------------------------------------------------------------
    GRADLE_BIN=""
    if [ -x "$REPO_ROOT/apps/android/gradlew" ]; then
        GRADLE_BIN="$REPO_ROOT/apps/android/gradlew"
    elif command -v gradle >/dev/null 2>&1; then
        GRADLE_BIN="gradle"
    fi
    if [ "$WANT_APK" = 0 ]; then
        printf '  skipped: --no-apk\n' >&2
    elif [ -z "$GRADLE_BIN" ]; then
        warn "no gradle and no apps/android/gradlew: skipping the APK"
        printf '  next: cd apps/android && gradle wrapper && ./gradlew assembleDebug\n' >&2
    elif [ -z "${JAVA_HOME:-}" ] && ! command -v java >/dev/null 2>&1; then
        warn "no JDK: skipping the APK (export JAVA_HOME=/path/to/jdk17)"
    else
        step "android apk (gradle assembleDebug)"
        SDK_DIR="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
        if [ -n "$SDK_DIR" ]; then
            printf 'sdk.dir=%s\n' "$SDK_DIR" > "$REPO_ROOT/apps/android/local.properties"
        fi
        ( cd "$REPO_ROOT/apps/android" && "$GRADLE_BIN" assembleDebug )
        APP_VERSION="$(awk '/^\[workspace.package\]/{f=1} f && /^version/{gsub(/[",]/,"",$3); print $3; exit}' "$REPO_ROOT/Cargo.toml")"
        mkdir -p "$DIST/apk"
        install -m0644 "$REPO_ROOT/apps/android/app/build/outputs/apk/debug/app-debug.apk" \
            "$DIST/apk/bproto-${APP_VERSION:-0.1.0}-debug.apk"
        ok "dist/apk/ ($(basename "$DIST"/apk/*.apk), $(du -h "$DIST"/apk/*.apk | cut -f1))"
        printf '  install: adb install -r %s/apk/%s\n' "$DIST" "$(basename "$DIST"/apk/*.apk)" >&2
    fi
fi

if [ "$WANT_IOS" = 1 ]; then
    step "ios (device + simulator static libs)"
    [ "$(uname -s)" = "Darwin" ] || die "--ios requires macOS"
    for tgt in aarch64-apple-ios aarch64-apple-ios-sim; do
        rustup target list --installed | grep -q "$tgt" || rustup target add "$tgt"
    done
    for tgt in aarch64-apple-ios aarch64-apple-ios-sim; do
        cargo build -p bproto "${CARGO_FLAGS[@]}" --target "$tgt"
    done
    mkdir -p "$DIST/ios"
    install -m0644 "$REPO_ROOT/target/aarch64-apple-ios/$PROFILE/libbproto.a" \
        "$DIST/ios/libbproto-device.a"
    install -m0644 "$REPO_ROOT/target/aarch64-apple-ios-sim/$PROFILE/libbproto.a" \
        "$DIST/ios/libbproto-sim.a"
    xcrun lipo -create "$DIST/ios/libbproto-device.a" "$DIST/ios/libbproto-sim.a" \
        -output "$DIST/ios/libbproto.a" 2>/dev/null || {
        warn "lipo unavailable: use the per-slice archives and set EXCLUDED_ARCHS"
    }
    ok "dist/ios/ ($(ls "$DIST/ios" | tr '\n' ' '))"
    printf '  next: add dist/ios/libbproto.a to the Packet Tunnel target (see apps/ios/README.md)\n' >&2
fi

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------
printf '\n%sbuilt%s\n' "$C_BOLD" "$C_RESET" >&2
( cd "$DIST" && find . -type f | sort | sed 's|^\./|  |' ) >&2
printf '\nrun the server:  %s/bin/vpn-server --config <server.toml> [--datapath]\n' "$DIST" >&2
printf 'run the client:  %s/bin/bproto --config <client.toml> connect\n' "$DIST" >&2
printf 'install it:      sudo ./install.sh server\n\n' >&2
