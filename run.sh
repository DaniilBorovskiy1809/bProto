#!/usr/bin/env bash
#
# run.sh — run bProto from the source tree
#
#   ./run.sh demo [seconds]   start a local server + client on 127.0.0.1 and show
#                             a real handshake and a tunnel coming up (no root)
#   ./run.sh server [args]    run the server (pass --datapath for the real data path)
#   ./run.sh check-config [path]
#   ./run.sh client [args]    run the bproto CLI, e.g.:
#                               ./run.sh client --config client.toml connect --seconds 5
#                               ./run.sh client --uri 'bproto://import/...' connect
#   ./run.sh panel            run the control panel backend locally
#   ./run.sh frontend         run the panel dev server (vite, :5173)
#   ./run.sh check            cargo fmt --check + clippy -D warnings
#   ./run.sh test             cargo test --workspace
#   ./run.sh e2e              the client<->server integration test, with output
#
# Binaries are taken from target/release, then target/debug, then built on demand.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

SERVER_CFG="$REPO_ROOT/crates/vpn-server/config/server.toml"

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

[ $# -ge 1 ] || usage 1
CMD="$1"; shift

rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# Path of a built artifact, or empty. Release wins over debug over dist/.
artifact() {
    local name="$1"
    for p in "$REPO_ROOT/target/release/$name" \
             "$REPO_ROOT/target/debug/$name" \
             "$REPO_ROOT/dist/bin/$name"; do
        if [ -x "$p" ]; then printf '%s' "$p"; return 0; fi
    done
}

# Same, but builds the crate if nothing is built yet.
ensure() { # name crate
    local p
    p="$(artifact "$1")"
    if [ -z "$p" ]; then
        step "building $2"
        cargo build -p "$2" >&2
        p="$(artifact "$1")"
    fi
    [ -n "$p" ] || die "$1 not found after building $2"
    printf '%s' "$p"
}

case "$CMD" in
    -h|--help) usage 0 ;;
esac

# ---------------------------------------------------------------------------
case "$CMD" in
    check)
        step "quality gate"
        cargo fmt --all --check && ok "fmt"
        cargo clippy --workspace --all-targets -- -D warnings && ok "clippy"
        ;;

    test)
        step "cargo test --workspace"
        cargo test --workspace
        ;;

    e2e)
        step "client <-> server over loopback UDP"
        cargo test -p vpn-core --test tunnel_e2e -- --nocapture
        ;;

    check-config)
        SERVER_BIN="$(ensure vpn-server vpn-server)"
        step "$SERVER_BIN --check-config"
        "$SERVER_BIN" --check-config --config "${1:-$SERVER_CFG}"
        ;;

    server)
        SERVER_BIN="$(ensure vpn-server vpn-server)"
        CFG="$SERVER_CFG"
        if [ $# -eq 0 ]; then
            step "$SERVER_BIN --config $CFG"
            exec "$SERVER_BIN" --config "$CFG"
        fi
        step "$SERVER_BIN $*"
        exec "$SERVER_BIN" "$@"
        ;;

    client)
        CLIENT_BIN="$(ensure bproto vpn-cli)"
        step "$CLIENT_BIN $*"
        exec "$CLIENT_BIN" "$@"
        ;;

    panel)
        TAG_KEY=""
        if [ -f /etc/bproto/server.toml ]; then
            TAG_KEY="$(sed -n 's/^[[:space:]]*tag_key[[:space:]]*=[[:space:]]*"\([0-9a-fA-F]\{64\}\)".*/\1/p' /etc/bproto/server.toml | head -n1)"
            [ -n "$TAG_KEY" ] && ok "tag_key taken from /etc/bproto/server.toml"
        fi
        if [ -z "$TAG_KEY" ]; then
            TAG_KEY="$(rand_hex 32)"
            warn "no server.toml found; using an ephemeral tag_key"
            warn "clients must use:  tag_key = \"$TAG_KEY\""
        fi
        step "panel backend on 127.0.0.1:8080"
        ( cd "$REPO_ROOT/panel/backend" && BPROTO_TAG_KEY="$TAG_KEY" exec cargo run "$@" )
        ;;

    frontend)
        FE="$REPO_ROOT/panel/frontend"
        [ -d "$FE" ] || die "panel/frontend not found"
        ( cd "$FE"
          if [ ! -d node_modules ]; then
              if command -v pnpm >/dev/null 2>&1; then pnpm install
              elif command -v npm >/dev/null 2>&1; then npm install
              else die "neither pnpm nor npm found"; fi
          fi
          step "vite dev server on http://127.0.0.1:5173"
          if command -v pnpm >/dev/null 2>&1 && [ -x node_modules/.bin/vite ]; then
              exec ./node_modules/.bin/vite "$@"
          else
              exec npm run dev -- "$@"
          fi
        )
        ;;

    demo)
        SECS="${1:-3}"
        SERVER_BIN="$(ensure vpn-server vpn-server)"
        CLIENT_BIN="$(ensure bproto vpn-cli)"

        TMP="$(mktemp -d "${TMPDIR:-/tmp}/bproto-demo.XXXXXX")"
        TAG="$(rand_hex 32)"
        PSK="$(rand_hex 32)"
        PORT=$(( 40000 + RANDOM % 20000 ))
        APORT=$(( PORT + 1 ))

        cat > "$TMP/server.toml" <<EOF
listen_addr = "127.0.0.1:${PORT}"
tag_key = "${TAG}"
[donor]
sni = "www.cloudflare.com"
[tun]
name = "bproto0"
address = "10.66.0.1"
netmask = "255.255.255.0"
mtu = 1280
[admin]
listen_addr = "127.0.0.1:${APORT}"
token = "$(rand_hex 16)"
[[users]]
id = 1
psk = "${PSK}"
EOF

        cat > "$TMP/client.toml" <<EOF
server = "127.0.0.1:${PORT}"
user_id = 1
psk = "${PSK}"
tag_key = "${TAG}"
[donor]
sni = "www.cloudflare.com"
EOF

        step "starting a local server on 127.0.0.1:$PORT (no --datapath, no root)"
        "$SERVER_BIN" --config "$TMP/server.toml" > "$TMP/server.log" 2>&1 &
        SERVER_PID=$!
        cleanup() {
            kill "$SERVER_PID" 2>/dev/null || true
            wait "$SERVER_PID" 2>/dev/null || true
            if [ "${KEEP:-0}" = 1 ]; then
                warn "kept $TMP"
            else
                rm -rf "$TMP"
            fi
        }
        trap cleanup EXIT INT TERM

        for _ in $(seq 1 50); do
            grep -q "listener up" "$TMP/server.log" 2>/dev/null && break
            kill -0 "$SERVER_PID" 2>/dev/null || break
            sleep 0.1
        done
        if ! grep -q "listener up" "$TMP/server.log" 2>/dev/null; then
            cat "$TMP/server.log" >&2
            die "server did not come up (port $PORT busy?)"
        fi
        ok "server is up"

        printf '\n' >&2
        "$CLIENT_BIN" --config "$TMP/client.toml" check
        printf '\n' >&2
        "$CLIENT_BIN" --config "$TMP/client.toml" connect --seconds "$SECS"

        printf '\n%sserver side of the exchange%s\n' "$C_BOLD" "$C_RESET" >&2
        sed 's/^/  /' "$TMP/server.log" >&2

        KEEP=0
        ok "handshake and session worked end to end"
        ;;

    *)
        die "unknown command: $CMD (try --help)"
        ;;
esac
