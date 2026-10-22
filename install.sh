#!/usr/bin/env bash
#
# install.sh — install bProto on this machine
#
#   sudo ./install.sh server     server: binary, user, /etc/bproto, sysctl, systemd
#   sudo ./install.sh client     client CLI (bproto)
#   sudo ./install.sh all        server + client
#        ./install.sh panel      control panel via docker compose (no root needed)
#   sudo ./install.sh uninstall  remove server + client (keeps /etc/bproto)
#
# Options:
#   --prefix DIR     install prefix (default /usr/local)
#   --port N         UDP listen port (default 443)          [server]
#   --donor HOST     donor SNI, HTTP/3 site (default www.cloudflare.com)
#   --domain NAME    panel hostname, e.g. panel.example.com [panel]
#   --no-build       use ./dist or target/ as-is, do not build
#   --no-start       install but do not start the service   [server]
#   --force-config   overwrite an existing server.toml      [server]
#
# What `server` produces:
#   /usr/local/bin/vpn-server
#   /etc/bproto/server.toml          0600, generated with real keys
#   /etc/bproto/user1.client.toml    0600, a matching client config (copy to a device)
#   /etc/sysctl.d/99-bproto.conf     net.ipv4.ip_forward=1
#   /etc/systemd/system/bproto-server.service
#
# The generated server.toml has NO internet routing until you check nat_interface
# and that the UDP port is open in your firewall. See docs/INSTALL.md.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

PREFIX="/usr/local"
PORT="443"
DONOR="www.cloudflare.com"
DOMAIN="${BPROTO_DOMAIN:-}"
NO_BUILD=0
NO_START=0
FORCE_CONFIG=0

ETC_DIR="/etc/bproto"
SERVER_CFG="$ETC_DIR/server.toml"
CLIENT_CFG="$ETC_DIR/user1.client.toml"
UNIT="/etc/systemd/system/bproto-server.service"
SYSCTL="/etc/sysctl.d/99-bproto.conf"
SVC_USER="bproto"

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
TARGET=""
while [ $# -gt 0 ]; do
    case "$1" in
        server|client|all|panel|uninstall) TARGET="$1"; shift ;;
        --prefix)      PREFIX="${2:?--prefix needs a value}"; shift 2 ;;
        --port)        PORT="${2:?--port needs a value}"; shift 2 ;;
        --donor)       DONOR="${2:?--donor needs a value}"; shift 2 ;;
        --domain)      DOMAIN="${2:?--domain needs a value}"; shift 2 ;;
        --no-build)    NO_BUILD=1; shift ;;
        --no-start)    NO_START=1; shift ;;
        --force-config) FORCE_CONFIG=1; shift ;;
        -h|--help)     usage 0 ;;
        *)             die "unknown argument: $1 (try --help)" ;;
    esac
done
[ -n "$TARGET" ] || usage 1

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "'$TARGET' must run as root:  sudo ./install.sh $TARGET"
    fi
}

rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

detect_iface() {
    local iface
    iface="$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)"
    [ -n "$iface" ] || iface="$(ip -o link show up 2>/dev/null \
        | awk -F': ' '{print $2}' | grep -v '^lo$' | head -n1)"
    printf '%s' "$iface"
}

detect_src_ip() {
    local ip
    ip="$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n1)"
    [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    printf '%s' "$ip"
}

# Read tag_key from an existing server.toml so the panel and the server agree.
existing_tag_key() {
    [ -f "$SERVER_CFG" ] || return 0
    sed -n 's/^[[:space:]]*tag_key[[:space:]]*=[[:space:]]*"\([0-9a-fA-F]\{64\}\)".*/\1/p' "$SERVER_CFG" | head -n1
}

find_artifact() { # name -> path or empty (release wins, dist/ is the fallback)
    local name="$1"
    for p in "$REPO_ROOT/target/release/$name" "$REPO_ROOT/dist/bin/$name" "$REPO_ROOT/target/debug/$name"; do
        if [ -x "$p" ]; then printf '%s' "$p"; return 0; fi
    done
}

# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------
install_server() {
    need_root
    step "installing the bProto server (port $PORT)"

    local src
    if [ -z "$(find_artifact vpn-server)" ] && [ "$NO_BUILD" = 0 ]; then
        "$REPO_ROOT/build_app.sh" --release --no-panel >&2
    fi
    src="$(find_artifact vpn-server)"
    [ -n "$src" ] || die "vpn-server not found; run ./build_app.sh first (or drop --no-build)"

    install -d -m0755 "$PREFIX/bin"
    install -m0755 "$src" "$PREFIX/bin/vpn-server"
    ok "$PREFIX/bin/vpn-server"

    if ! id -u "$SVC_USER" >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
        ok "created system user '$SVC_USER'"
    fi

    install -d -m0750 "$ETC_DIR"

    if [ -f "$SERVER_CFG" ] && [ "$FORCE_CONFIG" = 0 ]; then
        warn "$SERVER_CFG exists; keeping it (use --force-config to replace)"
    else
        generate_config
    fi
    chmod 0600 "$SERVER_CFG"

    # Never hand over a config the server itself rejects.
    if ! "$PREFIX/bin/vpn-server" --check-config --config "$SERVER_CFG" >/dev/null 2>"$ETC_DIR/.check.log"; then
        cat "$ETC_DIR/.check.log" >&2
        rm -f "$ETC_DIR/.check.log"
        die "generated $SERVER_CFG does not validate (see above)"
    fi
    rm -f "$ETC_DIR/.check.log"
    ok "config validates"

    # ipv4 forwarding
    install -d -m0755 "$(dirname "$SYSCTL")"
    if [ ! -f "$SYSCTL" ]; then
        echo 'net.ipv4.ip_forward=1' > "$SYSCTL"
        ok "$SYSCTL"
    fi
    sysctl -q --system 2>/dev/null || warn "could not apply sysctl; run: sysctl --system"
    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]; then
        warn "net.ipv4.ip_forward is not 1: clients will connect but reach no internet"
    fi

    # systemd unit. The shipped file is the source of truth for the hardening
    # flags; only ExecStart is rewritten so --prefix and the config path match.
    install -d -m0755 "$(dirname "$UNIT")"
    if [ -f "$REPO_ROOT/crates/vpn-server/deploy/bproto-server.service" ]; then
        sed -e "s|^ExecStart=.*|ExecStart=$PREFIX/bin/vpn-server --config $SERVER_CFG --datapath|" \
            "$REPO_ROOT/crates/vpn-server/deploy/bproto-server.service" > "$UNIT"
        chmod 0644 "$UNIT"
    else
        write_unit
    fi
    ok "$UNIT"

    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null || warn "systemctl daemon-reload failed (not a systemd host?)"
        if [ "$NO_START" = 0 ]; then
            if systemctl enable --now bproto-server 2>/dev/null; then
                sleep 1
                if systemctl is-active --quiet bproto-server 2>/dev/null; then
                    ok "bproto-server is running"
                else
                    warn "bproto-server failed to start; see: journalctl -u bproto-server -n 50"
                fi
            else
                warn "could not start bproto-server; start it by hand:"
                warn "  $PREFIX/bin/vpn-server --config $SERVER_CFG --datapath"
            fi
        else
            systemctl enable bproto-server 2>/dev/null || true
            ok "bproto-server enabled (not started: --no-start)"
        fi
    else
        warn "systemctl not found; start it by hand:"
        warn "  $PREFIX/bin/vpn-server --config $SERVER_CFG --datapath"
    fi

    local ip
    ip="$(detect_src_ip)"
    printf '\n%sserver installed%s\n' "$C_BOLD" "$C_RESET" >&2
    printf '  config      %s\n' "$SERVER_CFG" >&2
    printf '  start/stop  systemctl {start,stop,status} bproto-server\n' >&2
    printf '  logs        journalctl -u bproto-server -f\n' >&2
    printf '\nstill to do:\n' >&2
    printf '  1. open UDP %s in your firewall (ufw allow %s/udp)\n' "$PORT" "$PORT" >&2
    printf '  2. check nat_interface in %s\n' "$SERVER_CFG" >&2
    if [ -f "$CLIENT_CFG" ]; then
        printf '  3. copy %s to a device as client.toml\n' "$CLIENT_CFG" >&2
    fi
    printf '  4. on the device:  bproto --config client.toml check && sudo bproto up\n' >&2
    if [ -n "$ip" ]; then
        printf '\nclient server= line should read:  server = "%s:%s"\n' "$ip" "$PORT" >&2
    fi
}

generate_config() {
    local tag psk admin_token iface ip
    tag="$(rand_hex 32)"
    psk="$(rand_hex 32)"
    admin_token="$(rand_hex 32)"
    iface="$(detect_iface)"
    ip="$(detect_src_ip)"

    umask 077
    cat > "$SERVER_CFG" <<EOF
# bProto server — generated by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Secrets in this file are the deployment. Keep it 0600.

listen_addr = "0.0.0.0:${PORT}"

# Routing tag key: must be identical in every client and in the panel's
# BPROTO_TAG_KEY.
tag_key = "${tag}"

[donor]
# The site whose identity the protocol is shaped after. A QUIC/HTTP-3 capable
# site is required once "mode B" (DPI resistance) is enabled; harmless now.
sni = "${DONOR}"
alpn = ["h3"]

[tun]
name = "bproto0"
address = "10.66.0.1"
netmask = "255.255.255.0"
mtu = 1280
# Outbound interface for NAT. If this is wrong clients will not reach the net.
nat_interface = "${iface}"

[admin]
listen_addr = "127.0.0.1:9100"
token = "${admin_token}"

[[users]]
id = 1
psk = "${psk}"
EOF
    chmod 0600 "$SERVER_CFG"
    ok "$SERVER_CFG (tag_key, admin token and user 1 generated)"

    # A ready-to-use client config for user 1. Point it at the right address
    # before copying it to a device.
    cat > "$CLIENT_CFG" <<EOF
# bProto client — user 1, generated by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
server = "${ip}:${PORT}"
user_id = 1
psk = "${psk}"
tag_key = "${tag}"
mtu = 1280
fingerprint = "chrome112"
stealth = "off"
handshake_timeout = "10s"

[donor]
sni = "${DONOR}"
EOF
    chmod 0600 "$CLIENT_CFG"
    ok "$CLIENT_CFG (copy this to the device)"

    if [ -z "$iface" ]; then
        warn "could not detect the outbound interface; set nat_interface before relying on it"
    fi
}

write_unit() {
    cat > "$UNIT" <<EOF
[Unit]
Description=bProto VPN server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PREFIX/bin/vpn-server --config $SERVER_CFG --datapath
Restart=on-failure
RestartSec=2
User=$SVC_USER
Group=$SVC_USER
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=no
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
LimitNOFILE=1048576
Environment=RUST_LOG=info
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
}

# ---------------------------------------------------------------------------
# client
# ---------------------------------------------------------------------------
install_client() {
    need_root
    step "installing the bProto client"

    if [ -z "$(find_artifact bproto)" ] && [ "$NO_BUILD" = 0 ]; then
        "$REPO_ROOT/build_app.sh" --release --no-panel --no-ffi >&2
    fi
    local src
    src="$(find_artifact bproto)"
    [ -n "$src" ] || die "bproto not found; run ./build_app.sh first (or drop --no-build)"

    install -d -m0755 "$PREFIX/bin"
    install -m0755 "$src" "$PREFIX/bin/bproto"
    ok "$PREFIX/bin/bproto"

    install -d -m0755 "$PREFIX/share/bproto"
    if [ -f "$REPO_ROOT/crates/vpn-cli/config/client.example.toml" ]; then
        install -m0644 "$REPO_ROOT/crates/vpn-cli/config/client.example.toml" \
            "$PREFIX/share/bproto/client.example.toml"
        ok "$PREFIX/share/bproto/client.example.toml"
    fi

    printf '\n%sclient installed%s\n' "$C_BOLD" "$C_RESET" >&2
    printf '  generate a key config   bproto import "bproto://import/..." --out client.toml\n' >&2
    printf '  or start from           %s/share/bproto/client.example.toml\n' "$PREFIX" >&2
    printf '  validate                bproto --config client.toml check\n' >&2
    printf '  no-root test            bproto --config client.toml connect --seconds 5\n' >&2
    printf '  full tunnel             sudo bproto --config client.toml up\n' >&2
    if [ -f "$CLIENT_CFG" ]; then
        printf '\n  this host also serves a key:  %s\n' "$CLIENT_CFG" >&2
    fi
}

# ---------------------------------------------------------------------------
# panel
# ---------------------------------------------------------------------------
install_panel() {
    step "installing the control panel"

    command -v docker >/dev/null 2>&1 || die "docker not found; see https://docs.docker.com/engine/install/"
    docker compose version >/dev/null 2>&1 || die "docker compose (v2) not found"

    [ -n "$DOMAIN" ] || die "set the panel hostname:  ./install.sh panel --domain panel.example.com"

    local tag
    tag="$(existing_tag_key)"
    if [ -n "$tag" ]; then
        ok "reusing tag_key from $SERVER_CFG (panel and server will agree)"
    else
        tag="$(rand_hex 32)"
        warn "no $SERVER_CFG found; generating a tag_key."
        warn "put this in server.toml and every client:  tag_key = \"$tag\""
    fi

    local admin_pw
    admin_pw="$(rand_hex 24)"

    ( cd "$REPO_ROOT/panel"
      umask 077
      cat > .env <<EOF
BPROTO_DOMAIN=${DOMAIN}
BPROTO_TAG_KEY=${tag}
BPROTO_ADMIN_PASSWORD=${admin_pw}
EOF
      step "docker compose up -d --build"
      docker compose up -d --build
    )

    printf '\n%spanel installed%s\n' "$C_BOLD" "$C_RESET" >&2
    printf '  url       https://%s\n' "$DOMAIN" >&2
    printf '  login     admin / %s\n' "$admin_pw" >&2
    printf '  secrets   %s/panel/.env\n' "$REPO_ROOT" >&2
    printf '  logs      cd panel && docker compose logs -f\n' >&2
    printf '\npoint %s DNS at this host BEFORE the first request (Caddy needs port 80/443).\n' "$DOMAIN" >&2
    printf 'change the admin password after the first login.\n' >&2
}

# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------
uninstall() {
    need_root
    step "removing bProto server and client"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now bproto-server 2>/dev/null || true
    fi
    rm -f "$UNIT" "$SYSCTL" "$PREFIX/bin/vpn-server" "$PREFIX/bin/bproto"
    rm -rf "$PREFIX/share/bproto"
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
    if id -u "$SVC_USER" >/dev/null 2>&1; then
        userdel "$SVC_USER" 2>/dev/null || warn "could not remove user '$SVC_USER'"
    fi
    warn "kept $ETC_DIR (configs and keys). Remove it by hand if you mean to."
    ok "removed binaries, unit, sysctl, user"
}

# ---------------------------------------------------------------------------
case "$TARGET" in
    server)    install_server ;;
    client)    install_client ;;
    all)       install_server; install_client ;;
    panel)     install_panel ;;
    uninstall) uninstall ;;
esac
