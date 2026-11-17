#!/usr/bin/env bash
# Standalone network installer; supports bash <(curl -fsSL URL).
set -euo pipefail

REPOSITORY="https://github.com/dr-lexus-dr/bProto"
RELEASE="v1.5.0"
DIRECTORY="/opt/bproto"
TARGET="all"
PORT="443"
NO_START=0
SKIP_DEPS=0
DOWNLOAD_ONLY=0
DRY_RUN=0

fail() { printf 'bProto: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'HELP'
bProto server bootstrap / Установка bProto
Usage: bash bootstrap.sh [options]
  --release TAG       Published release, default v1.5.0
  --directory PATH    Persistent source checkout, default /opt/bproto
  --target TARGET     server, client, all (default all)
  --port PORT         New server UDP port, default 443
  --no-start          Install without starting the service
  --skip-deps         Do not run apt-get; prerequisites must exist
  --download-only DIR Download and verify Linux archive into an empty directory
  --dry-run           Show plan without network requests or system changes
  --help              Show this help
Run installations as root. Downloads and dry-run do not require root.
Existing server configuration is preserved. Firewall ports are not opened.
HELP
}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --release) RELEASE="${2:?--release requires a tag}"; shift 2 ;;
        --directory) DIRECTORY="${2:?--directory requires a path}"; shift 2 ;;
        --target) TARGET="${2:?--target requires a target}"; shift 2 ;;
        --port) PORT="${2:?--port requires a port}"; shift 2 ;;
        --no-start) NO_START=1; shift ;;
        --skip-deps) SKIP_DEPS=1; shift ;;
        --download-only) DOWNLOAD_ONLY=1; DIRECTORY="${2:?--download-only requires a path}"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) fail "Unknown option: $1 (see --help)" ;;
    esac
done
[[ "$RELEASE" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Release must have form v1.0.0"
[[ "$TARGET" =~ ^(server|client|all)$ ]] || fail "Target must be server, client or all"
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && (( 10#$PORT >= 1 && 10#$PORT <= 65535 )) || fail "Port must be 1..65535"
[[ "$DIRECTORY" =~ ^/[A-Za-z0-9_./-]+$ && "$DIRECTORY" != / && "$DIRECTORY" != *'/../'* && "$DIRECTORY" != */.. ]] || fail "Use an absolute, non-root directory without spaces or .."
if [ "$DRY_RUN" = 1 ]; then
    printf 'Release: %s\nTarget: %s\nDirectory: %s\nUDP port: %s\nDownload only: %s\n' "$RELEASE" "$TARGET" "$DIRECTORY" "$PORT" "$DOWNLOAD_ONLY"
    exit 0
fi
[ "$(uname -s)" = Linux ] || fail "Only Linux is supported"
[ "$(uname -m)" = x86_64 ] || fail "Prebuilt packages support x86_64; see README for source builds"
if [ "$DOWNLOAD_ONLY" = 0 ]; then
    [ "$(id -u)" = 0 ] || fail "Run as root; open a root shell with sudo -i first"
    [ "$TARGET" = client ] || [ -d /run/systemd/system ] || fail "Server installation requires a running systemd host"
    if [ "$SKIP_DEPS" = 0 ]; then
        command -v apt-get >/dev/null || fail "Automatic dependencies need apt-get; use --skip-deps with prerequisites installed"
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl git tar gzip coreutils iproute2 nftables passwd kmod
    fi
    if [ "$TARGET" != client ]; then
        if [ ! -c /dev/net/tun ] && command -v modprobe >/dev/null; then modprobe tun || true; fi
        [ -c /dev/net/tun ] || fail "TUN device missing; enable /dev/net/tun on the host or in VPS settings"
        for tool in ip nft systemctl useradd sysctl; do command -v "$tool" >/dev/null || fail "Missing prerequisite: $tool"; done
    fi
    for tool in git install getconf; do command -v "$tool" >/dev/null || fail "Missing prerequisite: $tool"; done
    glibc="$(getconf GNU_LIBC_VERSION)"
    [[ "$glibc" == 'glibc '* ]] || fail "Prebuilt packages require glibc, not musl"
    [ "$(printf '%s\n' 2.39 "${glibc#glibc }" | sort -V | head -n1)" = 2.39 ] || fail "Prebuilt packages require glibc >= 2.39 (Ubuntu 24.04+/Debian 13+); build from source on older hosts"
fi
for tool in curl sha256sum tar mktemp; do command -v "$tool" >/dev/null || fail "Missing prerequisite: $tool"; done
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT
fetch() { curl --fail --show-error --location --retry 3 --proto '=https' --proto-redir '=https' --tlsv1.2 "$1" -o "$2"; }
asset="bproto-linux-x86_64.tar.gz"
fetch "$REPOSITORY/releases/download/$RELEASE/SHA256SUMS" "$work_dir/SHA256SUMS"
fetch "$REPOSITORY/releases/download/$RELEASE/$asset" "$work_dir/$asset"
awk -v name="$asset" '$2 == name {print}' "$work_dir/SHA256SUMS" > "$work_dir/$asset.sha256"
[ "$(wc -l < "$work_dir/$asset.sha256")" -eq 1 ] || fail "Release checksum entry missing or duplicated"
(cd "$work_dir" && sha256sum --check "$asset.sha256")
tar -tzf "$work_dir/$asset" dist/bin/vpn-server dist/bin/bproto > /dev/null
if [ "$DOWNLOAD_ONLY" = 1 ]; then
    [ ! -e "$DIRECTORY" ] || fail "Download destination already exists; choose a new empty path"
    mkdir -p "$DIRECTORY"
    cp "$work_dir/$asset" "$work_dir/$asset.sha256" "$DIRECTORY/"
    printf 'Verified download: %s/%s\n' "$DIRECTORY" "$asset"
    exit 0
fi
if [ -e "$DIRECTORY" ]; then
    [ -d "$DIRECTORY/.git" ] || fail "Destination exists but is not a standalone checkout"
    origin="$(git -C "$DIRECTORY" remote get-url origin)"
    [[ "$origin" == "$REPOSITORY" || "$origin" == "$REPOSITORY.git" ]] || fail "Existing checkout has a different origin"
    [ -z "$(git -C "$DIRECTORY" status --porcelain --untracked-files=normal)" ] || fail "Checkout has local changes; preserve them before updating"
    git -C "$DIRECTORY" fetch origin main
    git -C "$DIRECTORY" merge --ff-only origin/main
else
    git clone --depth 1 --branch main "$REPOSITORY.git" "$DIRECTORY"
fi
# Current installation scripts plus an explicitly pinned, checksum-verified binary release.
tar -xzf "$work_dir/$asset" -C "$DIRECTORY" dist/bin/vpn-server dist/bin/bproto
arguments=("$TARGET" --no-build --port "$PORT")
[ "$NO_START" = 0 ] || arguments+=(--no-start)
bash "$DIRECTORY/install.sh" "${arguments[@]}"
printf '\nCheckout: %s\nNext steps: check NAT interface, public endpoint and firewall; read README.md.\n' "$DIRECTORY"
