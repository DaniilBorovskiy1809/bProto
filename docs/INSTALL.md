# Installing bProto

This is the practical, tested install guide. Two halves:

* a **server** on a public VPS (Rust binary, systemd unit, TUN + NAT), and
* a **client** on your own machine (`bproto` CLI today; Android/iOS/desktop build
  on the same library).

A **control panel** (key issuing, QR codes, subscription links, stats) is
optional and described in §5.

Read §0 before you start — it is the honest list of what works today.

---

## 0. What works today, and what does not

| | status |
|---|---|
| UDP datagram format, ChaCha20-Poly1305, replay window | **works, tested** |
| Native `HELLO`/`HELLO_ACK` handshake, X25519 + HKDF key schedule | **works, tested** |
| Server: TUN device, IP pool, routing, NAT (nft), systemd unit | **works** (verified end to end over loopback) |
| Client: TUN, address, default-route takeover with rollback | **works** (needs root/CAP_NET_ADMIN) |
| CUBIC + ACK ranges + RTT + keepalive | **works** |
| Control panel: login, inbounds, keys, QR, subscriptions, stats | **works, 37 tests** |
| Panel → server key push (admin API) | **not wired** — see §5.5, you copy the key once |
| Automatic DNS configuration on the client | **not implemented** — see §4.6 |
| Android app | **runs end to end on an emulator** (API 35): handshake, `tun0` lease, traffic through the tunnel; not yet run on a phone — see §6 |
| iOS app | **scaffolded only** — Swift never compiled (no macOS) — see §7 |
| Stealth / DPI evasion ("mode B": donor masquerade, craftls ClientHello) | **not implemented**, documented in §12 |
| FEC, post-quantum rekey, live key update | **not implemented** (`Error::Unimplemented`) |

In one sentence: this is a working, encrypted, tested VPN **protocol and
server**, with a working control panel. It is not yet a DPI-resistant product,
and you have to wire the panel→server key sync by hand.

---

## 1. Requirements

**Server** (Linux; the data path is Linux-only today):

* a VPS with a public IPv4 address, Ubuntu 22.04+/Debian 12+ or equivalent;
* kernel with `tun` (`modprobe tun` — present on every normal VPS kernel);
* `iproute2` (`ip`) and `nftables` (`nft`);
* root, or the `CAP_NET_ADMIN` capability (the shipped unit uses the capability,
  not uid 0);
* one open UDP port (443 is a good choice).

**Client**: Linux with `iproute2`, and root for the `up` mode.

**Build machine**: Rust **1.88 or newer** (`rustup toolchain install stable`).
Edition 2024 is used throughout; `just` is optional.

**Panel (optional)**: Docker + Docker Compose, or Rust + Node 20 with `pnpm`.

Install the server-side packages:

```sh
sudo apt update
sudo apt install -y iproute2 nftables ca-certificates
```

---

## 2. Build

Three scripts cover everything; plain `cargo` works just as well.

```sh
git clone <your-fork-or-checkout> bProto
cd bProto

./build_app.sh --check     # CI gate: fmt + clippy + tests
./build_app.sh             # release build of everything, staged into ./dist
```

`./dist` after a successful build:

```
dist/bin/vpn-server          server
dist/bin/bproto              client
dist/lib/libbproto.so        C-ABI shared library (Android / desktop)
dist/lib/libbproto.a         C-ABI static library (iOS)
dist/panel/panel             control panel backend
dist/panel/dist/             control panel frontend (static)
```

`build_app.sh` flags: `--debug`, `--check`, `--android`, `--ios`, `--no-panel`,
`--no-ffi`. To skip the scripts:

```sh
cargo build --release -p vpn-server -p vpn-cli

cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace          # 120 tests, 1 ignored (reaches a real donor)
```

Want to see it work before installing anything? `./run.sh demo` starts a local
server and connects a real client to it, on loopback, no root:

```
tunnel up:
  assigned address : 10.66.0.2
  MTU              : 1251
```

---

## 3. Server

Everything below is done on the VPS, as a user with `sudo`.

**Fast path.** This one command does §3.2–3.5 for you: it installs the binary,
creates the `bproto` user, generates `/etc/bproto/server.toml` *and* a matching
`/etc/bproto/user1.client.toml` with real keys, enables IPv4 forwarding, installs
the systemd unit and starts the service.

```sh
sudo ./install.sh server --port 443
```

Then do §3.1 (firewall) and check `nat_interface` + the "still to do" list it
prints. The manual steps follow, and are what `install.sh` is doing.

### 3.1 Open the UDP port

```sh
sudo ufw allow 443/udp
# or with nftables directly:
#   nft add rule inet filter input udp dport 443 accept
```

Do **not** open the admin port (`127.0.0.1:9100`); it is loopback-only by design.

### 3.2 Generate the keys

```sh
# Routing tag key: shared by every user of this deployment, and must also be in
# the panel's BPROTO_TAG_KEY.
openssl rand -hex 32            # -> tag_key

# One pre-shared key per user:
openssl rand -hex 32            # -> psk for user 1
```

`bproto genkey` prints the same thing if you prefer a single tool.

### 3.3 Write `/etc/bproto/server.toml`

Start from the example and edit it:

```sh
sudo install -d -m0750 /etc/bproto
sudo install -m0600 crates/vpn-server/config/server.toml /etc/bproto/server.toml
sudoedit /etc/bproto/server.toml
```

The file that matters:

```toml
# UDP listener. :443 with a UDP flow looks like HTTP/3 to a passive observer.
listen_addr = "0.0.0.0:443"

# MUST equal the panel's BPROTO_TAG_KEY and every client's tag_key.
tag_key = "<openssl rand -hex 32>"

[tun]
name = "bproto0"
address = "10.66.0.1"          # the server's own address inside the tunnel
netmask = "255.255.255.0"      # clients get 10.66.0.2, .3, ...
mtu = 1280
nat_interface = "eth0"         # <-- YOUR outbound interface, see below

[admin]
listen_addr = "127.0.0.1:9100"
token = "<openssl rand -hex 32>"

[[users]]
id = 1
psk = "<openssl rand -hex 32>"
```

Find the outbound interface name:

```sh
ip route get 1.1.1.1 | head -1     # -> "... dev eth0 src 203.0.113.10"
```

If `nat_interface` is omitted, the server warns at startup and clients can reach
the server but **not** the internet.

Validate before starting:

```sh
sudo /usr/local/bin/vpn-server --check-config --config /etc/bproto/server.toml
# configuration OK
```

### 3.4 Enable IPv4 forwarding (persistent)

The server will not route client traffic without this. It is a prerequisite
rather than something the process sets, because the unit keeps
`ProtectKernelTunables=yes`.

```sh
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-bproto.conf
sudo sysctl --system
sysctl net.ipv4.ip_forward       # -> net.ipv4.ip_forward = 1
```

### 3.5 Install and start

`sudo ./install.sh server` does this section for you. By hand:

```sh
sudo install -m0755 target/release/vpn-server /usr/local/bin/vpn-server
sudo useradd --system --no-create-home --shell /usr/sbin/nologin bproto
sudo install -m0644 crates/vpn-server/deploy/bproto-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bproto-server
```

The unit runs as `bproto` with **only** `CAP_NET_ADMIN` (for the TUN device and
the `nft` ruleset), a read-only filesystem, and `--datapath`. The process never
runs as root.

### 3.6 Verify

```sh
systemctl status bproto-server --no-pager
journalctl -u bproto-server -n 30 --no-pager
```

You should see:

```
configuration loaded listen=0.0.0.0:443 donor=www.cloudflare.com users=1 tunnel=10.66.0.0/24
listener up addr=0.0.0.0:443
TUN up name="bproto0" addr=10.66.0.1 mtu=1280
NAT ruleset installed iface="eth0"
```

Also check the interface and the socket:

```sh
ip -brief addr show bproto0     # UP, 10.66.0.1/24
sudo ss -lunp | grep 443
```

When a client connects you will see the handshake accepted and, every 60 s, a
stats line with `sessions=1`.

---

## 4. Client (Linux)

### 4.1 Get a configuration

`sudo ./install.sh all` on the server host already wrote a working client
config to `/etc/bproto/user1.client.toml` (it needs one edit if the detected
address is not your public one). Copy it over and skip to §4.2.

Otherwise, let the panel produce a key URI (§5.4) and import it:

```sh
bproto import 'bproto://import/eyJ2IjoxLC...' --out client.toml
```

…or write `client.toml` by hand from the example:

```sh
cp crates/vpn-cli/config/client.example.toml client.toml
# edit: server, user_id, psk, tag_key (and mtu, if you changed the server's)
```

### 4.2 Validate

```sh
bproto --config client.toml check
# configuration OK: server=203.0.113.10:443 donor=www.cloudflare.com mtu=1251 user_id=1
```

### 4.3 Connect without touching the network (no root)

This performs the real handshake and prints the negotiated result, but installs
no routes and needs no privileges:

```sh
bproto --config client.toml connect --seconds 5
```

```
tunnel up:
  assigned address : 10.66.0.2
  MTU              : 1251
```

If this fails with `handshake timeout`, the problem is the server, the firewall
or the keys — not the TUN layer. Debug here first.

You can also point at a URI directly, with no file at all:

```sh
bproto --uri 'bproto://import/...' connect --seconds 5
```

### 4.4 Bring the tunnel up (root)

```sh
sudo bproto --config client.toml up
```

This does exactly four things, in this order, and undoes them on Ctrl-C:

1. performs the handshake and learns the assigned address;
2. creates the TUN device (`bproto0` by default) and assigns `<assigned>/24`;
3. pins a host route to the **server's public IP** via your current gateway, so
   the tunnel's own UDP flow survives the next step;
4. adds a default route through the tunnel with `metric 50`, below the usual
   `metric 600` of DHCP/Wi-Fi, so it wins while the original route stays in the
   table.

Useful flags:

```sh
sudo bproto up --iface bproto0          # choose the interface name
sudo bproto up --no-default-route       # configure the interface only
```

### 4.5 Verify

In another terminal:

```sh
ip -brief addr show bproto0             # UP, 10.66.0.2/24
ip route show default                   # default dev bproto0 metric 50, plus your original
curl -s https://ifconfig.me             # should print the SERVER's public IP
journalctl -k -f                        # (optional) watch packets leave
```

`dig`/`curl` failing with "no route"/timeouts while `ping 10.66.0.1` works means
your DNS is still pointing at your local router — see the next section.

### 4.6 DNS

**Automatic DNS configuration is not implemented.** When the default route moves
into the tunnel, your existing resolver (usually your router) becomes
unreachable, so names stop resolving. Pick one:

systemd-resolved:

```sh
sudo resolvectl dns bproto0 1.1.1.1
sudo resolvectl domain bproto0 '~.'
```

plain `/etc/resolv.conf`:

```sh
printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\n' | sudo tee /etc/resolv.conf
```

Both are undone when the tunnel comes down (`resolvectl revert bproto0`; restore
your original `/etc/resolv.conf` backup).

### 4.7 Running it as a service

`bproto up` is designed to be run under systemd as a simple unit (`Type=simple`,
`Restart=always`), with `AmbientCapabilities=CAP_NET_ADMIN` instead of
`User=root`. It restores the routes on `SIGTERM`/Ctrl-C, which is what systemd
sends on `systemctl stop`. A shipped client unit is stage-2 work.

---

## 5. Control panel (optional)

The panel — **bUI** — issues keys, renders QR codes, serves subscription links
to clients, imports subscriptions from another bProto panel, and shows traffic
stats. It is a separate Rust service (axum + SQLite) plus a React frontend; Caddy
terminates TLS. [`panel/README.md`](../panel/README.md) has the data model, the
full API and the reporting protocol.

### 5.1 With Docker Compose (recommended)

`./install.sh panel --domain panel.example.com` writes `panel/.env` (reusing the
server's `tag_key` when `/etc/bproto/server.toml` exists) and runs compose. By
hand:

```sh
cd panel

BPROTO_DOMAIN=panel.example.com \
BPROTO_TAG_KEY=<the same tag_key as server.toml> \
BPROTO_ADMIN_PASSWORD="$(openssl rand -base64 24)" \
  docker compose up -d --build
```

Point `panel.example.com`'s DNS at this host **before** starting: Caddy obtains a
Let's Encrypt certificate on first boot. Ports 80 and 443 must be reachable.

The backend is never published; Caddy proxies `/api/*` and `/sub/*` to it and
serves the built frontend.

### 5.2 Without Docker (development)

```sh
# backend
cd panel/backend
BPROTO_TAG_KEY=$(openssl rand -hex 32) cargo run --release
# on first start it creates admin 'admin' and logs the password ONCE:
#   WARN created default admin 'admin' with password: <random>

# frontend (another terminal)
cd panel/frontend
pnpm install && pnpm dev        # http://127.0.0.1:5173, proxying /api to :8080
```

Environment variables the backend reads:

| variable | meaning |
|---|---|
| `BPROTO_TAG_KEY` | **required**, 32-byte hex; the routing tag key |
| `BPROTO_DB` | SQLite URL, default `sqlite://panel.db?mode=rwc` |
| `BPROTO_LISTEN` | default `127.0.0.1:8080` |
| `BPROTO_ADMIN_PASSWORD` | password for the bootstrap `admin`; random if unset |
| `BPROTO_INTERNAL_TOKEN` | bearer token for `/internal/v1/sessions/report` |
| `BPROTO_ALLOW_PRIVATE_SUBS` | allow subscriptions to private IPs (off by default) |

### 5.3 First login

Open `https://panel.example.com`, log in as `admin` with the password you set (or
the one in the log), and **change it immediately** — either on the **Settings**
page (its change-password form signs out the account's other sessions) or via
`POST /api/auth/password`.

### 5.4 Create an inbound and issue a key

1. Add an **inbound**: the server's `IP:port` (e.g. `203.0.113.10:443`), the
   donor SNI (`www.cloudflare.com`) and a fingerprint (`chrome112`).
2. Create a **user/client** and issue a **key** for that inbound.
3. The panel shows a QR code and a URI:

   ```
   bproto://import/eyJ2IjoxLCJzZXJ2ZXIiOiIyMDMuMC4xMTMuMTA6NDQzIi...
   ```

   Import it on any client: `bproto import '<uri>' --out client.toml`, or scan it
   with the mobile app (which passes the same string to Rust).

   The same client also gets a **subscription URL** (`/sub/<sub_id>`, shown on
   the Clients and Subscriptions pages) that importers can poll; the panel
   re-issues its configs from the inbound on every fetch, and merges in the
   configs of any remote subscriptions you attach to that client.

`user_id` in the URI is the panel's user id, and the URI contains the `psk` the
panel generated — that pair is what `server.toml` needs next.

### 5.5 Wiring the panel's keys into the server (one manual step)

The panel is the source of truth for keys; the server is not yet subscribed to
it (the admin API in `crates/vpn-server/src/admin.rs` is a guarded stub, and the
gRPC push is stage-2 work). So after issuing a key, copy its identity into
`server.toml` **once**:

```sh
# The URI contains both values:
bproto import '<uri>'          # prints user_id and psk
```

```toml
[[users]]
id  = 1                        # the uid from the URI
psk = "<psk printed above>"
```

Then:

```sh
sudo systemctl restart bproto-server
```

Revocation is the reverse: delete the block (or the user with
`POST /api/keys/{id}/revoke` in the panel) and restart the server. Do this before
you rely on the panel for anything security-critical, and remember that a
restart is required — the server keeps the tag table in memory only.

---

## 6. Android

There **is** an app in the tree: `apps/android/` (a `VpnService`, one screen, and
the JNI bindings). The full walkthrough lives in
[`apps/android/README.md`](../apps/android/README.md); this is the short form.

Build the native library and stage it into the Gradle project:

```sh
cargo install cargo-ndk                 # one-off
export JAVA_HOME=/path/to/jdk17
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$(ls "$ANDROID_HOME/ndk" | sort -V | tail -1)"

./build_app.sh --no-panel --android     # implies --features jni; also builds the APK
adb install -r dist/apk/bproto-0.1.0-debug.apk
```

`--features jni` is not optional: the Kotlin entry points
(`Java_dev_bproto_Bproto_*`) are compiled only with that feature, so a plain
`cargo ndk ... build` produces a library the app cannot call. If `gradle` is not
on `PATH`, `--android` stops after staging the native libraries; run
`cd apps/android && gradle wrapper && ./gradlew assembleDebug` yourself.

Four steps make the tunnel carry traffic, and the order matters:
`Bproto.connect()` (handshake, so the server leases an address) →
`protect(Bproto.socketFd(handle))` (or the encapsulated packets are routed back
into our own tunnel) → `Builder.addAddress(leased).establish()` →
`Bproto.pump(handle, pfd.fd)` on a worker thread until `Bproto.stop()`.

State: the Rust side is compile-checked for all three Android ABIs and its
packet pump is covered by a test in `crates/vpn-ffi` that runs the real tunnel
over a socketpair. The debug APK builds and signs cleanly
(`dist/apk/bproto-0.1.0-debug.apk`, `minSdk 26`, three ABIs). It has now been run
**end to end on an API 35 x86_64 emulator**: launch, consent, handshake, `tun0`
with the leased `10.66.0.2`, and a ping from the guest to the server's
`10.66.0.1` answered through the tunnel (3/3, server `sessions=1 unknown=0`). It
has **not** been run on a phone, so treat the first device run as a test.

One caveat that came out of that run: the builder asks for an IPv6 address and a
`::/0` route so v6 cannot leak in the clear, but this emulator's framework
rejects an IPv6 address in its native address-config path (`VpnJni: Invalid
address`). The service therefore treats IPv6 capture as best effort: it retries
IPv4-only and puts `warning: IPv6 not captured (…)` in the status line rather
than failing the connect. Details in `apps/android/README.md`.

## 7. iOS

Same library, static this time. Needs macOS + Xcode:

```sh
./build_app.sh --no-panel --ios     # dist/ios/libbproto.a (device + simulator)
```

The provider and the C header are in `apps/ios/`:
`BprotoTunnelProvider.swift` (`NEPacketTunnelProvider`) and `Bproto.h`. Add both
to a Packet Tunnel Provider target, link `dist/ios/libbproto.a` into it, and
hand the `bproto://` key over through `providerConfiguration`. Step-by-step:
[`apps/ios/README.md`](../apps/ios/README.md).

The tunnel needs iOS 16+ deployment: the provider uses the `async` overrides of
`startTunnel`/`stopTunnel`. iOS is the reason `bproto_recv_timeout` exists — the
receive loop needs a non-blocking way to notice `stopTunnel`.

State: written, never compiled (no macOS here).

## 8. Desktop

Today the desktop client **is** the `bproto` CLI (§4). A Tauri GUI and a
privileged-service/unprivileged-UI split are stage-2 items; do not run a GUI as
root.

---

## 9. Tests and quality gates

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                     # 121 tests, 1 ignored
cargo test -p bproto --features jni        # + 6 (JNI tier + the Android pump)
cargo test -p vpn-core --test tunnel_e2e   # real client vs real server over UDP

cd panel/backend && cargo test && cargo clippy --all-targets -- -D warnings
cd panel/frontend && pnpm build
```

The ignored test (`crates/vpn-core/tests/censor_gets_real_site.rs`) reaches a real
donor site and is skipped by default; run it with `-- --include-ignored` when you
have the network for it.

`crates/vpn-core/tests/tunnel_e2e.rs` is the important one: it starts a real
`ServerNode` on a loopback UDP socket, connects a real client `Tunnel` to it, and
checks handshake, address lease, bidirectional IP traffic, distinct addresses per
user, and that a prober with the wrong key never gets a session.

---

## 10. Troubleshooting

| symptom | cause | fix |
|---|---|---|
| `configuration OK` but the service exits at once | `--datapath` missing, or no TUN/NAT permissions | the unit passes `--datapath`; check `journalctl -u bproto-server` |
| `need root or CAP_NET_ADMIN` | run as a user without the capability | use `sudo` (client) or the shipped unit (server) |
| client hangs, then `handshake timeout` | wrong `psk`/`tag_key`, wrong port, firewall | re-check keys; the server logs `rejected` counts; try `connect` on the server host itself against `127.0.0.1` |
| tunnel connects, `ping 10.66.0.1` works, internet does not | `net.ipv4.ip_forward=0` or `nat_interface` wrong/absent | §3.4, and set `nat_interface` to the interface from `ip route get 1.1.1.1` |
| names do not resolve | DNS still points at the local router | §4.6 |
| `nft failed: ... Operation not permitted` | service lacks `CAP_NET_ADMIN` | keep `AmbientCapabilities=CAP_NET_ADMIN` in the unit |
| first client gets `10.66.0.2` every time and the second user gets `10.66.0.3` | correct: the same user reconnecting reuses the lease | nothing to do |
| client was killed and the routes are wrong | only happens on `SIGKILL`; `Drop` cannot run | `sudo ip route flush dev bproto0; sudo ip link del bproto0` |
| panel shows a blank page behind Caddy | the frontend volume was not populated | `docker compose up -d --build` (the `frontend` service fills it) |
| panel API 404s | Caddy config must keep the `/api` prefix | use `handle`, not `handle_path` (see `panel/Caddyfile`) |

---

## 11. Security notes

* `client.toml` and `server.toml` contain secrets. `chmod 600` them; the shipped
  server config is installed as `0600` in `/etc/bproto`.
* `tag_key` is deployment-wide. Rotating it invalidates every client at once.
* The admin API binds loopback only and **refuses** to start on a public address
  with an empty token; do not defeat that with a reverse proxy.
* The server drops root and runs with one capability. Keep it that way.
* Never expose `:9100`, and never put the panel's SQLite file on a shared path.

---

## 12. About stealth (read before trusting this against a censor)

Today bProto is an **honest** protocol: a real handshake between two parties,
with random-looking UDP payloads. There is no disguise. Any censor that
fingerprints or blocks unknown UDP flows will classify it on sight. Use it
where you already have a working path, not to *get* one.

The design that fixes that is "mode B" and is specified but **not implemented**:

* authenticate inside the TLS `session_id` field, exactly 32 bytes, so no
  handshake frame changes length (this closes the Aparecium `ServerFinished`
  vector);
* borrow a real donor site's certificate by relaying its handshake, and forward
  or synthesize its `NewSessionTicket` instead of dropping it (the second
  Aparecium vector);
* send the ClientHello with `craftls`, patched as described in
  `crates/craftls/PATCH.md` — a two-file change;
* shape datagram sizes to the donor's distribution (the `FLAG_SPIN` / size-bucket
  machinery is already in the packet format).

The same 32-byte label the native handshake uses (§4 of `docs/PROTOCOL.md`) is
what goes into `session_id`, so switching a client to mode B is a configuration
change, not a protocol break. Until then, treat `stealth = "off"` as the truth on
the wire.
