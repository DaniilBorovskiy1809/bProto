# bProto

A non-blocking, UDP-based VPN protocol and the ecosystem around it: a Rust
protocol core, a server, a Linux client, a C-ABI library for Android/iOS, and a
web control panel.

Everything is carried over UDP. Authentication binds a routing tag and a
time-windowed MAC to the pre-shared key issued by the panel; the datagram header
is authenticated as AEAD associated data and never carries plaintext payload.

**Start here: [`docs/INSTALL.md`](docs/INSTALL.md)** — the tested install guide
for the server, the client and the panel.

Other reading:

* [`docs/PLAN.md`](docs/PLAN.md) — the full engineering plan and phase breakdown;
* [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — the wire format, exactly as built;
* [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — what this does and does not
  protect against;
* [`docs/BUILD-CLIENTS.md`](docs/BUILD-CLIENTS.md) — how to build the Linux,
  Android and iOS clients, and what each one still lacks;
* [`crates/craftls/PATCH.md`](crates/craftls/PATCH.md) — the two-file patch that
  makes the `session_id` label carrier possible (stage 2).

## Repository layout

```
crates/vpn-core    Protocol core: packet format, crypto, handshake, session, CUBIC
crates/vpn-tun     Linux TUN + NAT + route plumbing (shared by server and client)
crates/vpn-server  Server binary: TUN + NAT, handshake acceptor, IP pool
crates/vpn-cli     Client (`bproto`): check / connect / up / import / genkey
crates/vpn-ffi     C-ABI surface (`libbproto.so`/`.a`) + JNI bridge for Android
crates/craftls     craftls fork + the session_id patch (PATCH.md)
apps/android/      Android client: VpnService + the JNI bindings
apps/ios/          iOS client: Packet Tunnel Provider + the C header
panel/             Control panel: axum + SQLite backend, React frontend, Caddy
docs/              INSTALL.md, BUILD-CLIENTS.md, PLAN.md, PROTOCOL.md, THREAT-MODEL.md
build_app.sh       build every artifact into ./dist
run.sh             run the server / client / panel / demo from the source tree
install.sh         install the server, client or panel on this machine
```

## Build

Requires Rust **1.88+** (edition 2024). `just` is optional.

Three scripts do the common work; plain `cargo` works too.

```sh
./build_app.sh                # everything -> ./dist (binaries, C-ABI libs, panel)
./build_app.sh --check        # the CI gate: fmt + clippy + tests
./build_app.sh --android      # + Android .so x3 ABIs and a debug APK (dist/apk/)
./run.sh demo                 # local server + client, real handshake, no root
sudo ./install.sh server      # install the server here (systemd, TUN, NAT)
```

| script | what it does |
|---|---|
| `build_app.sh` | `--debug`, `--check`, `--android`, `--ios`, `--no-apk`, `--no-panel`, `--no-ffi` |
| `run.sh` | `demo`, `server`, `check-config`, `client`, `panel`, `frontend`, `check`, `test`, `e2e` |
| `install.sh` | `server`, `client`, `all`, `panel`, `uninstall`; `--prefix`, `--port`, `--donor`, `--domain` |

`run.sh demo` is the fastest way to see it work: it generates a throwaway key
pair, starts a server on loopback and connects a real client to it.

Manual build:

```sh
cargo build --release -p vpn-server -p vpn-cli
cargo test --workspace            # 121 tests, 1 ignored
cargo test -p bproto --features jni   # + 6 for the Android JNI/pump tier
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

With `just`:

```sh
just check          # fmt + clippy, the CI gate
just test           # unit + integration tests
just build          # vpn-server + bproto release binaries
just run-server     # start the server with the example config
```

Run the server (needs the TUN device and the `nft` ruleset, so root or
`CAP_NET_ADMIN` — see `docs/INSTALL.md` §3):

```sh
sudo cargo run --release -p vpn-server -- --config crates/vpn-server/config/server.toml --datapath
```

## Status

Stage 1 (MVP) is functional end to end. Working and tested today:

* the 12-byte packet header, inner framing, and the AEAD data path
  (ChaCha20-Poly1305, per-direction nonce prefixes, replay window);
* the native three-datagram handshake: `HELLO`/`HELLO_ACK`, X25519, HKDF key
  schedule, constant-time label MAC with a ±5-minute window;
* the server data path: TUN device, IP pool (`10.66.0.0/24`), routing by inner
  destination, NAT via `nft`, address lease/release on idle;
* the Linux client: TUN setup, full-tunnel route takeover with rollback, DNS
  left to the operator (documented);
* CUBIC congestion control, ACK ranges, RFC 9002 RTT/loss detection, keepalive;
* the control panel (**bUI**): admin login with argon2id passwords and revocable
  sessions, inbounds, clients, per-device keys, QR codes, subscription links
  (`/sub/<id>` as base64, list or JSON), subscriptions imported from another
  panel, a traffic dashboard fed by server session reports, and an audit log
  (37 tests + `panel/smoke.sh`);
* `bproto import 'bproto://import/...'` — the panel's key URI is the same string
  the mobile library accepts, so a scanned key works without any file;
* the client library for phones: a C ABI plus a JNI bridge
  (`crates/vpn-ffi`), the Android `VpnService` app (its debug APK builds and
  signs into `dist/apk/`, and has been run end to end on an emulator — handshake,
  `tun0` lease, and traffic through the tunnel) and the iOS Packet Tunnel
  Provider in `apps/` — see [`docs/BUILD-CLIENTS.md`](docs/BUILD-CLIENTS.md).

Not yet implemented (clear `Unimplemented` errors, no silent stubs): the
DPI-evasion "mode B" (donor masquerade, craftls-backed ClientHello), FEC, live
rekey / key update, post-quantum rekey, and a Windows/macOS desktop client.
The Android app has been exercised against a real `VpnService` only on an
emulator, never on a phone; the iOS provider has not been built with Xcode; the
native library they call is compile-checked and tested. The panel does
not yet push keys to the server; §5.5 of `docs/INSTALL.md` describes the one
manual step. See `docs/PLAN.md` for the order these land in.

> bProto is an **honest** protocol today: real handshake, opaque UDP payloads, no
> disguise. It is not yet safe against a censor that fingerprints unknown UDP
> flows. See `docs/INSTALL.md` §12.
