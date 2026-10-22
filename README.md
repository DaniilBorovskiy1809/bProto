# bProto

A UDP-based VPN: a Rust protocol core, a server, a Linux client, a C-ABI library
for Android and iOS, and a web control panel.

Everything is carried over UDP. Authentication binds a routing tag and a
time-windowed MAC to the pre-shared key issued by the panel; the datagram header
is authenticated as AEAD associated data and never carries plaintext payload.

There are two ways to run it, and they are one server binary with one flag:

* **plain** — our own three-datagram handshake. Opaque UDP, real crypto, no
  disguise.
* **masquerade** — the same session, but the handshake is a browser-shaped TLS
  `ClientHello` for the donor site, and anyone we do not recognise is forwarded
  to the donor and answered by the donor. Set `masquerade.enabled = true` and
  pin `donor.addr`.

**Start here: [`docs/INSTALL.md`](docs/INSTALL.md)** — the install guide for the
server, the client and the panel.

Other reading:

* [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — the wire format, exactly as built;
* [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — what this does and does not
  protect against;
* [`docs/PLAN.md`](docs/PLAN.md) — the engineering plan, and what is left;
* [`docs/BUILD-CLIENTS.md`](docs/BUILD-CLIENTS.md) — building the Linux, Android
  and iOS clients, and what each one still lacks.

## Repository layout

```
crates/vpn-core     Protocol core: packet format, crypto, handshake, TLS
                    ClientHello/ServerHello codec, masquerade classifier.
                    Pure: no sockets, no async, no allocation of I/O.
crates/vpn-rt       The async datapath both peers run: session table, UDP,
                    keepalive and reaping. One ACK/CUBIC implementation.
crates/vpn-client   The client library. vpn-cli and the phone FFI are both
                    thin wrappers over this.
crates/vpn-server   The server: the Node (sessions, address pool, acceptor,
                    donor relay), the panel control plane, the binary.
crates/vpn-tun      Linux TUN + NAT + route plumbing (server and client).
crates/vpn-cli      Client (`bproto`): check / connect / up / import / genkey.
crates/vpn-ffi      C-ABI surface (`libbproto.so`/`.a`) + JNI bridge for Android.
apps/android/       Android client: VpnService + the JNI bindings.
apps/ios/           iOS client: Packet Tunnel Provider + the C header.
panel/              Control panel: axum + SQLite backend, React frontend, Caddy.
docs/               INSTALL, BUILD-CLIENTS, PLAN, PROTOCOL, THREAT-MODEL.
build_app.sh        build every artifact into ./dist.
run.sh              run the server / client / panel / demo from the source tree.
install.sh          install the server, client or panel on this machine.
```

The split is the point. `vpn-core` has no I/O at all, so the protocol can be
tested without a socket; `vpn-rt` holds the one copy of the transport state
machine, so the client and the server cannot drift apart; `vpn-client` is the
whole client, so the CLI and the phones share one implementation instead of
two.

## Build

Requires Rust **1.88+** (edition 2024). `just` is optional.

```sh
./build_app.sh                # everything -> ./dist (binaries, C-ABI libs, panel)
./build_app.sh --check        # the CI gate: fmt + clippy + tests
./build_app.sh --android      # + Android .so x3 ABIs and a debug APK (dist/apk/)
./run.sh demo                 # local server + client, real handshake, no root
sudo ./install.sh server      # install the server here (systemd, TUN, NAT)
```

Manual build:

```sh
cargo build --release -p vpn-server -p vpn-cli
cargo test --workspace                  # 157 tests
cargo test -p bproto --features jni     # + 6 for the Android JNI/pump tier
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

`run.sh demo` is the fastest way to see it work: it generates a throwaway key
pair, starts a server on loopback and connects a real client to it.

Run the server (the TUN device and the `nft` ruleset need root or
`CAP_NET_ADMIN` — see `docs/INSTALL.md`):

```sh
sudo cargo run --release -p vpn-server -- --config server.toml --datapath
```

## Masquerade

The server borrows a donor site's identity. Clients authenticate by putting a
32-byte label in the `ClientHello`'s `session_id` field — the exact length a
browser sends in middlebox compatibility mode, so the handshake does not change
length:

```
session_id[0..8]  = HMAC-SHA256(K_tag, user_id)[0..8]              // routing tag
session_id[8..32] = HMAC-SHA256(psk, tag || client_random ||
                                x25519_pub || T)[0..24]            // label MAC
T = floor(unix_time / 300)
```

The server reads it and chooses one of two fates, and there is no third:

* the label verifies → intercept. The reply is a TLS `ServerHello` carrying our
  handshake data in an [RFC 8701 GREASE](https://www.rfc-editor.org/rfc/rfc8701)
  extension, which real peers are required to ignore.
* anything else — absent, malformed, unknown, forged, stale → the bytes are
  forwarded to the donor verbatim and the donor's answer comes back. The prober
  completes a genuine handshake with the donor and receives the donor's real
  certificate.

Both fates are covered by tests in `crates/vpn-server/tests/e2e.rs`.

We build the `ClientHello` ourselves rather than patching a TLS library. That
means no fork to keep up with, and the fingerprint is data (`HelloProfile`), not
a compiled-in dependency.

Enabling it requires a pinned donor address, and configuration validation
refuses to start without one:

```toml
[donor]
sni  = "www.cloudflare.com"
addr = "1.1.1.1:443"      # required by masquerade; survives DNS poisoning

[masquerade]
enabled    = true
listen_addr = "0.0.0.0:443"
```

Masquerade and the plain datapath are two front-ends for the same node, so the
mode picks the listener: a session has to keep talking to the port it shook
hands with.

## Control plane

The server **pulls** keys from the panel and **pushes** traffic deltas to it.
The panel never reaches the server, so the server needs no inbound connectivity
and losing the panel is not fatal: it keeps serving with the last table it got,
warns, and retries.

## Status

Working and tested:

* the 12-byte packet header, inner framing, and the AEAD data path
  (ChaCha20-Poly1305, per-direction nonce prefixes, replay window);
* the handshake in both wire shapes — native `HELLO`/`HELLO_ACK`, and the
  masquerade `ClientHello`/`ServerHello` — over X25519 + HKDF, with a
  constant-time label MAC on a +-5-minute window;
* the donor relay: one upstream socket per peer, so QUIC's 4-tuple survives;
* the server data path: TUN device, IP pool (`10.66.0.0/24`), routing by inner
  destination, NAT via `nft`, address lease and release;
* one session per user: a reconnect evicts the previous session and releases its
  address instead of leaking it;
* CUBIC congestion control, ACK ranges, RTT/loss detection, keepalive;
* the control panel (**bUI**): admin login with argon2id passwords and revocable
  sessions, inbounds, clients, per-device keys, QR codes, subscription links
  (`/sub/<id>` as base64, list or JSON), subscriptions imported from another
  panel, a traffic dashboard fed by server session reports, an audit log;
* `bproto import 'bproto://import/...'` — the panel's key URI is the same string
  the mobile library accepts, so a scanned key works without any file;
* the C ABI and JNI bridge (`crates/vpn-ffi`), the Android `VpnService` app, and
  the iOS Packet Tunnel Provider — see
  [`docs/BUILD-CLIENTS.md`](docs/BUILD-CLIENTS.md).

Not implemented, and not faked: FEC, live rekey / key update, post-quantum
rekey, and a Windows/macOS desktop client. The Android app has been exercised
against a real `VpnService` only on an emulator, never on a phone; the iOS
provider has not been built with Xcode. See `docs/PLAN.md`.
