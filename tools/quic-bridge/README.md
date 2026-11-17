# Experimental QUIC / HTTP3 carrier

The existing bProto protocol is carried unchanged as length-prefixed datagrams
inside the DATA frames of one authenticated HTTP/3 POST stream. aioquic provides
QUIC v1, TLS 1.3, QPACK and HTTP/3 framing. ALPN is h3; server Retry is enabled.
The Python server interoperates with the native Rust/Android HTTP3 carrier added below.

## Deployment

Requires Python 3.11+ and an operator-owned certificate/hostname.

```sh
python3 -m venv .venv
.venv/bin/pip install -r tools/quic-bridge/requirements.txt
# Set BPROTO_BRIDGE_TOKEN to the same private random 64-hex value on both hosts.
# Generate once: python3 -c 'import secrets; print(secrets.token_hex(32))'
.venv/bin/python tools/quic-bridge/bridge.py server /etc/bproto/quic-server.json
# On the client host:
.venv/bin/python tools/quic-bridge/bridge.py client /etc/bproto/quic-client.json
```

Copy and edit the example JSON files. No secret belongs in version control.
The server points to the existing native UDP listener. The native client points
to 127.0.0.1:14443; keep its original user/tag/PSK credentials.
The example server binds loopback; set listen_host explicitly for remote access.
The optional client `ca` field trusts a local test CA; hostname validation stays on.
Restart to apply config changes. Do not enable full-tunnel routing without pinning
the external QUIC endpoint route: the native client only knows the loopback endpoint.

Unauthenticated HTTP/3 requests receive a local operator-owned HTML page. This
does not borrow another website's certificate or forward to third-party sites.
Tokens supplement native bProto authentication, not replace it.

## Tests

```sh
.venv/bin/pip install coverage==7.13.1
.venv/bin/python -m coverage run --source=tools/quic-bridge -m unittest discover -s tests -p test_quic_bridge.py
.venv/bin/python -m coverage report --fail-under=70
```

Seven tests cover QUIC v1 + Retry, bidirectional UDP echo, the CLI client carrier
path, HTTP/3 GET fallback, wrong token, hostname rejection and fragmented framing.
Measured statement coverage: 80%. Integration tests use real UDP and temporary
certificates; they are not native bProto TUN/Internet or Android e2e tests.
No independent curl/Wireshark/DPI interoperability validation has been performed.

## Limitations

No browser fingerprint imitation, ECH, automatic domain fronting, Android QUIC,
reconnect, deployment agent or RKN certification. QUIC streams are reliable and
ordered; packet loss can delay later datagrams. Outbound queue/admission limits
need production load testing before public deployment. One carrier stream per
connection, one native client per local process. The native protocol and TLS
remain authenticated; a matching JA3 alone would not prove DPI indistinguishability.
100% RKN bypass is not guaranteed. A reachable authorized endpoint is required.


## Native Rust and Android HTTP/3

The former vpn-core QUIC placeholder is now a working h3/quinn client carrier.
Android binds the external UDP socket, protects its descriptor using VpnService,
and only then starts QUIC. The HTTP/3 POST /bproto carries framed native datagrams;
the inner bProto wire format is unchanged. JNI owns the runtime and cancels
connection tasks on close. Native buffers and QUIC flow-control windows are bounded.

Select QUIC / HTTP3 in panel Settings and export an Android key using existing
bProto credentials. The optional quic JSON object contains hostname, server_host,
server_port and token. It cannot coexist with tls or wss. The server still runs
tools/quic-bridge with BPROTO_BRIDGE_TOKEN. The panel's Apply button continues to
target the configured raw-TLS service; QUIC JSON must be deployed separately.

Android QUIC uses the bundled Mozilla/WebPKI roots, not the Android user CA store.
Hostname verification stays enabled. The native Rust API also supports an explicit
DER private CA for desktop/test deployments; Android import doesn't expose it.
No ECH or browser impersonation is implemented.

Build/test:
- cargo test --locked -p vpn-core --features quic
- cargo build --locked -p vpn-core --features quic --example h3_bridge
- python -m unittest discover -s tests -p test_rust_quic.py -v
  (install QUIC and WSS test requirements and build native bproto/vpn-server first).
- Android build uses --features jni, which enables the native QUIC dependencies.

The native helper reads BPROTO_BRIDGE_TOKEN and accepts endpoint, hostname and
optional DER CA arguments. It prints a loopback port for local bProto, not a public
server URL. Outer routing must still be protected on desktop full-tunnel use.

Validation includes Rust-to-aioquic datagrams, wrong token, hostname rejection,
real native bProto handshake/address lease through Rust HTTP3, and server socket
cleanup. Android cross-compilation/JVM tests are separate from phone/VpnService
runtime tests, which remain outstanding.
