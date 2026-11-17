# Experimental QUIC / HTTP3 carrier

The existing bProto protocol is carried unchanged as length-prefixed datagrams
inside the DATA frames of one authenticated HTTP/3 POST stream. aioquic provides
QUIC v1, TLS 1.3, QPACK and HTTP/3 framing. ALPN is h3; server Retry is enabled.
This is a standalone Python client/server bridge, not Android QUIC integration.

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
