# Owned-domain WebSocket transport

This is WSS reverse proxying, **not arbitrary SNI/Host domain fronting**.
The client uses the same owned hostname for TLS verification and the HTTP Host
header. The provider must permit WebSockets and route this domain to your origin.
It is not an automatic Cloudflare/Fastly/Yandex integration or ECH implementation.

Architecture: native bProto UDP → local client bridge → WSS binary messages →
owned reverse proxy/CDN → TLS origin bridge → native bProto UDP server.
One binary WebSocket message carries one unchanged bProto datagram.
Compression is disabled. TLS certificate and hostname verification stay enabled.
Client WSS requires TLS 1.3; an optional ca file supports private test CAs.

## Setup

Install requirements.txt into a virtualenv. Copy the example JSON files, replace
vpn.example.com with your own domain and configure a matching valid certificate.
Set the same private 64-hex BPROTO_BRIDGE_TOKEN in server and client environments.
Start with `python bridge.py server /etc/bproto/wss-server.json` and
`python bridge.py client /etc/bproto/wss-client.json`.

Bind the native server to the configured upstream. Point the native client at
127.0.0.1:14443, retaining native PSK/tag/user credentials. Protect or pin the outer
WSS endpoint route before enabling full-tunnel routing. The native client only
sees loopback. This Python sidecar is not integrated into Android.

For a reverse proxy/CDN, explicitly enable WebSocket forwarding to your HTTPS
origin, preserve the /bproto path and Authorization header, and validate the origin
certificate. Do not cache this path. Use your provider's supported origin
configuration; do not disable TLS validation. Provider idle limits may terminate
connections. Restart the bridge to apply updated config; no rebuild needed.

Unknown paths and invalid carrier tokens receive the operator's local HTML page.
Nonbinary or oversized authenticated messages terminate the WebSocket.
This behavior is not claimed to be indistinguishable from all websites.

## Verification and limits

Run the native carrier suite after building vpn-server and bproto:
`python -m unittest discover -s tests -p test_native_carriers.py -v`.
Install both tools/fronting and tools/quic-bridge requirements for this suite.
BPROTO_TEST_BIN_DIR selects the binary directory (default target/debug).
Tests run real native handshakes through TLS, QUIC/HTTP3 and WSS, including wrong
native PSKs, wrong WSS tokens, hostname rejection and malformed messages.

No live CDN, Android WSS, browser fingerprint, ECH or real allowlist/DPI test has
been performed. The suite does not test kernel TUN or Internet forwarding.
A whitelisted hostname does not make an unreachable origin IP reachable; the
authorized proxy itself must be reachable. No 100% RKN bypass guarantee.
WSS uses TCP: head-of-line blocking and provider timeouts affect performance.
