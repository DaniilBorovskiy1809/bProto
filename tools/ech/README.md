# Required ECH client support (experimental)

Native Rust HTTP/3 and Android QUIC can now require Encrypted ClientHello.
TLS uses rustls ECH with the AWS-LC HPKE implementation. TLS traffic cryptography
still selects the ring provider explicitly. ECH configurations are public data,
not bearer credentials; obtain them from the endpoint operator through an
authenticated channel. Automatic HTTPS DNS record discovery is not implemented.

## Configuration

In the Android import JSON, the quic object may contain:

```json
{
  "ech": {
    "mode": "required",
    "config_list": "<base64-encoded ECHConfigList>",
    "expires_unix_secs": 1900000000
  }
}
```

The placeholder must be replaced with a real operator-issued configuration;
the epoch value is illustrative. A decoded list must be 2..4096 bytes and the
expiry must be in the future. Rust validates the actual ECH structure and supported
HPKE suite before sending a ClientHello. Android validates encoding and expiry
both on import and connection; Rust rechecks expiry before handshake.

Absence of ech disables ECH. Presence requires mode=required; optional/grease/
disabled objects are rejected. Configuring ECH on TLS/WSS or at the wrong JSON
level is rejected rather than silently ignored. Android export in the panel
supports these public settings for QUIC. It doesn't configure an ECH server.

The native helper uses BPROTO_ECH_CONFIG (path to binary ECHConfigList) and
BPROTO_ECH_EXPIRES (Unix seconds), plus the existing BPROTO_BRIDGE_TOKEN.
Build with `cargo build --locked -p vpn-core --features ech --example h3_bridge`.
Android JNI builds include the ech feature. The quic-only build rejects attempts
to configure ECH; it never silently disables it.

## Behavior and tests

A server rejecting ECH fails the handshake before application data is available.
There is no automatic retry with the cleartext inner SNI, no accepted downgrade,
and no automatic use of server-supplied retry configs. To rotate configuration,
obtain a new validated ECHConfigList and import/reconnect. Existing connections
retain their negotiated state.

`python -m unittest discover -s tests -p test_ech.py -v` includes the native
Rust/aioquic interoperability suite. It observes actual ClientHello bytes after
QUIC Initial decryption by the test server:
- the public hostname is present;
- the inner hostname is absent from the nonempty complete ClientHello;
- the ECH extension is present;
- a non-ECH server is rejected, with no local carrier exposed;
- malformed/expired configurations cause zero ClientHello messages.

These tests verify encryption emission and rejection, not a successful ECH
connection. The Python bProto server doesn't accept ECH. A compatible owned
ECH frontend must terminate ECH and support the carrier HTTP/3 exchange.
An accepting-server e2e, DNS discovery, key rotation, Android device testing,
optional-mode policy and browser fingerprinting remain outstanding.
ECH does not hide destination IP or guarantee access through an IP allowlist.

When a selected Android profile requires ECH, automatic server selection filters
out profiles without ECH. An expired or malformed ECH candidate fails rather than
opening a plain connection. This is separate from the TLS library's no-downgrade
behavior within a single handshake.
