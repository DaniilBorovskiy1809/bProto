# bProto wire protocol (v1)

Status: implemented. This document describes what `crates/vpn-core` actually
does today, not an aspiration. Anything marked **stage 2** is specified but not
yet coded, and the corresponding API returns `Error::Unimplemented`.

Everything is carried over UDP in a single flow to `server` (conventionally
`:443`, `:udp`).

## 0. Two deployment modes

| | mode A (implemented) | mode B (stage 2) |
|---|---|---|
| on the wire | bProto's own 12-byte header | QUIC/HTTP-3 to a real donor |
| handshake | native `HELLO`/`HELLO_ACK` (§4) | ClientHello with a bProto `session_id` (§6) |
| anti-DPI | none beyond the header being opaque | borrowed donor certificate + `NewSessionTicket` |
| config | `stealth = "off"` | `stealth = "shape"` and a reachable donor |

Mode A is what ships now and what the tests exercise end to end. Mode B reuses
the *same* authentication construction (§6) so a client can be switched without a
protocol break. Do not run mode A against a censor that fingerprints UDP
payloads: it is an honest protocol, not a disguise.

## 1. Datagram header

12 bytes, cleartext, used as the AEAD associated data.

| offset | size | field |
|---|---|---|
| 0 | 1 | `version[7:4] | flags[3:0]`, this document is version `0x1` |
| 1 | 4 | `session_tag` u32 BE |
| 5 | 5 | `packet_number` u40 BE |
| 10 | 2 | `reserved` u16 BE, MUST be 0 in v1 |

Flag bits:

| bit | name | meaning |
|---|---|---|
| 0 | `FEC_RESERVED` | reserved for FEC; always 0 in v1 |
| 1 | `KEY_PHASE` | key-update epoch bit (**stage 2**) |
| 2 | `SPIN` | obfuscation, mirrors QUIC's spin bit |
| 3 | `CONTROL` | this datagram carries a **plaintext** control frame and is not AEAD-protected |

`CONTROL` is set only during the handshake, where no key exists yet. Every other
datagram is an AEAD record. Encrypted control frames (`Ack`, `Ping`, `Pong`,
`Close`) travel inside an `InnerType::Control` frame with `CONTROL` **clear** —
otherwise they would be plaintext, which is exactly the bug this bit exists to
prevent.

* `session_tag` is a truncated connection id derived from the handshake (see
  §4). The handshake itself sets it to 0 and routes on the tag inside the frame.
* `packet_number` is monotonic per direction and never reused, 40 bits.

Decoding a datagram never allocates and never looks at the payload before the
header is authenticated; `reserved != 0` is a decode error, so a tampered header
fails closed.

## 2. AEAD

* Algorithm: ChaCha20-Poly1305 (RFC 8439), 16-byte tag in the `chacha20poly1305`
  crate.
* Key: 32 bytes per direction from the key schedule (§4).
* Nonce (12 bytes): `nonce_prefix[4] ‖ packet_number_be[8]`. The prefix differs
  per direction, so packet numbers may repeat across directions without a nonce
  collision.
* AAD: the full 12-byte header.
* Ciphertext: `ChaCha20-Poly1305(plaintext) ‖ tag`.

Only the inner frame is encrypted; the header is authenticated but visible, so a
datagram can be routed before any key lookup.

## 3. Inner frame

Plaintext layout:

| offset | size | field |
|---|---|---|
| 0 | 1 | `inner_type`: 0 = IP, 1 = control, 2 = keepalive |
| 1 | n | payload (an IP packet, or a control frame) |
| 1+n | * | zero padding to a size bucket, optional |

Padding snaps datagram sizes to a small set of buckets
(`packet::SIZE_BUCKETS`) so the size distribution is not a constant MTU. In v1
padding is a client-side option; both peers accept any valid padding on receipt.

Tunnel MTU is `1280 − 12 − 16 − 1 = 1251` bytes of IP payload
(`packet::TUNNEL_MTU`); `MAX_DATAGRAM` is 1280.

## 4. Handshake and key schedule

Three datagrams, all plaintext control frames (there is no key yet):

```text
  client                                        server
  ------                                        ------
  HELLO{tag, cr, x25519_pub, window, mac}   ->
                                            <-  HELLO_ACK{cr, sr, x25519_pub, ip, mac}
  (both sides derive: shared = X25519, keys = HKDF, tag = HKDF)
```

`HELLO` control frame (105 bytes; the datagram adds the 12-byte header):

| offset | size | field |
|---|---|---|
| 0 | 1 | frame type `0x01` |
| 1 | 8 | `tag = HMAC-SHA256(K_tag, user_id)[0..8]` |
| 9 | 32 | `client_random` |
| 41 | 32 | `x25519_pub` |
| 73 | 8 | `window = floor(unix_secs / 300)` u64 BE |
| 81 | 24 | `mac = HMAC-SHA256(psk, tag ‖ cr ‖ x25519_pub ‖ window)[0..24]` |

`HELLO_ACK` control frame (125 bytes):

| offset | size | field |
|---|---|---|
| 0 | 1 | frame type `0x02` |
| 1 | 32 | `client_random` (echo) |
| 33 | 32 | `server_random` |
| 65 | 32 | `x25519_pub` (server ephemeral) |
| 97 | 4 | `assigned_ip` (the leased tunnel address) |
| 101 | 24 | `mac` |

`mac = HMAC-SHA256(psk, cr ‖ sr ‖ x25519_pub ‖ assigned_ip)[0..24]`.

Rules:

1. The server looks the tag up in its table. An unknown tag or a bad MAC is
   `BadLabel`; in mode B it means "relay to the donor" instead.
2. `window` is accepted for `T−1 … T+1` (a ±5-minute clock-skew tolerance,
   `auth::WINDOW_SECS = 300`). Comparison is constant-time.
3. `client_random` is echoed in `HELLO_ACK` and checked, so a captured ACK from
   another exchange cannot be replayed onto this one.
4. Keys: `HKDF-SHA256(ikm = X25519(eph_c, eph_s), salt = client_random ‖
   server_random, info = "bproto v1 session keys")` → `c2s_key ‖ s2c_key ‖
   c2s_prefix ‖ s2c_prefix` (72 bytes).
5. `session_tag = HKDF-SHA256(ikm = shared, salt = cr ‖ sr, info = "bproto v1
   session tag")[0..4]`, bound to both randoms so it differs on every connection.
6. Both peers verify the other's MAC with the pre-shared key, so an active prober
   that does not know the PSK cannot key the session.

The client retransmits the byte-identical `HELLO` every 500 ms
(`session::HANDSHAKE_RETRY`) until `HELLO_ACK` arrives or `handshake_timeout`
expires. The server answers a repeated `(tag, client_random)` idempotently.

## 5. Addressing

The server owns a pool (default `10.66.0.0/24`). The server's own tunnel address
is the first host (`10.66.0.1`); the client is leased the next free host
(`10.66.0.2`, then `.3`, …). The lease is held for the life of the session and
released on idle teardown (`session::IDLE_TIMEOUT = 45 s`). Tunnel routing is by
inner destination IPv4, so the server does not need to know the client's address
until it has one.

## 6. The `session_id` label (mode B bridge)

The 32-byte TLS `session_id` that mode B puts in the ClientHello is *the same
construction* as the `HELLO` field above, packed into a fixed 32 bytes:

```
session_id[0..8]  = HMAC-SHA256(K_tag, user_id)[0..8]        (the routing tag)
session_id[8..32] = HMAC-SHA256(psk, tag ‖ client_random
                                     ‖ x25519_pub ‖ T)[0..24]  (the label MAC)
```

Using `session_id` as the carrier is the point: it does not change the length of
any handshake frame, so `ServerFinished` keeps its real size and the Aparecium
"length changed versus the donor" vector stays closed. `crates/craftls/PATCH.md`
is the exact two-file patch to `craftls` that lets the client supply this value.

Mode B additionally preserves the donor's `NewSessionTicket` (forwarding or
synthesizing it to match the donor's observed count and timing) rather than
dropping it — the second Aparecium vector. The `nst` module in `vpn-server` is
the policy guard that forbids shipping a build that suppresses it.

## 7. Reliability and congestion control

The data plane is WireGuard-shaped: **IP packets are not retransmitted**. Reliability
is the job of the TCP/QUIC running *inside* the tunnel. The transport-level
machinery exists for telemetry and backpressure only:

* ACK frames carry ranges of received packet numbers (RFC 9002 style), sent every
  8 packets or every 20 ms, whichever comes first;
* RTT estimation, loss detection and the PTO follow RFC 9002;
* NACK is an additional fast-loss hint so recovery does not wait for a timer;
* congestion control is CUBIC (`congestion.rs`, RFC 8312 shaped, bytes-based),
  replacing the placeholder with `quinn`'s implementation in stage 2; BBR is
  opt-in later; BBRv3 is never used (reproducible underflow in the `quinn`
  implementation);
* the handshake is the only thing that is retransmitted, on the 500 ms timer
  above.

This is not "TCP over TCP": we acknowledge our own datagrams and never
retransmit a TCP segment.

## 8. Key update and tag rotation (**stage 2**)

A key update will advance the `KEY_PHASE` bit and derive fresh traffic keys with
the same HKDF, using the previous keys as IKM. Key update and `session_tag`
rotation happen together, on a timer and on a byte threshold; both directions
switch within one RTT and the receiver keeps the previous key for a grace period.
`Session::rekey` returns `Error::Unimplemented` until then.

## 9. Reserved for later

* FEC: `FEC_RESERVED` and the two reserved header bytes. Order is AEAD first,
  then Reed-Solomon, so parity symbols never appear in the clear.
* Post-quantum: a hybrid X25519 + ML-KEM-768 rekey inside the encrypted channel,
  after the handshake (the ClientHello stays 32 bytes / 1.3 KB like a browser's).

## 10. Test vectors

`crates/vpn-core` carries round-trip and negative tests for every layer above:
`packet.rs` (header + framing), `crypto.rs` (AEAD + HKDF), `auth.rs`
(`compute_tag` has a pinned vector), `handshake.rs` (mutual key agreement, wrong
PSK, stale window, replayed ACK), `replay.rs` (window boundaries) and
`tests/tunnel_e2e.rs` (a real client against a real server over loopback UDP).
`crates/vpn-ffi` re-exports the same `session_id` computation as `bproto_compute_session_id`
for the mobile clients. `cargo test -p vpn-core` is the reference.
