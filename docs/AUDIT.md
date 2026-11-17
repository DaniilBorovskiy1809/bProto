# 2.5 transport audit

Baseline: 831a2e1, test/connection-lab. This document records observed implementation,
not promises of censorship resistance.

| Requirement | Baseline status | Evidence |
|---|---|---|
| Native encrypted protocol | Implemented | crates/vpn-core |
| Real TLS carrier | Experimental Python sidecar | tools/tls-bridge/bridge.py |
| Certificate verification | Implemented; local tests | tests/test_tls_bridge.py |
| Panel transport configuration | Export only | TlsBridgeEditor.tsx |
| Android TLS carrier | Absent | BprotoVpnService.kt uses native UDP |
| QUIC/HTTP3 | Core placeholder, no carrier | transport/quic.rs |
| Browser fingerprints | Enum only, no verified browser handshakes | config.rs |
| CDN/ECH/allowlist deployment | Absent; no operator domain/CDN available | environment |
| Config agent with mTLS/rollback | Absent | tools |
| Android runtime e2e | Not verified | no emulator validation |
| DPI/JA3/JA4 evidence | Absent | no reference captures |
| Coverage >=70% | Not measured | four carrier tests only |

## Constraints / Ограничения

An unrelated SNI cannot bypass an IP allowlist. TLS certificate chains cannot be
borrowed from a fallback site without its private key. HTTP/3 requires HTTP/3
framing; raw QUIC streams must not advertise h3. TLS 1.3 padding is optional, not
automatic 16-byte alignment. Failure to reject a timing hypothesis (p > .05)
does not prove indistinguishability. Synthetic tests cannot certify RKN evasion.

Разрешённый SNI не делает заблокированный IP доступным. Для реальной проверки
нужны контролируемый разрешённый узел и доступ к целевой сети; сейчас их нет.
100% гарантии обхода РКН нет.

## Implementation update

- Android TLS carrier added in TlsCarrier.kt: protected TCP socket, TLS 1.3,
  hostname verification, framed datagrams and shutdown cleanup.
- TlsProfile.kt validates optional transport configuration; six JVM tests added.
- Panel exports Android TLS import keys from existing native credentials.
- Existing four TLS tests are included in build.yml.
- Android runtime e2e, QUIC, fingerprints, ECH/CDN, agent and coverage gate remain
  open. The full 2.5.0 acceptance criteria are not yet met.

## QUIC implementation update

tools/quic-bridge now implements a separate aioquic HTTP/3 carrier with QUIC v1,
Retry, certificate validation, framed native datagrams and local HTML fallback.
Seven real-UDP integration/framing tests pass, with 80% statement coverage.
CI runs these tests with a 70% gate. Android QUIC and independent HTTP/3/DPI
interoperability evidence remain open; this does not satisfy the full 2.5 DoD.
