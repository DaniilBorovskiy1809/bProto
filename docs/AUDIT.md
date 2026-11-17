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

## Config-agent implementation update

Added a version-1 JSON transaction agent, atomic replacement, validation/restart/
health commands, automatic recovery, explicit rollback and mandatory client
certificates. Panel API and TLS editor now expose Apply/Health/Rollback against
one fixed operator-configured mTLS destination. Seven agent tests pass, including
real mTLS rejection/acceptance, with 75% statement coverage. Actual systemd and
full panel-to-service e2e remain unverified; this is experimental.

## Native carrier and WSS update

Real vpn-server and bproto CLI binaries now establish sessions through TLS,
HTTP3 and WSS in tests; wrong native PSKs are rejected across all three.
An owned-domain WSS reverse-proxy carrier has been added, with certificate
verification, environment token, bounded WebSocket buffers and local HTML fallback.
This is not arbitrary SNI/Host fronting or ECH. Live CDN/allowlist testing,
Android QUIC/WSS, browser fingerprints and TUN/Internet e2e remain open.

## Android WSS update (2f7296d)

Android WSS now uses OkHttp with pre-connect VpnService socket protection,
system certificate validation, TLS 1.3, bounded outbound queues and shutdown
cleanup. The panel exports WSS JSON and Android import keys.
24 Android JVM tests pass, including a local TLS/WebSocket UDP round-trip;
the APK and panel build. These are not Android device VpnService tests.
Android QUIC, ECH, browser profiles and live network validation remain open.

## Documentation correction

The audit was accidentally replaced by the Russian WSS README in 2f7296d.
This version restores the preceding audit and appends the Android WSS result.
See [the current release plan](PLAN-2.5.md) for remaining acceptance gates.

## Native/Android HTTP3 implementation

Replaced the native QUIC placeholder with an h3/quinn client carrier and added
two-phase JNI bind/protect/start plus synchronized Kotlin lifecycle handling.
Panel exports QUIC profiles. Independent Rust↔aioquic tests cover datagrams,
certificate name/token rejection and real native bProto connection/address lease.
Fixed Python server shutdown to close upstream UDP without relying on a later
ConnectionTerminated event. Android device/VpnService testing remains open.

Validation for this update: vpn-core with quic: 117 passed, 1 previously ignored
donor test; Rust/aioquic suite: 10 passed; Python QUIC suite: 8 passed, 80% coverage;
Android: 27 JVM tests passed, APK assembled with three rebuilt ABIs and all five
new QUIC JNI symbols verified. Frontend TypeScript/Vite build passed.
No Android device run, ECH, browser profile or target-network evidence is claimed.

## Required ECH client implementation

Native HTTP3/Android QUIC now accept a bounded, expiring operator-provided
ECHConfigList with required-only semantics. Rustls/AWS-LC emits ECH; rejected ECH
does not retry with a cleartext inner SNI. Panel exports Android ECH settings.
The observed full ClientHello contains the public hostname and ECH extension,
without the inner hostname; malformed/expired configurations emit no ClientHello.
Successful ECH acceptance remains unverified; the Python server does not support
ECH termination. DNS discovery, rotation and Android device tests remain open.

Validation: 117 Rust tests passed with ech enabled (one legacy donor test remains
ignored); 13 ECH/interoperability tests passed; 34 Android JVM tests passed.
All three native Android ABIs and the APK built successfully; frontend build passed.
Required-ECH Android selections filter out non-ECH fallback candidates.
These results do not include successful ECH acceptance or device runtime.
