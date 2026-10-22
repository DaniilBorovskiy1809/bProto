# Building the bProto clients

Three targets, three very different amounts of finished work. This page says
which one is which instead of implying parity.

| Target | What you get | State |
| --- | --- | --- |
| **Linux desktop** | `bproto` CLI with a real TUN interface, default route, NAT | **Works.** Built and tested here. |
| **Android** | `libbproto.so` + a `VpnService` app in `apps/android/` → debug APK | Runs end to end on an emulator (API 35): handshake, `tun0` lease, and a ping through the tunnel. APK builds and signs. Not yet run on a phone. |
| **iOS** | `libbproto.a` + a Packet Tunnel Provider in `apps/ios/` | Rust side compiles; the Swift is written but **never compiled** (no macOS here). |
| **Windows / macOS desktop** | — | **Not supported yet.** `crates/vpn-tun` is Linux-only (`/dev/net/tun`). Wintun on Windows and `utun` on macOS are stage 2. |

The shared part is `crates/vpn-core` (protocol, handshake, congestion, replay)
and `crates/vpn-ffi` (the C ABI and the JNI bridge). No platform gets its own
implementation of the protocol.

---

## 1. Linux desktop

Nothing to cross-compile. One command installs the client, generates a config
and a systemd unit:

```bash
sudo ./install.sh client
```

Then get a key. Either from the panel's QR code, or from a config file the
server generated:

```bash
bproto --config /etc/bproto/user1.client.toml import /etc/bproto/user1.client.toml
```

and connect:

```bash
sudo bproto --config /etc/bproto/user1.client.toml up
```

`up` creates the TUN device, assigns the leased address, sets the MTU and moves
the default route (opt out with `--no-default-route`). It needs root; without it
use `connect`, which runs the handshake and reports the RTT and the lease
without touching the host network:

```bash
bproto --config /etc/bproto/user1.client.toml connect --seconds 10
```

Skip the config file entirely if you have a key URI:

```bash
sudo bproto --uri 'bproto://import/...' up
```

If you only want the shared library (embedding bProto in your own app):

```bash
./build_app.sh --no-panel --no-ffi=false        # dist/lib/libbproto.so
```

Verified in this repository: `install.sh client` on a clean root filesystem,
followed by a real handshake from the installed binary (the server leased
`10.66.0.2`). See `INSTALL.md` §4.1 for the full transcript.

---

## 2. Android

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk
export JAVA_HOME=/path/to/jdk17
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$(ls "$ANDROID_HOME/ndk" | sort -V | tail -1)"

./build_app.sh --no-panel --android      # .so x3 ABIs + the debug APK (--features jni)
adb install -r dist/apk/bproto-0.1.0-debug.apk
```

`--android` implies `--features jni` — the Kotlin entry points
(`Java_dev_bproto_Bproto_*`) only exist with that feature on, so a plain
`cargo ndk ... build` gives you a library the app cannot call. It also runs
Gradle, if a JDK and a `gradle` are on `PATH`, and stages the APK in `dist/apk/`;
without Gradle it stops after the native libraries (add `--no-apk` to force that
on purpose).

Full instructions, the four ordered steps that make the tunnel actually carry
traffic, and the verification commands: [`apps/android/README.md`](../apps/android/README.md).

---

## 3. iOS

Needs macOS + Xcode — the cross-compilation and the project setup cannot happen
anywhere else.

```bash
./build_app.sh --no-panel --ios          # dist/ios/libbproto.a (device + simulator)
```

Then add `apps/ios/Bproto.h` and `apps/ios/BprotoTunnelProvider.swift` to a
Packet Tunnel Provider extension target, link `dist/ios/libbproto.a` into it,
and hand the key over through `providerConfiguration`.

Full walkthrough: [`apps/ios/README.md`](../apps/ios/README.md).

---

## What each platform still lacks

These are MVP gaps, not oversights — each one is recorded here so nobody
discovers it in production.

| Gap | Linux | Android | iOS |
| --- | --- | --- | --- |
| IPv6 in the tunnel | ✗ routes IPv4 only | captured and dropped (best effort — see the note below) | not captured (leaks) |
| DNS pushed by the server | ✗ | hardcoded `1.1.1.1` | hardcoded `1.1.1.1` |
| Kill switch / always-on | ✗ | use Android's always-on VPN | ✗ |
| GUI | ✗ CLI only | one screen | none (provider only) |
| Stealth (mode B) | ✗ stage 2 | ✗ stage 2 | ✗ stage 2 |

The transport is honest UDP in all three: a DPI box that fingerprints UDP
traffic will see bProto for what it is. That is deliberate for v0.1 — see
`docs/PROTOCOL.md` §"Mode B".

The Android IPv6 row deserves a note because "best effort" is doing real work
there. The client asks for an IPv6 address and a `::/0` route so v6 cannot walk
out in the clear, but some Android builds reject an IPv6 address in their native
address-config path (`VpnJni: Invalid address`). When that happens the service
retries IPv4-only and puts the fact in the status line; it does not fail the
tunnel and it does not hide the gap.
