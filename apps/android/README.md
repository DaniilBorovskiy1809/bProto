# bProto — Android client

The protocol, the handshake and the datapath are Rust (`crates/vpn-core`); this
folder is the Android shell that hosts them. There is no protocol logic here —
only the `VpnService` plumbing and the JNI bindings.

## What is in here

| Path | Role |
| --- | --- |
| `app/src/main/kotlin/dev/bproto/Bproto.kt` | JNI declarations, a Kotlin `object` whose members are resolved by name at runtime as `Java_dev_bproto_Bproto_*`. Do not add `@JvmStatic` or rename the members. |
| `app/src/main/kotlin/dev/bproto/BprotoVpnService.kt` | The tunnel: handshake, `protect()`, `establish()`, packet pump. |
| `app/src/main/kotlin/dev/bproto/MainActivity.kt` | Paste a `bproto://` key, connect, disconnect. |
| `app/src/main/jniLibs/<abi>/libbproto.so` | Build output. Produced by `./build_app.sh --android`. |

## Prerequisites

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk            # one-off

# Point cargo-ndk at your NDK (Android Studio ships one):
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$(ls "$ANDROID_HOME/ndk" | sort -V | tail -1)"
```

Plus a JDK 17 and either Android Studio or the Gradle CLI.

## Build

From the repository root:

```bash
./build_app.sh --no-panel --android      # add --no-apk to stop after the .so files
```

That does four things: cross-compiles `libbproto.so` for `arm64-v8a`,
`armeabi-v7a` and `x86_64` **with `--features jni`**, copies the result into
`dist/android/jniLibs/`, mirrors it into `apps/android/app/src/main/jniLibs/`
where Gradle picks it up, and — if a JDK and a `gradle` (or `apps/android/gradlew`)
are on `PATH` — assembles the debug APK into `dist/apk/`.

Verify the bridge before you build the APK — a missing symbol only shows up as a
`UnsatisfiedLinkError` at runtime:

```bash
nm -D --defined-only dist/android/jniLibs/arm64-v8a/libbproto.so \
  | grep Java_dev_bproto
# Java_dev_bproto_Bproto_assignedIp
# Java_dev_bproto_Bproto_close
# Java_dev_bproto_Bproto_connect
# Java_dev_bproto_Bproto_lastError
# Java_dev_bproto_Bproto_pump
# Java_dev_bproto_Bproto_socketFd
# Java_dev_bproto_Bproto_stop
# Java_dev_bproto_Bproto_version
```

The matching declaration on the Kotlin side is an `object Bproto` with
`external fun connect/pump/...` — an `object`'s members compile to *instance*
methods on `dev.bproto.Bproto`, which is exactly what those symbols expect. A
top-level function or a `@JvmStatic` member would produce a different name or a
duplicate method and fail at run time.

Then the APK, if you skipped it above or want to rebuild it:

```bash
cd apps/android
export JAVA_HOME=/path/to/jdk17 ANDROID_HOME=/path/to/Android/Sdk
gradle wrapper            # once: no wrapper is committed, it contains a binary
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Or just open `apps/android` in Android Studio and press Run.

**Status:** the APK builds and signs cleanly (Gradle 8.11.1, AGP 8.7.3,
Kotlin 2.1.0, NDK r27c, `minSdk 26` / `targetSdk 35`, three ABIs, ~8 MB) and has
been **run end to end on an x86_64 emulator** (API 35): the app launches, the
consent dialog is accepted, the handshake completes, `tun0` comes up with the
leased `10.66.0.2`, and a ping from the guest to the server's `10.66.0.1` is
answered **3/3 through the tunnel** with the server's TUN showing traffic in both
directions. It has not been run on physical hardware; see the limitations below.

The end-to-end run is reproducible without a phone: inside `unshare -rn`, start
`vpn-server --datapath` (real TUN, `10.66.0.1`) and the emulator in the same
namespace, so the guest's `10.0.2.2` is the server's `127.0.0.1`; then ping the
server's tunnel address from the guest. Nothing in the guest can answer that
address locally, so a reply proves the packet traversed the tunnel.

## Getting a key to paste

On the server machine:

```bash
bproto --config /etc/bproto/user1.client.toml import /etc/bproto/user1.toml
```

or scan the QR code the panel shows for the user. Both give the same
`bproto://import/<base64url>` URI, which carries the server address, the PSK and
the server's static public key. The app sends it straight to `Bproto.connect()`.

## The four things that make it work

This order is not cosmetic; swapping any two steps produces a tunnel that
connects and carries nothing:

1. **Handshake before `establish()`** — `Bproto.connect()` runs first so the server
   can lease an address; the leased address is what goes into
   `Builder.addAddress()`.
2. **`protect()` on the native socket** — `Bproto.socketFd(handle)` is passed to
   `VpnService.protect()`. Without it the encapsulated packets are routed back
   into our own tunnel.
3. **`establish()`** creates the tun descriptor the pump writes to.
4. **`Bproto.pump(handle, fd)`** blocks on its own thread until `Bproto.stop()`.

## Known limitations (MVP)

* **IPv4 only.** The tunnel carries IPv4; native IPv6 routing is stage 2. IPv6 is
  *captured and dropped* (`fd00:6270:726f:746f::2` plus a `::/0` route — the ULA
  spells "bproto" in hex) so that v6 traffic cannot leave the device in the clear
  while the user believes they are tunnelled; IPv6-only destinations are
  therefore unreachable. Capturing it is **best effort**, because some Android
  builds refuse an IPv6 address in their native address-config path (logcat
  `VpnJni: Invalid address: …`). If the framework refuses it, the service
  re-establishes IPv4-only and says so in the status line —
  `connected as 10.66.0.2 — warning: IPv6 not captured (…)`. A loud warning beats
  a dead tunnel, but it is a real leak and the status text is there so it cannot
  be missed.
* **One DNS server, hardcoded** (`BprotoVpnService.DNS`). The key URI does not
  carry DNS yet; point it at your resolver if you run one.
* **No kill switch.** If the service dies, traffic follows the system default
  route again. Use `Builder.addDisallowedApplication` for split tunneling or
  Android's always-on VPN with block-connections for a hard guarantee.
* **Verified on an emulator, not on a phone.** Everything above was exercised
  against a real `VpnService` on an API 35 x86_64 emulator: launch, consent,
  handshake, `protect()`, `tun0` with the leased address, and a ping through the
  tunnel answered by the server's TUN. Treat the first run on physical hardware
  as a test: vendor builds differ in exactly the places that bit us here
  (component names, the IPv6 address path).

## Verifying on a device

```bash
# the tunnel is up and the address is the leased one
adb shell ifconfig tun0
# status lines: handshake, lease, connect, stop
adb logcat -s bproto
curl --interface tun0 ifconfig.me    # should return the server's egress IP
```

If `tun0` comes up but nothing passes, check `protect()` first. Rust connects
the server socket during the handshake — before the app can protect it — and
although Android implements `protect()` as a per-socket routing mark, which
applies to an already-connected socket, this is the step to suspect before
anything else. `adb logcat -s bproto` shows `could not protect socket N` when the
call is refused outright.

Then check the server's own stats line: `sessions=1` means the client is in the
session table, and `unknown=0` means nothing is arriving with a tag the server
does not know. A rising `unknown` with `sessions=0` means the client believes it
is connected while the server has already forgotten it — a server-side bug of
exactly that kind (`last_rx_us` initialised to `0`, so every session created more
than `idle_timeout` after server start was reaped on the next tick) was found
this way and is fixed, but the counters are the fastest way to tell "the tunnel
carries nothing" from "the tunnel was never established".

First RTT reading is ~333 ms: that is RFC 9002's initial estimate and settles
after the first ACK exchange. It is not a bug.
