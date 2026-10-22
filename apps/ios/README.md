# bProto — iOS client

The tunnel runs inside a **Network Extension** (Packet Tunnel Provider). Unlike
Android there is no file descriptor to hand over and no `protect()` — the
provider pushes and pulls packets through `NEPacketTunnelFlow` and calls the C
ABI in `apps/ios/Bproto.h` directly.

| Path | Role |
| --- | --- |
| `apps/ios/Bproto.h` | The C ABI as Swift sees it. Hand-written to match `crates/vpn-ffi/src/lib.rs`. |
| `apps/ios/BprotoTunnelProvider.swift` | `NEPacketTunnelProvider` subclass: settings, datapath, stop flag. |

Status: **written but not compiled here** — it needs macOS, Xcode and a signing
team. The Rust side it calls (`libbproto.a`, `bproto_recv_timeout`) is built and
tested on Linux.

## Step 1 — build the static library

On macOS:

```bash
./build_app.sh --no-panel --ios
```

`dist/ios/libbproto.a` is a fat archive for device + simulator
(`libbproto-device.a` and `libbproto-sim.a` are also kept). Nothing else is
needed: the C ABI has no external dependencies to link.

## Step 2 — Xcode project

1. Create an iOS App target (SwiftUI or UIKit), deployment target **iOS 16**
   (the Swift `async` overrides of `startTunnel`/`stopTunnel` need it).
2. Add a **Network Extension** target → *Packet Tunnel Provider*. Name it
   `BprotoTunnel`. Bundle identifier must be the app's identifier plus a suffix,
   e.g. `dev.bproto.client.tunnel`.
3. Capabilities on **both** targets: *Network Extensions* (tick *Packet Tunnel
   Provider*), *App Groups* (shared container for the key, optional), and
   *Personal VPN* on the app target.
4. Add `apps/ios/Bproto.h` and `apps/ios/BprotoTunnelProvider.swift` to the
   extension target. Set the bridging header of the extension target to
   `Bproto.h` (or add it as `#import "Bproto.h"` in an existing bridging header).
5. Link `dist/ios/libbproto.a` into the extension target only. Under *Build
   Settings → Other Linker Flags* add `-lc++` if the linker complains about
   Rust's unwinder.
6. In the extension's `Info.plist`, set `NSExtensionPointIdentifier` to
   `com.apple.networkextension.packet-tunnel` (Xcode does this for you).

## Step 3 — start it from the app

The app never talks to the tunnel directly; it hands the key to the extension
through `providerConfiguration`.

```swift
import NetworkExtension

func start(key: String) async throws {
    let manager = NEVPNManager.shared()
    try await manager.loadFromPreferences()

    let proto = NETunnelProviderProtocol()
    proto.providerBundleIdentifier = "dev.bproto.client.tunnel"
    proto.serverAddress = "bProto"
    proto.providerConfiguration = ["key": key]   // the bproto://import/... URI

    manager.protocolConfiguration = proto
    manager.localizedDescription = "bProto"
    manager.isEnabled = true
    try await manager.saveToPreferences()

    try manager.connection.startVPNTunnel()
}
```

And on the other side, the provider reads it back in `startTunnel`:

```swift
let key = (protocolConfiguration as? NETunnelProviderProtocol)?
    .providerConfiguration?["key"] as? String
```

## What the provider does

1. `bproto_connect(key)` — handshake, blocks until the server answers.
2. `bproto_assigned_ip` — the leased IPv4 address, which becomes the tun address
   in `NEPacketTunnelNetworkSettings` (MTU `1251`, `includedRoutes = 0.0.0.0/0`).
3. A receive loop on a private queue calls `bproto_recv_timeout(..., 1000)` and
   writes whatever comes back with `packetFlow.writePackets`.
4. `packetFlow.readPackets` (one-shot, so re-armed every batch) feeds
   `bproto_send`.
5. `stopTunnel` flips a flag; the receive loop notices within a second and the
   handle is released.

## Why `bproto_recv_timeout` exists

`bproto_recv` blocks forever, and a Network Extension cannot afford a thread
that never returns on stop. The timeout variant returns `-2` instead of a packet
length, which turns the receive loop into something cancellable without a
signal handler or a socket shutdown. iOS is the only consumer; the function is
part of the C ABI for every platform.

## Known limitations (MVP)

* **IPv4 only.** `NEPacketTunnelNetworkSettings` sets no IPv6 settings, so IPv6
  traffic follows the underlying default route — a leak, unlike the Android side
  which captures and drops it. Add an `NEDNSSettings` + IPv6 `NEIPv6Settings`
  with a documentation prefix and no route if you need parity.
* **DNS is hardcoded** to `1.1.1.1`.
* **No `NEOnDemandRule`** and no kill switch wired in; the key is handed over
  only while the app is in the foreground.
* **Header is hand-written.** If a signature in `crates/vpn-ffi/src/lib.rs`
  changes, `Bproto.h` has to change with it. Generating it with `cbindgen` is
  the stage-2 fix.
* **Not compiled.** Treat `BprotoTunnelProvider.swift` as reviewed source, not as
  a verified build.
