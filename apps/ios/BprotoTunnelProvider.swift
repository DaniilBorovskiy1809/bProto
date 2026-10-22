import Foundation
import NetworkExtension

/// Packet tunnel provider for the bProto client.
///
/// Data flow: `packetFlow` hands us IP packets from the system, we push them
/// through the bProto session (`bproto_send`), and a receive loop pulls packets
/// out of the session (`bproto_recv_timeout`) and writes them back.
///
/// The blocking C calls run on a serial queue of our own; nothing here touches
/// the main thread. `bproto_recv_timeout` is what makes cancellation possible:
/// it returns -2 every second so the loop can notice `stopped`.
///
/// Status: written against the real C ABI, but **not compiled here** — it needs
/// Xcode, a Packet Tunnel Provider target and the signing entitlements. See
/// README.md for the exact project setup and for the current limitations.
final class BprotoTunnelProvider: NEPacketTunnelProvider {

    private let work = DispatchQueue(label: "dev.bproto.tunnel")
    private let stopped = NSLock()
    private var stopRequested = false

    private var handle: OpaquePointer?

    /// Receive buffer: one MTU-sized packet plus slack.
    private let bufferSize = 65_536
    private let recvTimeoutMs: UInt64 = 1_000

    // MARK: - Lifecycle

    override func startTunnel(options: [String: NSObject]?) async throws {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let key = proto.providerConfiguration?["key"] as? String,
              !key.isEmpty else {
            throw NSError(domain: "dev.bproto", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "no bproto:// key in the tunnel configuration"])
        }

        guard let tunnel = bproto_connect(key) else {
            throw NSError(domain: "dev.bproto", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: errorText()])
        }
        handle = tunnel

        var octets = [UInt8](repeating: 0, count: 4)
        guard bproto_assigned_ip(tunnel, &octets) == 0 else {
            bproto_free(tunnel)
            handle = nil
            throw NSError(domain: "dev.bproto", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: errorText()])
        }
        let address = "\(octets[0]).\(octets[1]).\(octets[2]).\(octets[3])"

        // Routes: everything through the tunnel. The extension's own socket to
        // the server is exempt because NetworkExtension does not route the
        // provider's traffic back into its own tunnel.
        let ipv4 = NEIPv4Settings(addresses: [address], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: address)
        settings.mtu = NSNumber(value: 1251)
        settings.ipv4Settings = ipv4
        settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1"])
        await setTunnelNetworkSettings(settings)

        startReceiveLoop(tunnel)
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
        requestStop()
        if let tunnel = handle {
            handle = nil
            // Give the receive loop a moment to unwind, then release.
            work.asyncAfter(deadline: .now() + 1.5) {
                bproto_free(tunnel)
            }
        }
    }

    override func handleAppMessage(_ messageData: Data) async -> Data? {
        guard let tunnel = handle else { return nil }
        var stats = BprotoStats()
        guard bproto_stats(tunnel, &stats) == 0 else { return nil }
        let reply: [String: Any] = [
            "rtt_us": stats.rtt_us,
            "rx_bytes": stats.rx_bytes,
            "tx_bytes": stats.tx_bytes,
            "dropped": stats.dropped,
            "uptime_s": stats.uptime_s,
        ]
        return try? JSONSerialization.data(withJSONObject: reply)
    }

    // MARK: - Datapath

    private func startReceiveLoop(_ tunnel: OpaquePointer) {
        // tunnel -> system
        work.async { [weak self] in
            guard let self else { return }
            var buf = [UInt8](repeating: 0, count: self.bufferSize)
            while !self.isStopRequested() {
                let n = bproto_recv_timeout(tunnel, &buf, UInt(buf.count), self.recvTimeoutMs)
                if n == -2 { continue }          // idle tick: re-check the stop flag
                if n <= 0 { break }              // session gone or fatal error
                let packet = Data(buf[0..<Int(n)])
                self.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
            }
        }

        // system -> tunnel: readPackets is one-shot, so re-arm after each batch.
        readOnce()
    }

    private func readOnce() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            guard let tunnel = self.handle, !self.isStopRequested() else {
                self.cancelTunnelWithError(nil)
                return
            }
            for packet in packets {
                _ = packet.withUnsafeBytes { raw -> Int32 in
                    guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                    return bproto_send(tunnel, base, UInt(raw.count))
                }
            }
            self.readOnce()
        }
    }

    // MARK: - Stop flag

    private func requestStop() {
        stopped.lock()
        stopRequested = true
        stopped.unlock()
    }

    private func isStopRequested() -> Bool {
        stopped.lock()
        defer { stopped.unlock() }
        return stopRequested
    }

    private func errorText() -> String {
        guard let c = bproto_last_error() else { return "unknown error" }
        return String(cString: c)
    }
}
