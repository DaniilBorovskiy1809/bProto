package dev.bproto

import java.io.Closeable
import java.net.InetAddress
import java.net.Inet6Address
import java.net.Socket
import java.util.Base64
import org.json.JSONObject

/** Owns a native handle; synchronizes polling and close to prevent use-after-free. */
class QuicCarrier private constructor(private var handle: Long) : Closeable {
    @Synchronized private fun alive(): Boolean = handle != 0L && Bproto.quicAlive(handle) != 0
    @Synchronized override fun close() {
        if (handle != 0L) { Bproto.quicClose(handle); handle = 0 }
    }
    private fun monitor(failed: () -> Unit) {
        Thread({
            while (true) {
                Thread.sleep(200)
                synchronized(this) {
                    if (handle == 0L) return@Thread
                    if (!alive()) {
                        close()
                        failed()
                        return@Thread
                    }
                }
            }
        }, "bproto-quic").start()
    }
    companion object {
        fun prepare(uri: String, protectFd: (Int) -> Boolean, protectSocket: (Socket) -> Boolean,
                    failed: () -> Unit): Pair<String, Closeable?> {
            val config = JSONObject(String(Base64.getUrlDecoder().decode(uri.removePrefix("bproto://import/")), Charsets.UTF_8))
            val profile = QuicProfile.parse(config) ?: return WssCarrier.prepare(uri, protectSocket, failed)
            val address = InetAddress.getByName(profile.address)
            val ipv6 = address is Inet6Address
            val handle = Bproto.quicBind(if (ipv6) 1 else 0)
            check(handle != 0L) { "Could not bind QUIC carrier" }
            val carrier = QuicCarrier(handle)
            try {
                val fd = Bproto.quicSocketFd(handle)
                check(fd >= 0 && protectFd(fd)) { "QUIC socket protection failed" }
                val endpoint = if (ipv6) "[${address.hostAddress}]:${profile.port}" else "${address.hostAddress}:${profile.port}"
                val port = Bproto.quicStart(handle, endpoint, profile.hostname, profile.token)
                check(port > 0) { "QUIC handshake failed" }
                config.remove("quic")
                config.put("server", "127.0.0.1:$port")
                val native = "bproto://import/" + Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(config.toString().toByteArray(Charsets.UTF_8))
                carrier.monitor(failed)
                return native to carrier
            } catch (e: Exception) { carrier.close(); throw e }
        }
    }
}
