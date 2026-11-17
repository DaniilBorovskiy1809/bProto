package dev.bproto

import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import org.json.JSONObject

/** One native UDP session over a verified TLS 1.3 connection. */
class TlsCarrier private constructor(
    private val tcp: SSLSocket,
    private val udp: DatagramSocket,
    private val failed: () -> Unit,
) : Closeable {
    private val closed = AtomicBoolean(false)
    @Volatile private var peer: java.net.SocketAddress? = null
    val port: Int get() = udp.localPort

    private fun launch(action: () -> Unit) {
        Thread({
            try { action() } catch (_: Exception) {
                if (!closed.get()) failed()
            } finally { close() }
        }, "bproto-tls").apply { start() }
    }

    private fun start() {
        launch {
            val output = DataOutputStream(tcp.outputStream)
            while (!closed.get()) {
                val packet = DatagramPacket(ByteArray(2049), 2049)
                udp.receive(packet)
                if (peer == null) peer = packet.socketAddress
                if (peer == packet.socketAddress) {
                    require(packet.length in 1..2048)
                    output.writeShort(packet.length)
                    output.write(packet.data, packet.offset, packet.length)
                    output.flush()
                }
            }
        }
        launch {
            val input = DataInputStream(tcp.inputStream)
            while (!closed.get()) {
                val size = input.readUnsignedShort()
                require(size in 1..2048)
                val bytes = ByteArray(size)
                input.readFully(bytes)
                peer?.let { udp.send(DatagramPacket(bytes, size, it)) }
            }
        }
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            runCatching { tcp.close() }
            udp.close()
        }
    }

    companion object {
        fun prepare(uri: String, protect: (Socket) -> Boolean, failed: () -> Unit): Pair<String, TlsCarrier?> {
            val config = JSONObject(String(Base64.getUrlDecoder().decode(uri.removePrefix("bproto://import/")), Charsets.UTF_8))
            val profile = TlsProfile.parse(config) ?: return uri to null
            val (host, address, port, token) = profile
            check(android.os.Build.VERSION.SDK_INT >= 29) { "TLS carrier requires Android 10 or newer" }
            val raw = Socket()
            var secure: SSLSocket? = null
            var local: DatagramSocket? = null
            try {
                check(protect(raw)) { "TLS socket protection failed" }
                raw.connect(InetSocketAddress(address, port), 10000)
                secure = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                    .createSocket(raw, host, port, true) as SSLSocket
                secure.enabledProtocols = arrayOf("TLSv1.3")
                secure.sslParameters = secure.sslParameters.apply {
                    endpointIdentificationAlgorithm = "HTTPS"
                    serverNames = listOf(SNIHostName(host))
                    if (android.os.Build.VERSION.SDK_INT >= 29) applicationProtocols = arrayOf("http/1.1")
                }
                secure.soTimeout = 10000
                secure.startHandshake()
                secure.outputStream.write(("CONNECT /bproto HTTP/1.1\r\nHost: $host\r\nAuthorization: Bearer $token\r\n\r\n").toByteArray(Charsets.US_ASCII))
                secure.outputStream.flush()
                val response = StringBuilder()
                while (!response.endsWith("\r\n\r\n")) {
                    val byte = secure.inputStream.read()
                    check(byte >= 0 && response.length < 8192) { "Invalid TLS carrier response" }
                    response.append(byte.toChar())
                }
                check(response.toString() == "HTTP/1.1 200 Connection Established\r\n\r\n") { "TLS carrier authentication failed" }
                secure.soTimeout = 0
                local = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
                val carrier = TlsCarrier(secure, local, failed)
                config.remove("tls")
                config.put("server", "127.0.0.1:${carrier.port}")
                val native = "bproto://import/" + Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(config.toString().toByteArray(Charsets.UTF_8))
                carrier.start()
                return native to carrier
            } catch (e: Exception) {
                runCatching { secure?.close() }
                local?.close()
                runCatching { raw.close() }
                throw e
            }
        }
    }
}
