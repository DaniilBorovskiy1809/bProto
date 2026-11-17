package dev.bproto

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import okhttp3.*
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.ByteString
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class WssCarrierTest {
    private fun config(url: String) = JSONObject().put("wss", JSONObject()
        .put("url", url).put("token", "a".repeat(64)))

    @Test fun validatesProfiles() {
        assertNull(WssProfile.parse(JSONObject()))
        assertEquals("wss://vpn.example.com/bproto", WssProfile.parse(config("wss://vpn.example.com/bproto"))!!.url)
        for (url in listOf("ws://example.com/", "wss://user:pass@example.com/", "wss://example.com/#fragment", "wss://example.com:0/")) {
            assertThrows(IllegalArgumentException::class.java) { WssProfile.parse(config(url)) }
        }
        assertThrows(IllegalArgumentException::class.java) { WssProfile.parse(config("wss://example.com/").put("tls", JSONObject())) }
    }

    @Test fun protectsSocketBeforeConnection() {
        var called = false
        val socket = ProtectedSocketFactory { called = true; assertFalse(it.isConnected); true }.createSocket()
        socket.close()
        assertTrue(called)
        assertThrows(IllegalStateException::class.java) { ProtectedSocketFactory { false }.createSocket() }
    }

    @Test fun realTlsWebSocketUdpRoundTrip() {
        val certificate = HeldCertificate.Builder().commonName("localhost").addSubjectAlternativeName("localhost").build()
        val serverTls = HandshakeCertificates.Builder().heldCertificate(certificate).build()
        val clientTls = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
        val server = MockWebServer()
        server.useHttps(serverTls.sslSocketFactory(), false)
        server.enqueue(MockResponse().withWebSocketUpgrade(object : WebSocketListener() {
            override fun onMessage(webSocket: WebSocket, bytes: ByteString) { webSocket.send(bytes) }
        }))
        server.start()
        val failed = AtomicBoolean(false)
        val protected = AtomicBoolean(false)
        try {
            val url = server.url("/bproto").toString().replace("https://", "wss://")
            val builder = OkHttpClient.Builder().sslSocketFactory(clientTls.sslSocketFactory(), clientTls.trustManager)
            WssCarrier.connect(WssProfile(url, "a".repeat(64)), {
                assertFalse(it.isConnected); protected.set(true); true
            }, { failed.set(true) }, builder).use { carrier ->
                DatagramSocket().use { socket ->
                    socket.soTimeout = 3000
                    val bytes = ByteArray(1252) { (it % 256).toByte() }
                    socket.send(DatagramPacket(bytes, bytes.size, InetAddress.getByName("127.0.0.1"), carrier.port))
                    val reply = DatagramPacket(ByteArray(2048), 2048)
                    socket.receive(reply)
                    assertArrayEquals(bytes, reply.data.copyOf(reply.length))
                }
                assertTrue(protected.get())
                assertFalse(failed.get())
                val request = server.takeRequest()
                assertEquals("Bearer " + "a".repeat(64), request.getHeader("Authorization"))
                assertEquals(TlsVersion.TLS_1_3, request.handshake!!.tlsVersion)
            }
        } finally { server.shutdown() }
    }

    @Test fun rejectsHttpFallbackAsCarrier() {
        val certificate = HeldCertificate.Builder().commonName("localhost").addSubjectAlternativeName("localhost").build()
        val serverTls = HandshakeCertificates.Builder().heldCertificate(certificate).build()
        val clientTls = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
        val server = MockWebServer()
        server.useHttps(serverTls.sslSocketFactory(), false)
        server.enqueue(MockResponse().setResponseCode(200).setBody("Operator site"))
        server.start()
        try {
            val url = server.url("/bproto").toString().replace("https://", "wss://")
            assertThrows(IllegalStateException::class.java) {
                WssCarrier.connect(WssProfile(url, "a".repeat(64)), { true }, {},
                    OkHttpClient.Builder().sslSocketFactory(clientTls.sslSocketFactory(), clientTls.trustManager))
            }
        } finally { server.shutdown() }
    }
}
