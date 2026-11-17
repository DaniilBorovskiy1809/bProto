package dev.bproto
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
class QuicProfileTest {
    private fun config() = JSONObject().put("quic", JSONObject()
        .put("hostname", "vpn.example.com").put("token", "a".repeat(64)))
    @Test fun defaults() {
        assertNull(QuicProfile.parse(JSONObject()))
        val parsed = QuicProfile.parse(config())!!
        assertEquals("vpn.example.com", parsed.address)
        assertEquals(443, parsed.port)
    }
    @Test fun rejectsAmbiguousCarrier() {
        for (other in listOf("tls", "wss")) {
            assertThrows(IllegalArgumentException::class.java) {
                QuicProfile.parse(config().put(other, JSONObject()))
            }
        }
    }
    @Test fun validatesEndpointAndToken() {
        for ((field, value) in listOf("hostname" to "bad\r\n", "server_port" to 0,
            "server_port" to 65536, "token" to "short", "server_host" to " ")) {
            val config = config()
            config.getJSONObject("quic").put(field, value)
            assertThrows(IllegalArgumentException::class.java) { QuicProfile.parse(config) }
        }
    }
}
