package dev.bproto

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class TlsProfileTest {
    private fun config() = JSONObject().put("tls", JSONObject()
        .put("hostname", "vpn.example.com").put("token", "a".repeat(64)))
    @Test fun nativeProfilesRemainNative() {
        assertNull(TlsProfile.parse(JSONObject()))
    }
    @Test fun defaultsAreVerifiedHostnameAnd443() {
        val parsed = TlsProfile.parse(config())!!
        assertEquals("vpn.example.com", parsed.address)
        assertEquals(443, parsed.port)
    }
    @Test fun acceptsExplicitEndpoint() {
        val config = config()
        config.getJSONObject("tls").put("server_host", "192.0.2.1").put("server_port", 8443)
        assertEquals(8443, TlsProfile.parse(config)!!.port)
    }
    @Test(expected = IllegalArgumentException::class) fun rejectsHeaderInjection() {
        val config = config()
        config.getJSONObject("tls").put("hostname", "host\r\nInjected: yes")
        TlsProfile.parse(config)
    }
    @Test(expected = IllegalArgumentException::class) fun rejectsShortToken() {
        val config = config()
        config.getJSONObject("tls").put("token", "short")
        TlsProfile.parse(config)
    }
    @Test(expected = IllegalArgumentException::class) fun rejectsInvalidPort() {
        val config = config()
        config.getJSONObject("tls").put("server_port", 65536)
        TlsProfile.parse(config)
    }
}
