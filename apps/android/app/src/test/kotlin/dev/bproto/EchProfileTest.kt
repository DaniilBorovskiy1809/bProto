package dev.bproto
import java.util.Base64
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
class EchProfileTest {
    private fun profile() = JSONObject().put("mode", "required")
        .put("config_list", Base64.getEncoder().encodeToString(byteArrayOf(0, 0)))
        .put("expires_unix_secs", 200)
    @Test fun absenceDisablesEch() { assertNull(EchProfile.parse(null, 100)) }
    @Test fun parsesPublicConfig() {
        val result = EchProfile.parse(profile(), 100)!!
        assertEquals(200L, result.expires)
        assertArrayEquals(byteArrayOf(0, 0), result.bytes)
    }
    @Test fun expiryAndInvalidModesAreRejected() {
        assertThrows(IllegalArgumentException::class.java) { EchProfile.parse(profile(), 200) }
        for (mode in listOf("optional", "disabled", "grease", "")) {
            assertThrows(IllegalArgumentException::class.java) { EchProfile.parse(profile().put("mode", mode), 100) }
        }
    }
    @Test fun malformedEncodingIsRejected() {
        for (value in listOf("", "!", Base64.getEncoder().encodeToString(ByteArray(4097)))) {
            assertThrows(IllegalArgumentException::class.java) { EchProfile.parse(profile().put("config_list", value), 100) }
        }
    }

    @Test fun unsupportedCarriersRejectEch() {
        val token = "a".repeat(64)
        val tls = JSONObject().put("tls", JSONObject().put("hostname", "vpn.example")
            .put("token", token).put("ech", profile()))
        assertThrows(IllegalArgumentException::class.java) { TlsProfile.parse(tls) }
        val wss = JSONObject().put("wss", JSONObject().put("url", "wss://vpn.example/")
            .put("token", token).put("ech", profile()))
        assertThrows(IllegalArgumentException::class.java) { WssProfile.parse(wss) }
    }
    @Test fun nullEchCannotSilentlyDisableRequirement() {
        val quic = JSONObject().put("quic", JSONObject().put("hostname", "vpn.example")
            .put("token", "a".repeat(64)).put("ech", JSONObject.NULL))
        assertThrows(org.json.JSONException::class.java) { QuicProfile.parse(quic) }
    }

    @Test fun requiredSelectionCanExcludePlainFallbacks() {
        fun uri(value: JSONObject) = "bproto://import/" + Base64.getUrlEncoder().withoutPadding()
            .encodeToString(value.toString().toByteArray())
        assertFalse(QuicProfile.requiresEchUri(uri(JSONObject())))
        assertFalse(QuicProfile.requiresEchUri(uri(JSONObject().put("quic", JSONObject()))))
        assertTrue(QuicProfile.requiresEchUri(uri(JSONObject().put("quic", JSONObject().put("ech", profile())))))
    }
}
