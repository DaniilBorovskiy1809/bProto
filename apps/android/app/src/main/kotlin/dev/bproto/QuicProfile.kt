package dev.bproto

import org.json.JSONObject

data class QuicProfile(val hostname: String, val address: String, val port: Int, val token: String, val ech: EchProfile? = null) {
    companion object {
        /** A required-ECH selection must never auto-select a plain carrier. */
        fun requiresEchUri(uri: String): Boolean {
            val config = JSONObject(String(java.util.Base64.getUrlDecoder().decode(
                uri.removePrefix("bproto://import/")), Charsets.UTF_8))
            return config.optJSONObject("quic")?.has("ech") == true
        }

        fun parse(config: JSONObject): QuicProfile? {
            require(!config.has("ech")) { "ECH must be inside the QUIC profile" }
            require(listOf("tls", "wss", "quic").count { config.has(it) } <= 1) { "Choose one carrier" }
            if (!config.has("quic")) return null
            val value = config.getJSONObject("quic")
            val hostname = value.getString("hostname")
            val address = value.optString("server_host", hostname)
            val port = value.optInt("server_port", 443)
            val token = value.getString("token")
            require(hostname.length in 1..253 && hostname.matches(Regex("[a-zA-Z0-9.-]+"))) { "Invalid QUIC hostname" }
            require(address.isNotBlank() && address.none { it.isWhitespace() } && port in 1..65535) { "Invalid QUIC endpoint" }
            require(token.matches(Regex("[a-fA-F0-9]{64}"))) { "Invalid QUIC token" }
            return QuicProfile(hostname, address, port, token, if (value.has("ech")) EchProfile.parse(value.getJSONObject("ech")) else null)
        }
    }
}
