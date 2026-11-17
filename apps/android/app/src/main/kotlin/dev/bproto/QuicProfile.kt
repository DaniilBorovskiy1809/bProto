package dev.bproto

import org.json.JSONObject

data class QuicProfile(val hostname: String, val address: String, val port: Int, val token: String) {
    companion object {
        fun parse(config: JSONObject): QuicProfile? {
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
            return QuicProfile(hostname, address, port, token)
        }
    }
}
