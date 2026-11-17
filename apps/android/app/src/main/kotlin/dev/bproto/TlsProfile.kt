package dev.bproto

import org.json.JSONObject

data class TlsProfile(val hostname: String, val address: String, val port: Int, val token: String) {
    companion object {
        fun parse(config: JSONObject): TlsProfile? {
            if (!config.has("tls")) return null
            val tls = config.getJSONObject("tls")
            require(!tls.has("ech")) { "ECH is supported only by QUIC carrier" }
            val host = tls.getString("hostname")
            val address = tls.optString("server_host", host)
            val port = tls.optInt("server_port", 443)
            val token = tls.getString("token")
            require(host.length <= 253 && host.matches(Regex("[a-zA-Z0-9.-]+"))) { "Invalid TLS hostname" }
            require(address.isNotBlank() && address.none { it.isWhitespace() } && port in 1..65535) { "Invalid TLS endpoint" }
            require(token.matches(Regex("[a-fA-F0-9]{64}"))) { "Invalid TLS token" }
            return TlsProfile(host, address, port, token)
        }
    }
}
