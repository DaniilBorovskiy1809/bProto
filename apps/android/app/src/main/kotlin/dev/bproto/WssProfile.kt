package dev.bproto

import java.net.URI
import org.json.JSONObject

data class WssProfile(val url: String, val token: String) {
    companion object {
        fun parse(config: JSONObject): WssProfile? {
            require(!(config.has("tls") && config.has("wss"))) { "Choose one carrier" }
            if (!config.has("wss")) return null
            val value = config.getJSONObject("wss")
            require(!value.has("ech")) { "ECH is supported only by QUIC carrier" }
            val url = value.getString("url")
            val parsed = URI(url)
            require(parsed.scheme == "wss" && !parsed.host.isNullOrBlank() &&
                parsed.rawUserInfo == null && parsed.rawFragment == null &&
                (parsed.port == -1 || parsed.port in 1..65535)) { "Invalid WSS URL" }
            val token = value.getString("token")
            require(token.matches(Regex("[a-fA-F0-9]{64}"))) { "Invalid WSS token" }
            return WssProfile(url, token)
        }
    }
}
