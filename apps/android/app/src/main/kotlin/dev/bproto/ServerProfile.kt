package dev.bproto

import java.util.Base64
import org.json.JSONObject

data class ServerProfile(val name: String, val uri: String, val routing: RoutingPolicy) {
    companion object {
        fun fromUri(uri: String, name: String = "Server", routing: RoutingPolicy = RoutingPolicy()): ServerProfile {
            require(uri.startsWith("bproto://import/")) { "Expected a bproto import key" }
            require(uri.length <= 65536) { "Import key is too large" }
            val encoded = uri.removePrefix("bproto://import/")
            val config = JSONObject(String(Base64.getUrlDecoder().decode(encoded), Charsets.UTF_8))
            require(config.optInt("v", 1) == 1) { "Unsupported import version" }
            for (field in listOf("psk", "tag_key")) {
                require(config.getString(field).matches(Regex("[0-9a-fA-F]{64}"))) { "Invalid $field" }
            }
            require(config.getLong("uid") > 0) { "Invalid user ID" }
            val endpoint = java.net.URI("udp://${config.getString("server")}")
            require(endpoint.host != null && endpoint.port in 1..65535 && endpoint.userInfo == null && endpoint.rawPath.isNullOrEmpty() && endpoint.rawQuery == null && endpoint.rawFragment == null) { "Invalid server endpoint" }
            require(config.getString("sni").isNotBlank()) { "Missing donor SNI" }
            return ServerProfile(name.take(120), uri, routing)
        }
    }
}
