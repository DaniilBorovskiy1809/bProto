package dev.bproto

import android.util.Base64
import org.json.JSONObject

data class ServerProfile(val name: String, val uri: String, val routing: RoutingPolicy) {
    companion object {
        fun fromUri(uri: String, name: String = "Server", routing: RoutingPolicy = RoutingPolicy()): ServerProfile {
            require(uri.startsWith("bproto://import/")) { "Expected a bproto import key" }
            require(uri.length <= 65536) { "Import key is too large" }
            val encoded = uri.removePrefix("bproto://import/")
            val config = JSONObject(String(Base64.decode(encoded, Base64.URL_SAFE or Base64.NO_WRAP), Charsets.UTF_8))
            require(config.getString("server").isNotBlank()) { "Missing server address" }
            return ServerProfile(name.take(120), uri, routing)
        }
    }
}
