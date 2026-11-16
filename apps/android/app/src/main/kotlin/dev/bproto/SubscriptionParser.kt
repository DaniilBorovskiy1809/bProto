package dev.bproto

import android.util.Base64
import org.json.JSONObject

object SubscriptionParser {
    fun parse(body: String): List<ServerProfile> {
        require(body.length <= 1048576) { "Subscription exceeds 1 MiB" }
        val text = body.trim()
        val profiles = if (text.startsWith("{")) {
            val document = JSONObject(text)
            val routing = RoutingPolicy.parse(document.optJSONObject("routing"))
            val entries = document.getJSONArray("clients")
            require(entries.length() <= 128) { "Too many servers" }
            (0 until entries.length()).map { index ->
                val entry = entries.getJSONObject(index)
                ServerProfile.fromUri(entry.getString("uri"), entry.optString("label").takeIf { it.isNotBlank() && it != "null" } ?: "Server ${index + 1}", routing)
            }
        } else {
            val decoded = if (text.startsWith("bproto://")) text else
                String(Base64.decode(text, Base64.DEFAULT), Charsets.UTF_8)
            val lines = decoded.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
            require(lines.size <= 128) { "Too many servers" }
            lines.mapIndexed { index, uri -> ServerProfile.fromUri(uri, "Server ${index + 1}") }
        }
        require(profiles.isNotEmpty()) { "Subscription has no active servers" }
        return profiles.distinctBy { it.uri }
    }
}
