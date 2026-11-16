package dev.bproto

import java.net.HttpURLConnection
import java.net.URL

object SubscriptionFetcher {
    fun fetch(address: String): List<ServerProfile> {
        val parsed = android.net.Uri.parse(address)
        val requested = if (parsed.getQueryParameter("format") == null)
            parsed.buildUpon().appendQueryParameter("format", "json").build().toString() else address
        val url = URL(requested)
        require(url.protocol == "https" && url.userInfo == null) { "Subscription URL must use HTTPS without embedded credentials" }
        val connection = url.openConnection() as HttpURLConnection
        connection.connectTimeout = 10000
        connection.readTimeout = 10000
        connection.instanceFollowRedirects = false
        connection.setRequestProperty("Accept", "application/json, text/plain")
        try {
            require(connection.responseCode == 200) { "Subscription HTTP ${connection.responseCode}" }
            val bytes = connection.inputStream.use { input ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    require(output.size() + count <= 1048576) { "Subscription exceeds 1 MiB" }
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
            require(bytes.size <= 1048576) { "Subscription exceeds 1 MiB" }
            return SubscriptionParser.parse(String(bytes, Charsets.UTF_8))
        } finally { connection.disconnect() }
    }
}
