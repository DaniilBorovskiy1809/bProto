package dev.bproto

import org.json.JSONObject

/** IPv4 routes are applied by Android; arbitrary domain rules require a DNS engine. */
data class RoutingPolicy(
    val routes: List<String> = listOf("0.0.0.0/0"),
    val dns: List<String> = listOf("1.1.1.1"),
    val bypassApps: List<String> = emptyList(),
) {
    companion object {
        fun parse(value: JSONObject?): RoutingPolicy {
            if (value == null) return RoutingPolicy()
            fun strings(key: String, defaults: List<String>): List<String> {
                val array = value.optJSONArray(key) ?: return defaults
                require(array.length() <= 128) { "Too many $key entries" }
                return (0 until array.length()).map { array.getString(it).trim() }.distinct()
            }
            val policy = RoutingPolicy(
                strings("routes", listOf("0.0.0.0/0")),
                strings("dns", listOf("1.1.1.1")),
                strings("bypass_apps", emptyList()),
            )
            require(policy.routes.isNotEmpty()) { "At least one route is required" }
            require(policy.dns.isNotEmpty()) { "At least one DNS server is required" }
            policy.routes.forEach { cidr ->
                val parts = cidr.split('/')
                require(parts.size == 2 && ipv4(parts[0])) { "Invalid IPv4 route: $cidr" }
                val prefix = parts[1].toIntOrNull()
                require(prefix != null && prefix in 0..32) { "Invalid prefix: $cidr" }
                val octets = parts[0].split('.').map { it.toLong() }
                val address = octets.fold(0L) { acc, octet -> (acc shl 8) or octet }
                val hostMask = if (prefix == 32) 0L else (1L shl (32 - prefix)) - 1
                require(address and hostMask == 0L) { "Route must use a network address: $cidr" }
            }
            policy.dns.forEach { require(ipv4(it)) { "DNS must be an IPv4 literal" } }
            policy.bypassApps.forEach {
                require(it.matches(Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"))) { "Invalid application package" }
            }
            return policy
        }

        private fun ipv4(value: String): Boolean {
            val parts = value.split('.')
            return parts.size == 4 && parts.all {
                it.isNotEmpty() && it.all(Char::isDigit) && it.toIntOrNull() in 0..255 && (it == "0" || !it.startsWith("0"))
            }
        }
    }
}
