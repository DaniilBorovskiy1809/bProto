package dev.bproto

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class SubscriptionParserTest {
    private fun uri(id: Int = 1): String {
        val body = JSONObject().put("v", 1).put("server", "203.0.113.10:443").put("uid", id)
            .put("sni", "example.org").put("psk", "ab".repeat(32)).put("tag_key", "cd".repeat(32))
        return "bproto://import/" + Base64.getUrlEncoder().withoutPadding().encodeToString(body.toString().toByteArray())
    }
    @Test fun plainSubscriptionKeys() {
        val profiles = SubscriptionParser.parse(uri(1) + "\n" + uri(2))
        assertEquals(2, profiles.size)
        assertEquals(uri(2), profiles[1].uri)
    }
    @Test fun base64SubscriptionKeys() {
        val encoded = Base64.getEncoder().encodeToString((uri(1) + "\n" + uri(2)).toByteArray())
        assertEquals(2, SubscriptionParser.parse(encoded).size)
    }
    @Test fun jsonRoutingInheritance() {
        val document = JSONObject().put("clients", JSONArray().put(JSONObject().put("uri", uri()).put("label", "Paris")))
            .put("routing", JSONObject().put("routes", JSONArray(listOf("10.0.0.0/8"))).put("dns", JSONArray(listOf("9.9.9.9"))))
        val profile = SubscriptionParser.parse(document.toString()).single()
        assertEquals("Paris", profile.name)
        assertEquals(listOf("10.0.0.0/8"), profile.routing.routes)
        assertEquals(listOf("9.9.9.9"), profile.routing.dns)
    }
    @Test fun duplicateKeyDeduplication() {
        assertEquals(1, SubscriptionParser.parse(uri() + "\n" + uri()).size)
    }
    @Test(expected = IllegalArgumentException::class) fun emptySubscriptionRejected() {
        SubscriptionParser.parse("{\"clients\":[]}")
    }
    @Test(expected = IllegalArgumentException::class) fun profileLimitEnforced() {
        SubscriptionParser.parse((1..129).joinToString("\n") { uri(it) })
    }
    @Test(expected = IllegalArgumentException::class) fun subscriptionByteLimit() {
        SubscriptionParser.parse("A".repeat(1048577))
    }
    @Test fun nullServerLabelsUseReadableFallback() {
        val body = JSONObject().put("clients", JSONArray().put(JSONObject().put("uri", uri()).put("label", JSONObject.NULL)))
        assertEquals("Server 1", SubscriptionParser.parse(body.toString()).single().name)
    }
    @Test(expected = IllegalArgumentException::class) fun foreignUriRejected() {
        ServerProfile.fromUri("https://example.org/key")
    }
    @Test(expected = IllegalArgumentException::class) fun shortSecretRejected() {
        val body = JSONObject().put("v", 1).put("server", "203.0.113.10:443").put("uid", 1)
            .put("sni", "example.org").put("psk", "ab").put("tag_key", "cd".repeat(32))
        ServerProfile.fromUri("bproto://import/" + Base64.getUrlEncoder().encodeToString(body.toString().toByteArray()))
    }
}
