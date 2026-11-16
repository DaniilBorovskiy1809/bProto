package dev.bproto

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class RoutingPolicyTest {
    @Test fun fullTunnelDefaults() {
        val policy = RoutingPolicy.parse(null)
        assertEquals(listOf("0.0.0.0/0"), policy.routes)
        assertEquals(listOf("1.1.1.1"), policy.dns)
        assertTrue(policy.bypassApps.isEmpty())
    }

    @Test fun selectiveRoutesAndExclusionsSurviveParsing() {
        val policy = RoutingPolicy.parse(JSONObject("""{"routes":["10.0.0.0/8","192.168.0.0/16"],"dns":["9.9.9.9"],"bypass_apps":["org.example.browser"]}"""))
        assertEquals(2, policy.routes.size)
        assertEquals(listOf("org.example.browser"), policy.bypassApps)
    }

    @Test fun malformedNetworksAreRejected() {
        for (route in listOf("10.1.2.3/8", "::/0", "0.0.0.0/33", "1.2.3.4", "999.0.0.0/8", "01.0.0.0/8")) {
            try {
                RoutingPolicy.parse(JSONObject().put("routes", org.json.JSONArray(listOf(route))))
                fail("Accepted $route")
            } catch (_: IllegalArgumentException) { }
        }
    }
}
