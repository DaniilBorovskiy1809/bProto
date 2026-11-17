package dev.bproto

import java.util.Base64
import org.json.JSONObject

/** An operator-provided public ECHConfigList; required means no SNI fallback. */
data class EchProfile(val bytes: ByteArray, val expires: Long) {
    companion object {
        fun parse(value: JSONObject?, now: Long = System.currentTimeMillis() / 1000): EchProfile? {
            if (value == null) return null
            require(value.getString("mode") == "required") { "Only required ECH is supported" }
            val encoded = value.getString("config_list")
            require(encoded.length <= 5500) { "ECH configuration too large" }
            val bytes = Base64.getDecoder().decode(encoded)
            require(bytes.size in 2..4096) { "Invalid ECH configuration size" }
            val expires = value.getLong("expires_unix_secs")
            require(expires > now) { "ECH configuration expired" }
            return EchProfile(bytes, expires)
        }
    }
}
