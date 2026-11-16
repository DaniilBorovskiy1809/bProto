package dev.bproto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Device-local encrypted profile storage. Keys and subscription credentials never enter backups. */
class ProfileStore(private val context: Context) {
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey("bproto-profiles", null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder("bproto-profiles", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }

    fun save(profiles: List<ServerProfile>) {
        val array = JSONArray()
        profiles.forEach { profile ->
            array.put(JSONObject().put("label", profile.name).put("uri", profile.uri)
                .put("routing", JSONObject().put("routes", JSONArray(profile.routing.routes))
                    .put("dns", JSONArray(profile.routing.dns)).put("bypass_apps", JSONArray(profile.routing.bypassApps))))
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val bytes = cipher.iv + cipher.doFinal(array.toString().toByteArray(Charsets.UTF_8))
        val file = android.util.AtomicFile(java.io.File(context.noBackupFilesDir, "profiles.enc"))
        val stream = file.startWrite()
        try { stream.write(bytes); file.finishWrite(stream) } catch (error: Exception) { file.failWrite(stream); throw error }
    }

    fun load(): List<ServerProfile> {
        val file = java.io.File(context.noBackupFilesDir, "profiles.enc")
        if (!file.exists()) return emptyList()
        require(file.length() <= 2097152) { "Profile store too large" }
        val bytes = android.util.AtomicFile(file).readFully()
        require(bytes.size >= 28) { "Invalid encrypted profile store" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
        val entries = JSONArray(String(cipher.doFinal(bytes.copyOfRange(12, bytes.size)), Charsets.UTF_8))
        require(entries.length() <= 128) { "Too many saved profiles" }
        return (0 until entries.length()).map {
            val entry = entries.getJSONObject(it)
            ServerProfile.fromUri(entry.getString("uri"), entry.getString("label"), RoutingPolicy.parse(entry.getJSONObject("routing")))
        }
    }
}
