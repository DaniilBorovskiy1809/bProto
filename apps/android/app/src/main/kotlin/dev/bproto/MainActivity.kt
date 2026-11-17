package dev.bproto

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import dev.bproto.client.R
import dev.bproto.client.databinding.ActivityMainBinding

/**
 * Single screen: paste a `bproto://import/...` key, press Connect.
 *
 * The key comes from the panel's QR code or from
 * `bproto import user1.client.toml` on the server; the URI carries the server
 * address, the PSK and the static public key, so nothing else has to be typed.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var pendingConfig: String? = null
    private var profiles: List<ServerProfile> = emptyList()
    private var selected: ServerProfile? = null
    private var automatic = false
    private var importing = false

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val config = pendingConfig
            pendingConfig = null
            if (result.resultCode == RESULT_OK && config != null) {
                send(BprotoVpnService.ACTION_CONNECT, config)
            } else {
                toast(getString(R.string.permission_needed))
            }
        }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            render(BprotoVpnService.lastStatus)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        androidx.core.view.ViewCompat.setOnApplyWindowInsetsListener(binding.root) { view, insets ->
            val bars = insets.getInsets(androidx.core.view.WindowInsetsCompat.Type.systemBars() or androidx.core.view.WindowInsetsCompat.Type.displayCutout())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }

        binding.importButton.setOnClickListener {
            binding.importPanel.visibility = if (binding.importPanel.visibility == android.view.View.VISIBLE) android.view.View.GONE else android.view.View.VISIBLE
        }
        binding.applyImportButton.setOnClickListener { connect() }
        binding.globe.setOnClickListener {
            if (BprotoVpnService.running || BprotoVpnService.connecting) send(BprotoVpnService.ACTION_DISCONNECT, null) else connect()
        }
        binding.routingButton.setOnClickListener {
            val profile = selected ?: runCatching { ServerProfile.fromUri(binding.configUri.text.toString().trim()) }.getOrNull()
            if (profile == null) toast("Select or import a server first") else {
                RoutingDialog.show(this, profile.routing) { policy ->
                    selected = profile.copy(routing = policy)
                    profiles = if (profiles.any { it.uri == profile.uri }) profiles.map { if (it.uri == profile.uri) selected!! else it } else profiles + selected!!
                    runCatching { ProfileStore(this).save(profiles) }.onFailure { toast("Could not save routing") }
                }
            }
        }
        binding.serverButton.setOnClickListener { showServers() }
        runCatching { ProfileStore(this).load() }.onSuccess {
            profiles = it
            val preferences = getPreferences(Context.MODE_PRIVATE)
            val index = preferences.getInt("selectedIndex", 0).coerceIn(0, (it.size - 1).coerceAtLeast(0))
            selected = it.getOrNull(index)
            automatic = preferences.getBoolean("automatic", false)
            binding.serverButton.text = if (automatic && it.isNotEmpty()) getString(R.string.automatic_server) else selected?.name ?: getString(R.string.choose_server)
            selected?.let { profile -> binding.configUri.setText(profile.uri) }
        }.onFailure { toast("Saved profiles could not be decrypted. Import your subscription again.") }
        binding.connectButton.setOnClickListener { connect() }
        binding.disconnectButton.setOnClickListener {
            send(BprotoVpnService.ACTION_DISCONNECT, null)
        }

        binding.importPanel.visibility = if (profiles.isEmpty()) android.view.View.VISIBLE else android.view.View.GONE
        render(BprotoVpnService.lastStatus)
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(BprotoVpnService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.registerReceiver(
                this,
                statusReceiver,
                filter,
                ContextCompat.RECEIVER_NOT_EXPORTED,
            )
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(statusReceiver, filter)
        }
    }

    override fun onStop() {
        super.onStop()
        runCatching { unregisterReceiver(statusReceiver) }
    }

    private fun connect() {
        if (importing) return
        val config = binding.configUri.text?.toString()?.trim().orEmpty()
        if (config.isEmpty()) {
            toast("paste a bproto:// key first")
            return
        }
        if (config.startsWith("https://")) {
            importing = true
            render(BprotoVpnService.lastStatus)
            Thread {
                val result = runCatching { SubscriptionFetcher.fetch(config) }
                runOnUiThread {
                    if (isDestroyed || isFinishing) return@runOnUiThread
                    importing = false
                    render(BprotoVpnService.lastStatus)
                    result.onSuccess { servers ->
                        profiles = servers
                        runCatching { ProfileStore(this).save(servers) }
                            .onFailure { toast("Imported, but profiles could not be saved") }
                        showServers()
                    }.onFailure { toast(it.message ?: "Subscription failed") }
                }
            }.start()
            return
        }
        val validation = runCatching { ServerProfile.fromUri(config) }
        if (validation.isFailure) { toast(validation.exceptionOrNull()?.message ?: "Invalid key"); return }
        val consent = VpnService.prepare(this)
        if (consent != null) {
            pendingConfig = config
            vpnPermission.launch(consent)
        } else {
            send(BprotoVpnService.ACTION_CONNECT, config)
        }
    }

    private fun showServers() {
        if (profiles.isEmpty()) { toast("Import an HTTPS subscription first"); return }
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Select server")
            .setNeutralButton("Forget profiles") { _, _ ->
                androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Forget all imported profiles?")
                    .setMessage("You will need your subscription URL or keys to import them again.")
                    .setNegativeButton("Cancel", null).setPositiveButton("Forget") { _, _ ->
                        runCatching { ProfileStore(this).save(emptyList()) }.onSuccess {
                            profiles = emptyList(); selected = null; automatic = false
                            binding.configUri.setText("")
                            binding.serverButton.setText(R.string.choose_server)
                            binding.importPanel.visibility = android.view.View.VISIBLE
                            render(BprotoVpnService.lastStatus)
                        }.onFailure { toast("Could not remove saved profiles") }
                    }.show()
            }
            .setItems((listOf("Automatic · first reachable") + profiles.map { it.name }).toTypedArray()) { _, index ->
                getPreferences(Context.MODE_PRIVATE).edit().putInt("selectedIndex", if (index == 0) 0 else index - 1)
                    .putBoolean("automatic", index == 0).apply()
                automatic = index == 0
                selected = profiles[if (automatic) 0 else index - 1]
                binding.configUri.setText(selected!!.uri)
                binding.serverButton.text = if (automatic) getString(R.string.automatic_server) else selected!!.name
                binding.importPanel.visibility = android.view.View.GONE
                render(BprotoVpnService.lastStatus)
            }.show()
    }

    private fun send(action: String, config: String?) {
        val intent = Intent(this, BprotoVpnService::class.java).setAction(action)
        if (config != null) {
            intent.putExtra(BprotoVpnService.EXTRA_CONFIG, config)
            if (automatic && selected?.uri == config) {
                intent.putStringArrayListExtra(BprotoVpnService.EXTRA_CANDIDATES, ArrayList(profiles.map { it.uri }))
            }
            selected?.takeIf { it.uri == config }?.let { profile ->
                val policy = org.json.JSONObject()
                    .put("routes", org.json.JSONArray(profile.routing.routes))
                    .put("dns", org.json.JSONArray(profile.routing.dns))
                    .put("bypass_apps", org.json.JSONArray(profile.routing.bypassApps))
                intent.putExtra(BprotoVpnService.EXTRA_ROUTING, policy.toString())
            }
        }
        startService(intent)
    }

    private fun render(status: String) {
        val active = BprotoVpnService.running
        val busy = BprotoVpnService.connecting
        binding.connectionTitle.setText(when {
            importing -> R.string.importing_profile
            busy -> R.string.state_connecting
            active -> R.string.state_connected
            else -> R.string.state_disconnected
        })
        binding.connectionHint.setText(when {
            busy -> R.string.tap_to_cancel
            active -> R.string.tap_to_disconnect
            else -> R.string.tap_to_connect
        })
        binding.profileSummary.text = if (profiles.isEmpty()) getString(R.string.no_profiles) else getString(R.string.profiles_count, profiles.size)
        binding.globe.connecting = busy
        binding.globe.isEnabled = !importing
        binding.globe.connected = BprotoVpnService.running
        binding.status.text = status.ifBlank { getString(R.string.status_idle) }
        binding.disconnectButton.isEnabled = BprotoVpnService.running || BprotoVpnService.connecting
        binding.connectButton.isEnabled = !BprotoVpnService.running && !BprotoVpnService.connecting && !importing
        binding.serverButton.isEnabled = !BprotoVpnService.running && !BprotoVpnService.connecting && !importing
        binding.routingButton.isEnabled = binding.serverButton.isEnabled
        binding.importButton.isEnabled = binding.serverButton.isEnabled
        binding.applyImportButton.isEnabled = binding.serverButton.isEnabled
        binding.configUri.isEnabled = binding.serverButton.isEnabled
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    override fun onResume() {
        super.onResume()
        render(BprotoVpnService.lastStatus)
    }


}
