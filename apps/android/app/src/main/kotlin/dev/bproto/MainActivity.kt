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
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.connectButton.setOnClickListener { connect() }
        binding.disconnectButton.setOnClickListener {
            send(BprotoVpnService.ACTION_DISCONNECT, null)
        }
        binding.configUri.setText(savedInstanceState?.getString("config").orEmpty())
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
        val config = binding.configUri.text?.toString()?.trim().orEmpty()
        if (config.isEmpty()) {
            toast("paste a bproto:// key first")
            return
        }
        val consent = VpnService.prepare(this)
        if (consent != null) {
            pendingConfig = config
            vpnPermission.launch(consent)
        } else {
            send(BprotoVpnService.ACTION_CONNECT, config)
        }
    }

    private fun send(action: String, config: String?) {
        val intent = Intent(this, BprotoVpnService::class.java).setAction(action)
        if (config != null) {
            intent.putExtra(BprotoVpnService.EXTRA_CONFIG, config)
        }
        startService(intent)
    }

    private fun render(status: String) {
        binding.status.text = status
        binding.disconnectButton.isEnabled = BprotoVpnService.running
        binding.connectButton.isEnabled = !BprotoVpnService.running
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    override fun onResume() {
        super.onResume()
        render(BprotoVpnService.lastStatus)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString("config", binding.configUri.text?.toString())
    }
}
