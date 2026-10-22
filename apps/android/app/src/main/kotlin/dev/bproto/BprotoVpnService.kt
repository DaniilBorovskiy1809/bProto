package dev.bproto

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import dev.bproto.client.R

/**
 * The tunnel, built on the Android [VpnService] contract.
 *
 * Order matters and is the whole point of this class:
 *
 * 1. `Bproto.connect()` runs the handshake **before** the VPN exists, so the
 *    server learns which address to lease.
 * 2. `protect()` marks the UDP socket from step 1 as exempt from the tunnel.
 *    Without it the encapsulated packets are routed back into our own tunnel and
 *    nothing gets through.
 * 3. `establish()` creates the tun descriptor; the address from step 1 is what
 *    we hand to the builder.
 * 4. `Bproto.pump()` moves packets until `stop()`.
 *
 * The native `run` call blocks, so it lives on a thread we own; the service
 * object itself only ever touches it through `stop()`.
 */
class BprotoVpnService : VpnService() {

    companion object {
        private const val TAG = "bproto"
        private const val CHANNEL_ID = "bproto-tunnel"
        private const val NOTIFICATION_ID = 1

        const val ACTION_CONNECT = "dev.bproto.client.CONNECT"
        const val ACTION_DISCONNECT = "dev.bproto.client.DISCONNECT"
        const val EXTRA_CONFIG = "config"

        /** Broadcast the activity listens to for status updates. */
        const val ACTION_STATUS = "dev.bproto.client.STATUS"

        /** Tunnel MTU. Must match `MAX_DATAGRAM` minus the encapsulating header. */
        const val MTU = 1251
        private const val PREFIX = 24

        /** Resolver pushed to the system. Change it to your own if you run one. */
        private const val DNS = "1.1.1.1"

        /**
         * Capture address for IPv6. The MVP tunnel carries IPv4 only, so we do
         * not route v6 anywhere — but we do have to *catch* it, otherwise v6
         * traffic walks out of the device in the clear while the user believes
         * they are tunnelled. `62 70 72 6f 74 6f` is "bproto" in hex.
         */
        private const val IPV6_ADDRESS = "fd00:6270:726f:746f::2"
        private const val IPV6_PREFIX = 64

        /** Last status line, for the activity to render after a reconnect. */
        @Volatile
        var lastStatus: String = ""

        @Volatile
        var running: Boolean = false
            private set
    }

    // Touched from the main thread (start) and the tunnel thread (finally).
    @Volatile
    private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val config = intent.getStringExtra(EXTRA_CONFIG)
                if (config.isNullOrBlank()) {
                    publish("no key: nothing to connect with")
                } else {
                    start(config)
                }
            }
            ACTION_DISCONNECT -> stopTunnel()
            else -> Unit
        }
        return START_NOT_STICKY
    }

    /** Start the tunnel on a private thread. No-op if one is already running. */
    fun start(config: String) {
        if (worker != null) {
            return
        }
        goForeground()
        worker = Thread({ pump(config) }, "bproto-vpn").apply { start() }
    }

    fun stopTunnel() {
        Bproto.stop()
    }

    override fun onRevoke() {
        // The system took the tunnel away (another VPN, or the user revoked it).
        publish("revoked by the system")
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    private fun pump(config: String) {
        var handle = 0L
        var tun: ParcelFileDescriptor? = null
        try {
            handle = Bproto.connect(config)
            if (handle == 0L) {
                publish("handshake failed: ${Bproto.lastError()}")
                return
            }

            val address = Bproto.assignedIp(handle)
            if (address.isEmpty()) {
                publish("server leased no address: ${Bproto.lastError()}")
                return
            }

            // Step 2: the server link must not enter our own tunnel.
            val socket = Bproto.socketFd(handle)
            if (socket < 0) {
                publish("no socket descriptor: ${Bproto.lastError()}")
                return
            }
            if (!protect(socket)) {
                publish("could not protect socket $socket")
                return
            }

            // Step 3: the tun interface.
            val (established, warning) = establishTunnel(address)
            tun = established
            if (tun == null) {
                publish("establish() was refused (no VPN permission?): $warning")
                return
            }

            running = true
            if (warning != null) {
                publish("connected as $address — warning: $warning")
            } else {
                publish("connected as $address")
            }

            // Step 4: this call blocks until stopTunnel()/onRevoke()/an error.
            val error = Bproto.pump(handle, tun.fd)
            if (error != null) {
                publish("tunnel stopped: $error")
            } else {
                publish("disconnected")
            }
        } catch (t: Throwable) {
            Log.w(TAG, "tunnel failed", t)
            publish("failed: ${t.message ?: t.javaClass.simpleName}")
        } finally {
            running = false
            Bproto.stop()
            if (handle != 0L) {
                Bproto.close(handle)
            }
            runCatching { tun?.close() }
            worker = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    /**
     * Establishes the tun interface.
     *
     * The tunnel itself carries IPv4 only. IPv6 is *captured and dropped* so
     * that v6 traffic cannot leave the device in the clear; the ULA in
     * [IPV6_ADDRESS] exists for that alone. Capturing it is best effort: some
     * Android builds refuse an IPv6 address in their native address-config
     * path (logcat `VpnJni: Invalid address`), which would otherwise take the
     * whole tunnel down with it. If that happens we retry IPv4-only and return
     * a warning that gets surfaced in the UI — a silent fallback would hide an
     * IPv6 leak, and a loud one is strictly better than a dead tunnel.
     *
     * @return the descriptor, plus an optional warning describing what was lost.
     */
    private fun establishTunnel(address: String): Pair<ParcelFileDescriptor?, String?> {
        return try {
            vpnBuilder(address)
                .addAddress(IPV6_ADDRESS, IPV6_PREFIX)
                .addRoute("::", 0)
                .establish() to null
        } catch (refused: IllegalArgumentException) {
            val reason = refused.message ?: "the framework refused the IPv6 address"
            Log.w(TAG, "IPv6 capture refused ($reason); retrying IPv4-only")
            try {
                val warning = "IPv6 not captured ($reason): v6 traffic is not tunnelled"
                vpnBuilder(address).establish() to warning
            } catch (failed: IllegalArgumentException) {
                null to (failed.message ?: failed.javaClass.simpleName)
            }
        }
    }

    private fun vpnBuilder(address: String): Builder {
        val builder = Builder()
            .setSession("bProto")
            .setMtu(MTU)
            .addAddress(address, PREFIX)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(DNS)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        return builder
    }

    private fun goForeground() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel),
                NotificationManager.IMPORTANCE_LOW,
            )
            manager.createNotificationChannel(channel)
        }
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notification: Notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun publish(status: String) {
        lastStatus = status
        Log.i(TAG, status)
        sendBroadcast(Intent(ACTION_STATUS).setPackage(packageName))
    }
}
