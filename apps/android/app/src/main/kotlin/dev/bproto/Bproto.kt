package dev.bproto

/**
 * JNI bridge to `libbproto.so`.
 *
 * This is an `object`, not a file-level class, and that is load-bearing: the
 * Rust entry points are `Java_dev_bproto_Bproto_<name>`, and the Kotlin
 * compiler turns an `object`'s members into *instance* methods on the singleton
 * `dev.bproto.Bproto` — exactly those names. Two rules follow:
 *
 *  * do **not** add `@JvmStatic` here: it would emit a second, static method
 *    with the same descriptor and the runtime would resolve the wrong one;
 *  * do not rename the members. Each name is half of a symbol pair.
 *
 * Threading contract (matches `crates/vpn-ffi/src/jni.rs`):
 *   [connect] and [pump] block — call them from a worker thread you own.
 *   [stop] is safe from any thread.
 */
object Bproto {

    init {
        System.loadLibrary("bproto")
    }

    /** Library version, e.g. `"0.1.0"`. */
    external fun version(): String

    /** Last error message from a failing call on *this* thread. */
    external fun lastError(): String

    /**
     * Run the handshake and return an opaque handle, or `0` on failure
     * ([lastError] explains). [config] is a `bproto://import/...` key URI or the
     * JSON `TunnelConfig`. Blocks until the handshake finishes or times out.
     */
    external fun connect(config: String): Long

    /** Address leased by the server, e.g. `"10.66.0.2"`. Empty on failure. */
    external fun assignedIp(handle: Long): String

    /** UDP descriptor of the server link. Pass it to `VpnService.protect`. */
    external fun socketFd(handle: Long): Int

    /**
     * Move packets between the tunnel and a tun descriptor until [stop] is
     * called. Blocks for the whole tunnel lifetime. Returns `null` on a clean
     * stop, or an error message to show the user.
     */
    external fun pump(handle: Long, fd: Int): String?

    /** Ask a running [pump] call to return. Safe from any thread. */
    external fun stop()

    /** Release a handle from [connect]. Never call while [pump] is using it. */
    external fun close(handle: Long)
}
