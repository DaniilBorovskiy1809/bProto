//! C-ABI surface for the mobile and desktop clients.
//!
//! This crate is the only place in the workspace that exposes `unsafe` FFI. All
//! protocol logic lives in `vpn-core`; here we only marshal bytes and translate
//! errors into strings the platform layer can show.
//!
//! Design rules:
//!
//! * every function that can fail returns a null/negative value and stores a
//!   thread-local error string retrievable via [`bproto_last_error`];
//! * calls that need the datapath block the calling thread on a private tokio
//!   runtime — the platform layer is expected to call them from its own worker
//!   thread, never from the UI thread;
//! * pointers returned to the caller are freed by the matching `_free`.

#![allow(unsafe_code)]

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr;

use vpn_client::Tunnel;
use vpn_core::TunnelConfig;
use vpn_core::auth::{TAG_LEN, compute_tag};
use vpn_core::config::from_hex;
use vpn_core::crypto::KEY_LEN;

/// The JNI tier is Unix-only: it does descriptor I/O with `poll(2)`/`fcntl(2)`,
/// which Android and iOS both have and Windows does not. The feature is a no-op
/// elsewhere rather than a build error.
#[cfg(all(feature = "jni", unix))]
mod jni;

thread_local! {
    static LAST_ERROR: RefCell<CString> =
        RefCell::new(CString::new("no error").expect("static string is valid"));
    static LAST_VERSION: CString =
        CString::new(env!("CARGO_PKG_VERSION")).expect("version has no NUL");
}

fn set_error(msg: &str) {
    let sanitized = msg.replace('\0', " ");
    LAST_ERROR.with(|e| {
        *e.borrow_mut() =
            CString::new(sanitized).unwrap_or_else(|_| CString::new("error").unwrap());
    });
}

/// The calling thread's last error as an owned `String`. Used by the JNI tier,
/// which cannot return a borrowed pointer to Kotlin.
#[cfg(all(feature = "jni", unix))]
fn last_error_string() -> String {
    LAST_ERROR.with(|e| e.borrow().to_string_lossy().into_owned())
}

/// Borrow the calling thread's last error string. Valid until the next call on
/// the same thread. Never free this pointer.
#[unsafe(no_mangle)]
pub extern "C" fn bproto_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}

/// Library version, as a NUL-terminated static string. Never free this pointer.
#[unsafe(no_mangle)]
pub extern "C" fn bproto_version() -> *const c_char {
    LAST_VERSION.with(|v| v.as_ptr())
}

/// Stats snapshot, `#[repr(C)]` so Swift/Kotlin can lay it out directly.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BprotoStats {
    /// Smoothed RTT in microseconds.
    pub rtt_us: u64,
    /// Congestion window in bytes.
    pub cwnd_bytes: u64,
    /// Bytes received (post-decrypt).
    pub rx_bytes: u64,
    /// Bytes sent (pre-encrypt).
    pub tx_bytes: u64,
    /// Datagrams dropped (replay / auth failure).
    pub dropped: u64,
    /// Seconds since the session was established.
    pub uptime_s: u64,
}

/// Opaque tunnel handle: a runtime plus a live [`Tunnel`].
pub struct BprotoTunnel {
    rt: tokio::runtime::Runtime,
    tunnel: Tunnel,
}

/// Connect a tunnel from a JSON-serialized `TunnelConfig`, or from a
/// `bproto://import/...` key URI (what the panel's QR code contains).
///
/// Returns a handle on success or null on failure (see [`bproto_last_error`]).
/// Blocks the calling thread until the handshake completes or times out.
///
/// # Safety
///
/// `config_json` must be null or point to a valid NUL-terminated C string that
/// stays alive for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bproto_connect(config_json: *const c_char) -> *mut BprotoTunnel {
    if config_json.is_null() {
        set_error("config_json is null");
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees a valid NUL-terminated string.
    let text = match unsafe { CStr::from_ptr(config_json) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("config_json is not valid UTF-8");
            return ptr::null_mut();
        }
    };
    let cfg: TunnelConfig = if text.trim_start().starts_with("bproto://") {
        match vpn_core::config::from_import_uri(text) {
            Ok(c) => c,
            Err(e) => {
                set_error(&format!("invalid key URI: {e}"));
                return ptr::null_mut();
            }
        }
    } else {
        match serde_json::from_str(text) {
            Ok(c) => c,
            Err(e) => {
                set_error(&format!("invalid config: {e}"));
                return ptr::null_mut();
            }
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            set_error(&format!("cannot start runtime: {e}"));
            return ptr::null_mut();
        }
    };
    match rt.block_on(Tunnel::connect(cfg)) {
        Ok(tunnel) => Box::into_raw(Box::new(BprotoTunnel { rt, tunnel })),
        Err(e) => {
            set_error(&format!("connect failed: {e}"));
            ptr::null_mut()
        }
    }
}

fn tunnel_ref<'a>(tunnel: *mut BprotoTunnel) -> Result<&'a BprotoTunnel, &'static str> {
    // SAFETY: the caller contract promises this came from bproto_connect.
    unsafe { tunnel.as_ref() }.ok_or("tunnel handle is null")
}

/// Raw descriptor of the tunnel's UDP socket, or -1 on failure.
///
/// Android needs it to call `VpnService.protect(fd)` before the tunnel starts
/// carrying traffic; iOS and Linux builds can ignore it. The descriptor stays
/// owned by the tunnel — never close it.
///
/// # Safety
///
/// `tunnel` must be null or a live handle.
#[cfg(unix)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bproto_socket_fd(tunnel: *mut BprotoTunnel) -> c_int {
    let t = match tunnel_ref(tunnel) {
        Ok(t) => t,
        Err(e) => {
            set_error(e);
            return -1;
        }
    };
    t.tunnel.socket_fd() as c_int
}

/// The address the server leased to this tunnel, as 4 bytes.
///
/// `out` must point to at least 4 writable bytes. Returns 0 on success.
///
/// # Safety
///
/// `tunnel` must be a live handle and `out` must be writable for 4 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bproto_assigned_ip(tunnel: *mut BprotoTunnel, out: *mut u8) -> c_int {
    if out.is_null() {
        set_error("out is null");
        return -1;
    }
    let t = match tunnel_ref(tunnel) {
        Ok(t) => t,
        Err(e) => {
            set_error(e);
            return -1;
        }
    };
    let octets = t.tunnel.assigned_ip().octets();
    // SAFETY: caller promised 4 writable bytes.
    unsafe { ptr::copy_nonoverlapping(octets.as_ptr(), out, 4) };
    0
}

/// Send one IP packet into the tunnel.
///
/// Returns the number of bytes consumed, or -1 on failure.
///
/// # Safety
///
/// `tunnel` must be a live handle and `buf` must be readable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bproto_send(
    tunnel: *mut BprotoTunnel,
    buf: *const u8,
    len: usize,
) -> c_int {
    if buf.is_null() || len == 0 {
        set_error("empty buffer");
        return -1;
    }
    let t = match tunnel_ref(tunnel) {
        Ok(t) => t,
        Err(e) => {
            set_error(e);
            return -1;
        }
    };
    // SAFETY: caller promised `len` readable bytes.
    let packet = unsafe { std::slice::from_raw_parts(buf, len) };
    match t.rt.block_on(t.tunnel.send_ip_packet(packet)) {
        Ok(true) => len as c_int,
        // The congestion window was full: nothing was sent, and that is not an
        // error — the transport would have dropped the packet anyway.
        Ok(false) => 0,
        Err(e) => {
            set_error(&format!("send failed: {e}"));
            -1
        }
    }
}

/// Receive the next IP packet into `buf` (capacity `cap`).
///
/// Returns the packet length, or -1 on failure (including "does not fit").
/// Blocks the calling thread until a packet arrives.
///
/// # Safety
///
/// `tunnel` must be a live handle and `buf` must be writable for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bproto_recv(tunnel: *mut BprotoTunnel, buf: *mut u8, cap: usize) -> c_int {
    if buf.is_null() || cap == 0 {
        set_error("empty buffer");
        return -1;
    }
    let t = match tunnel_ref(tunnel) {
        Ok(t) => t,
        Err(e) => {
            set_error(e);
            return -1;
        }
    };
    match t.rt.block_on(t.tunnel.recv_ip_packet()) {
        Ok(packet) => {
            if packet.len() > cap {
                set_error("packet larger than the provided buffer");
                return -1;
            }
            // SAFETY: caller promised `cap` writable bytes and we checked len <= cap.
            unsafe { ptr::copy_nonoverlapping(packet.as_ptr(), buf, packet.len()) };
            packet.len() as c_int
        }
        Err(e) => {
            set_error(&format!("recv failed: {e}"));
            -1
        }
    }
}

/// Like [`bproto_recv`], but gives up after `timeout_ms`.
///
/// Returns the packet length, `-2` when the timeout expires with no packet, or
/// `-1` on failure. iOS uses this so the receive loop can observe a stop flag
/// instead of blocking forever inside the extension.
///
/// # Safety
///
/// `tunnel` must be a live handle and `buf` must be writable for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bproto_recv_timeout(
    tunnel: *mut BprotoTunnel,
    buf: *mut u8,
    cap: usize,
    timeout_ms: u64,
) -> c_int {
    if buf.is_null() || cap == 0 {
        set_error("empty buffer");
        return -1;
    }
    let t = match tunnel_ref(tunnel) {
        Ok(t) => t,
        Err(e) => {
            set_error(e);
            return -1;
        }
    };
    let waited = t.rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            t.tunnel.recv_ip_packet(),
        )
        .await
    });
    match waited {
        Ok(Ok(packet)) => {
            if packet.len() > cap {
                set_error("packet larger than the provided buffer");
                return -1;
            }
            // SAFETY: caller promised `cap` writable bytes and we checked len <= cap.
            unsafe { ptr::copy_nonoverlapping(packet.as_ptr(), buf, packet.len()) };
            packet.len() as c_int
        }
        Ok(Err(e)) => {
            set_error(&format!("recv failed: {e}"));
            -1
        }
        Err(_elapsed) => -2,
    }
}

/// Fill `out` with the current stats. Returns 0 on success.
///
/// # Safety
///
/// `tunnel` must be a live handle and `out` must be writable for one
/// [`BprotoStats`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bproto_stats(tunnel: *mut BprotoTunnel, out: *mut BprotoStats) -> c_int {
    if out.is_null() {
        set_error("out is null");
        return -1;
    }
    let t = match tunnel_ref(tunnel) {
        Ok(t) => t,
        Err(e) => {
            set_error(e);
            return -1;
        }
    };
    let s = t.tunnel.blocking_stats();
    let snapshot = BprotoStats {
        rtt_us: s.rtt_us,
        cwnd_bytes: s.cwnd_bytes,
        rx_bytes: s.rx_bytes,
        tx_bytes: s.tx_bytes,
        dropped: s.dropped,
        uptime_s: s.uptime_s,
    };
    // SAFETY: caller promised a writable BprotoStats.
    unsafe { ptr::write(out, snapshot) };
    0
}

/// Raise/lower the stealth level at runtime. Stage 2 feature; the entry point
/// exists in MVP so the mobile clients have a stable ABI to bind against.
#[unsafe(no_mangle)]
pub extern "C" fn bproto_set_stealth(_tunnel: *mut BprotoTunnel, level: c_int) -> c_int {
    match level {
        0..=2 => 0,
        _ => {
            set_error("unknown stealth level");
            -1
        }
    }
}

/// Release a tunnel handle. Safe to call with null.
///
/// # Safety
///
/// `tunnel` must be null or a pointer previously returned by [`bproto_connect`]
/// that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bproto_free(tunnel: *mut BprotoTunnel) {
    if tunnel.is_null() {
        return;
    }
    // SAFETY: the pointer came from Box::into_raw in bproto_connect.
    drop(unsafe { Box::from_raw(tunnel) });
}

/// Compute a 32-byte `session_id` label. Real, testable crypto: this is the
/// piece the mobile clients need to fill the ClientHello.
///
/// `out` must point to at least 32 writable bytes. Returns 0 on success.
///
/// # Safety
///
/// Every `*_hex` argument must be null or point to a valid NUL-terminated C
/// string, and `out` must point to at least 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bproto_compute_session_id(
    psk_hex: *const c_char,
    tag_key_hex: *const c_char,
    user_id: u64,
    client_random_hex: *const c_char,
    x25519_pub_hex: *const c_char,
    unix_secs: u64,
    out: *mut u8,
) -> c_int {
    if out.is_null() {
        set_error("out is null");
        return -1;
    }
    let psk = match cstr_to_key(psk_hex) {
        Ok(k) => k,
        Err(e) => {
            set_error(e);
            return -1;
        }
    };
    let tag_key = match cstr_to_key(tag_key_hex) {
        Ok(k) => k,
        Err(e) => {
            set_error(e);
            return -1;
        }
    };
    let client_random = match cstr_to_array32(client_random_hex) {
        Ok(a) => a,
        Err(e) => {
            set_error(e);
            return -1;
        }
    };
    let x25519_pub = match cstr_to_array32(x25519_pub_hex) {
        Ok(a) => a,
        Err(e) => {
            set_error(e);
            return -1;
        }
    };

    let tag: [u8; TAG_LEN] = compute_tag(&tag_key, user_id);
    let sid = client_label_raw(&psk, &tag, &client_random, &x25519_pub, unix_secs);
    // SAFETY: caller promised 32 writable bytes.
    unsafe { ptr::copy_nonoverlapping(sid.as_ptr(), out, sid.len()) };
    0
}

/// The 32-byte masquerade label: `tag ‖ MAC`, exactly as long as the random
/// session id a browser sends.
fn client_label_raw(
    psk: &[u8; KEY_LEN],
    tag: &[u8; TAG_LEN],
    client_random: &[u8; 32],
    x25519_pub: &[u8; 32],
    unix_secs: u64,
) -> [u8; vpn_core::auth::SESSION_ID_LEN] {
    let mut out = [0u8; vpn_core::auth::SESSION_ID_LEN];
    out[..TAG_LEN].copy_from_slice(tag);
    out[TAG_LEN..].copy_from_slice(&vpn_core::auth::label_mac(
        psk,
        tag,
        client_random,
        x25519_pub,
        vpn_core::auth::time_window(unix_secs),
    ));
    out
}

fn cstr_to_key(p: *const c_char) -> Result<[u8; KEY_LEN], &'static str> {
    cstr_to_array32(p)
}

fn cstr_to_array32(p: *const c_char) -> Result<[u8; 32], &'static str> {
    if p.is_null() {
        return Err("null string argument");
    }
    // SAFETY: caller guarantees a valid NUL-terminated string.
    let s = unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| "not UTF-8")?;
    let v = from_hex(s).map_err(|_| "invalid hex")?;
    v.try_into().map_err(|_| "expected 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_helper_writes_32_bytes() {
        let psk = CString::new("11".repeat(32)).unwrap();
        let tag = CString::new("22".repeat(32)).unwrap();
        let cr = CString::new("aa".repeat(32)).unwrap();
        let pubk = CString::new("bb".repeat(32)).unwrap();
        let mut out = [0u8; 32];
        let rc = unsafe {
            bproto_compute_session_id(
                psk.as_ptr(),
                tag.as_ptr(),
                5,
                cr.as_ptr(),
                pubk.as_ptr(),
                1_800_000_000,
                out.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);
        assert_ne!(out, [0u8; 32]);
    }

    #[test]
    fn bad_hex_is_reported() {
        let bad = CString::new("zz").unwrap();
        let tag = CString::new("22".repeat(32)).unwrap();
        let cr = CString::new("aa".repeat(32)).unwrap();
        let pubk = CString::new("bb".repeat(32)).unwrap();
        let mut out = [0u8; 32];
        let rc = unsafe {
            bproto_compute_session_id(
                bad.as_ptr(),
                tag.as_ptr(),
                5,
                cr.as_ptr(),
                pubk.as_ptr(),
                0,
                out.as_mut_ptr(),
            )
        };
        assert_eq!(rc, -1);
        let msg = unsafe { CStr::from_ptr(bproto_last_error()) };
        assert_eq!(msg.to_str().unwrap(), "invalid hex");
    }

    #[test]
    fn connect_rejects_a_bad_config() {
        let bad = CString::new("{ not json }").unwrap();
        let handle = unsafe { bproto_connect(bad.as_ptr()) };
        assert!(handle.is_null());
        let msg = unsafe { CStr::from_ptr(bproto_last_error()) };
        assert!(msg.to_str().unwrap().contains("invalid config"));
    }

    #[test]
    fn version_is_exposed() {
        let v = unsafe { CStr::from_ptr(bproto_version()) };
        assert!(!v.to_str().unwrap().is_empty());
    }

    #[test]
    fn recv_timeout_rejects_a_null_handle() {
        let mut buf = [0u8; 2048];
        let rc = unsafe { bproto_recv_timeout(ptr::null_mut(), buf.as_mut_ptr(), buf.len(), 10) };
        assert_eq!(rc, -1);
        let msg = unsafe { CStr::from_ptr(bproto_last_error()) };
        assert!(msg.to_str().unwrap().contains("null"));
    }
}
