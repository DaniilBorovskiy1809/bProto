//! JNI entry points for the Android client (`--features jni`).
//!
//! Kotlin sees a singleton, `dev.bproto.Bproto`, declared as a Kotlin `object`
//! with `external` members. An `object`'s members compile to *instance* methods
//! (the receiver is the singleton), so the symbols are
//! `Java_dev_bproto_Bproto_<name>` with a `jobject` in the second slot. Do not
//! add `@JvmStatic` on the Kotlin side: that emits a second, static method with
//! the same descriptor and the runtime resolves the wrong one.
//!
//! The Android runtime owns the VPN file descriptor (from `VpnService`), while
//! this crate owns the UDP socket that talks to the server. The app must call
//! [`Java_dev_bproto_Bproto_socketFd`] and pass the result to
//! `VpnService.protect()` before handing us the tunnel descriptor, otherwise the
//! encapsulated traffic is routed back into the tunnel.
//!
//! Threading: `connect` blocks while the handshake runs and `pump` blocks for the
//! whole life of the tunnel. Both must be called from a worker thread that the
//! app owns; `stop` is the only function safe to call from anywhere.

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;

use jni::JNIEnv;
use jni::objects::{JObject, JString};
use jni::sys::{jint, jlong, jstring};
use tokio::sync::{Notify, mpsc};

use crate::BprotoTunnel;

#[cfg(test)]
mod tests;

/// Wake-up channel pair width: enough to smooth a scheduling hiccup without
/// letting a stalled peer grow the queue without bound.
const CHANNEL_DEPTH: usize = 128;
/// How long a tun-side thread waits for the descriptor before rechecking stop.
const POLL_MS: i32 = 200;
/// Largest IP packet we will read from the tun descriptor.
const TUN_BUF: usize = 65_535;

/// The `Notify` currently armed for the running tunnel. Replaced on every `run`
/// so a stale signal from a previous session cannot stop a fresh one.
fn stop_slot() -> &'static Mutex<Arc<Notify>> {
    static SLOT: OnceLock<Mutex<Arc<Notify>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(Arc::new(Notify::new())))
}

/// Arm a fresh signal and return it. Also clears anything left over.
fn rearm_stop() -> Arc<Notify> {
    let mut slot = stop_slot().lock().expect("stop slot poisoned");
    *slot = Arc::new(Notify::new());
    Arc::clone(&slot)
}

fn current_stop() -> Arc<Notify> {
    Arc::clone(&stop_slot().lock().expect("stop slot poisoned"))
}

/// Only one tunnel can be pumped per process; the Kotlin service enforces this
/// too, but the native side must not be corrupted by a double call.
static PUMPING: AtomicBool = AtomicBool::new(false);

struct PumpGuard;

impl Drop for PumpGuard {
    fn drop(&mut self) {
        PUMPING.store(false, Ordering::SeqCst);
    }
}

fn new_string(env: &mut JNIEnv<'_>, value: &str) -> jstring {
    match env.new_string(value) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn read_string(env: &mut JNIEnv<'_>, value: &JString<'_>) -> Result<String, String> {
    env.get_string(value)
        .map(Into::into)
        .map_err(|e| format!("config string is not readable: {e}"))
}

/// Library version. Mirrors `bproto_version`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_version<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
) -> jstring {
    new_string(&mut env, env!("CARGO_PKG_VERSION"))
}

/// Message from the most recent failing call on this thread (empty if none).
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_lastError<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
) -> jstring {
    let msg = crate::last_error_string();
    new_string(&mut env, &msg)
}

/// Connect: run the handshake and return an opaque handle, or 0 on failure.
///
/// `config` is either the JSON `TunnelConfig` or a `bproto://import/...` key.
/// Blocks the calling thread until the handshake completes or times out.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_connect<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    config: JString<'local>,
) -> jlong {
    let text = match read_string(&mut env, &config) {
        Ok(s) => s,
        Err(e) => {
            crate::set_error(&e);
            return 0;
        }
    };
    let Ok(cstr) = std::ffi::CString::new(text) else {
        crate::set_error("config contains a NUL byte");
        return 0;
    };
    // SAFETY: `cstr` is a valid NUL-terminated string alive for the call.
    let handle = unsafe { crate::bproto_connect(cstr.as_ptr()) };
    handle as jlong
}

/// Address the server leased to this tunnel, e.g. `"10.66.0.2"`. Empty on error.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_assignedIp<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    handle: jlong,
) -> jstring {
    let mut octets = [0u8; 4];
    // SAFETY: the caller passes a handle from `open`; `octets` is 4 bytes.
    let rc = unsafe { crate::bproto_assigned_ip(handle as *mut BprotoTunnel, octets.as_mut_ptr()) };
    if rc != 0 {
        return new_string(&mut env, "");
    }
    let ip = std::net::Ipv4Addr::from(octets);
    new_string(&mut env, &ip.to_string())
}

/// UDP socket descriptor of the server link — pass it to `VpnService.protect`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_socketFd<'local>(
    _env: JNIEnv<'local>,
    _this: JObject<'local>,
    handle: jlong,
) -> jint {
    // SAFETY: the caller passes a handle from `open`.
    unsafe { crate::bproto_socket_fd(handle as *mut BprotoTunnel) }
}

/// Pump packets between the tunnel and an Android tun descriptor until `stop`.
///
/// Returns null on a clean stop, or an error message the UI should show.
/// Blocks the calling thread for the whole tunnel lifetime.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_pump<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    handle: jlong,
    fd: jint,
) -> jstring {
    match run_pump(handle as *mut BprotoTunnel, fd as RawFd) {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => new_string(&mut env, &e),
    }
}

/// Ask a running `run` call to return. Safe to call from any thread.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_stop(_env: JNIEnv<'_>, _this: JObject<'_>) {
    current_stop().notify_one();
}

/// Release a handle from `open`. Does not stop a running `run` call.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_close(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    // SAFETY: the pointer came from `open` and is freed exactly once.
    unsafe { crate::bproto_free(handle as *mut BprotoTunnel) };
}

fn run_pump(handle: *mut BprotoTunnel, fd: RawFd) -> Result<(), String> {
    if handle.is_null() {
        return Err("tunnel handle is null".to_owned());
    }
    if fd < 0 {
        return Err("tun descriptor is invalid".to_owned());
    }
    if PUMPING.swap(true, Ordering::SeqCst) {
        return Err("a tunnel is already running".to_owned());
    }
    let _guard = PumpGuard;

    // SAFETY: the handle is live for the whole call; the Kotlin service keeps
    // the handle and the descriptor alive until `run` returns.
    let owner = unsafe { &*handle };
    let notify = rearm_stop();

    set_nonblocking(fd).map_err(|e| format!("tun descriptor: {e}"))?;

    // tun -> tunnel (reader thread) and tunnel -> tun (writer thread), with the
    // async pump in the middle. Using channels here keeps every read/write off
    // the runtime threads: the tun descriptor is a blocking object we do not own.
    let (fd_tx, mut fd_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);
    let (to_fd_tx, mut to_fd_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);

    let reader = spawn_thread("bproto-tun-read", move || tun_reader(fd, fd_tx))?;
    let writer = spawn_thread("bproto-tun-write", move || tun_writer(fd, &mut to_fd_rx))?;

    let outcome = owner.rt.block_on(async move {
        loop {
            tokio::select! {
                // `biased` keeps shutdown and inbound traffic ahead of the
                // reader channel, so a busy tunnel still stops promptly.
                biased;
                () = notify.notified() => return Ok(()),
                inbound = owner.tunnel.recv_ip_packet() => match inbound {
                    Ok(packet) => {
                        if to_fd_tx.send(packet).await.is_err() {
                            return Ok(());
                        }
                    }
                    Err(e) => return Err(format!("tunnel receive: {e}")),
                },
                outbound = fd_rx.recv() => match outbound {
                    Some(packet) => {
                        if let Err(e) = owner.tunnel.send_ip_packet(&packet).await {
                            return Err(format!("tunnel send: {e}"));
                        }
                    }
                    None => return Ok(()),
                },
            }
        }
    });

    // The `async move` block owns both channel halves, so they are dropped the
    // moment it returns: the reader sees its send fail, the writer sees the
    // channel close. That is what ends the tun threads.
    current_stop().notify_one();
    join_thread(reader);
    join_thread(writer);

    // Best-effort Close frame; ignore failures on an already dead session.
    owner.rt.block_on(owner.tunnel.close());
    outcome
}

fn spawn_thread(
    name: &str,
    body: impl FnOnce() + Send + 'static,
) -> Result<JoinHandle<()>, String> {
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(body)
        .map_err(|e| format!("cannot start {name}: {e}"))
}

fn join_thread(handle: JoinHandle<()>) {
    if handle.join().is_err() {
        tracing::warn!("a tun worker thread panicked");
    }
}

fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: plain fcntl on a descriptor the caller owns.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Wait up to [`POLL_MS`] for `events`. `Ok(true)` means ready.
fn wait_fd(fd: RawFd, events: libc::c_short) -> std::io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    // SAFETY: one valid pollfd, one element.
    let rc = unsafe { libc::poll(&mut pfd, 1, POLL_MS) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(err);
    }
    Ok(rc > 0)
}

fn tun_reader(fd: RawFd, tx: mpsc::Sender<Vec<u8>>) {
    let mut buf = vec![0u8; TUN_BUF];
    loop {
        // The pump drops the receiving half when it returns. Nothing else
        // reports that to a thread parked in `poll`, so ask the channel
        // directly — otherwise this thread outlives the tunnel forever.
        if tx.is_closed() {
            return;
        }
        match wait_fd(fd, libc::POLLIN) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                tracing::warn!(error = %e, "tun read poll failed");
                return;
            }
        }
        // SAFETY: `buf` is writable for its full length.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n == 0 {
            return; // descriptor closed by the app
        }
        if n < 0 {
            let err = std::io::Error::last_os_error();
            match err.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => continue,
                _ => {
                    tracing::warn!(error = %err, "tun read failed");
                    return;
                }
            }
        }
        let packet = buf[..n as usize].to_vec();
        if tx.blocking_send(packet).is_err() {
            return; // tunnel shut down
        }
    }
}

fn tun_writer(fd: RawFd, rx: &mut mpsc::Receiver<Vec<u8>>) {
    while let Some(packet) = rx.blocking_recv() {
        write_all(fd, &packet);
    }
}

/// Write a packet, retrying a bounded number of times on a busy descriptor.
fn write_all(fd: RawFd, packet: &[u8]) {
    let mut offset = 0;
    let mut busy = 0;
    while offset < packet.len() {
        match wait_fd(fd, libc::POLLOUT) {
            Ok(true) => {}
            Ok(false) => {
                busy += 1;
                if busy > 5 {
                    return; // drop: the tun side is not draining
                }
                continue;
            }
            Err(_) => return,
        }
        // SAFETY: `packet[offset..]` is readable for its full length.
        let n = unsafe { libc::write(fd, packet[offset..].as_ptr().cast(), packet.len() - offset) };
        if n > 0 {
            offset += n as usize;
            busy = 0;
            continue;
        }
        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => busy += 1,
            _ => return,
        }
        if busy > 5 {
            return;
        }
    }
}
