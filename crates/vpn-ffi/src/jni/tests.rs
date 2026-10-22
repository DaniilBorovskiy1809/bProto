//! The Android datapath, exercised on Linux.
//!
//! `pump` is the one piece of the JNI tier a host test cannot reach through the
//! JNI API — there is no JVM here. What we *can* do is hand it the same two
//! things Android hands it: a live tunnel and a bidirectional datagram
//! descriptor. `socketpair(2)` is an honest stand-in for the tun descriptor, so
//! this test proves the real property — packets cross both ways between the
//! descriptor and the server — instead of a mock of it.

use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use vpn_core::tags::TagTable;
use vpn_core::{DonorSpec, HelloProfile, IpPool, MAX_DATAGRAM, TunnelConfig};
use vpn_server::server::{Node, Outcome};

use super::{current_stop, run_pump};
use crate::{BprotoTunnel, bproto_assigned_ip, bproto_connect, bproto_free};

const TAG_KEY: [u8; 32] = [0x22; 32];
const PSK: [u8; 32] = [0x11; 32];
const USER: u64 = 42;

/// The server side of the link, plus the channel of packets aimed at its TUN.
struct Harness {
    node: Arc<Node>,
    addr: SocketAddr,
    to_tun: mpsc::Receiver<Vec<u8>>,
}

fn start_server(rt: &tokio::runtime::Runtime) -> Harness {
    let mut table = TagTable::new();
    table.insert(&TAG_KEY, USER, PSK);
    let tags = Arc::new(RwLock::new(table));

    let (sock, addr) = rt
        .block_on(async {
            let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            let addr = sock.local_addr()?;
            Ok::<_, std::io::Error>((Arc::new(sock), addr))
        })
        .expect("bind loopback");
    let node = Arc::new(Node::new(
        Arc::clone(&sock),
        tags,
        IpPool::new(Ipv4Addr::new(10, 66, 0, 0), 24),
        vpn_core::packet::TUNNEL_MTU,
    ));

    let (to_tun_tx, to_tun) = mpsc::channel::<Vec<u8>>(1024);
    let reader = Arc::clone(&node);
    let reader_sock = Arc::clone(&sock);
    rt.spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM + 32];
        loop {
            let Ok((n, from)) = reader_sock.recv_from(&mut buf).await else {
                break;
            };
            if let Ok(Outcome::Packet(pkt)) = reader.route(&buf[..n], from, 0).await {
                let _ = to_tun_tx.send(pkt).await;
            }
        }
    });

    Harness { node, addr, to_tun }
}

fn client_config(server: SocketAddr) -> TunnelConfig {
    TunnelConfig {
        server,
        donor: DonorSpec::default(),
        psk: PSK,
        user_id: USER,
        tag_key: TAG_KEY,
        mtu: 1280,
        fingerprint: HelloProfile::default(),
        masquerade: false,
        handshake_timeout: Duration::from_secs(3),
    }
}

/// An IPv4/UDP packet with the given endpoints and a marker byte.
fn ip_packet(src: [u8; 4], dst: [u8; 4], marker: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 48];
    pkt[0] = 0x45;
    pkt[9] = 17; // UDP
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..24].copy_from_slice(&src);
    pkt[47] = marker;
    pkt
}

/// The tunnel handle, moved onto the pump thread. Raw pointers are not `Send`;
/// this one is only ever touched by the thread it is moved to.
struct Handle(*mut BprotoTunnel);

// SAFETY: the handle is created on the test thread, moved exactly once into the
// pump thread, and freed there after `pump` returns.
unsafe impl Send for Handle {}

impl Handle {
    /// Borrowed accessor: keeps closure capture at the whole-struct level, so
    /// the closure keeps `Handle`'s `Send` rather than the raw pointer's lack
    /// of it.
    fn get(&self) -> *mut BprotoTunnel {
        self.0
    }
}

fn socketpair() -> (OwnedFd, OwnedFd) {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: `fds` is a valid two-element array.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    assert_eq!(
        rc,
        0,
        "socketpair failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: both descriptors are fresh and ownership transfers here.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn write_packet(fd: RawFd, packet: &[u8]) {
    // SAFETY: `packet` is readable for its length and `fd` is ours.
    let n = unsafe { libc::write(fd, packet.as_ptr().cast(), packet.len()) };
    assert_eq!(n as usize, packet.len(), "short write");
}

/// Read one datagram with a deadline, so a broken datapath fails the test
/// instead of hanging the suite.
fn read_packet(fd: RawFd, timeout: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 65_536];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, left.as_millis() as libc::c_int) };
        if rc <= 0 {
            return None;
        }
        // SAFETY: `buf` is writable for its full length and `fd` is ours.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            buf.truncate(n as usize);
            return Some(buf);
        }
    }
}

/// The property the Android client depends on: a packet written to the tun
/// descriptor reaches the server, and a packet the server sends towards the
/// leased address comes back out of the descriptor.
#[test]
fn pump_moves_packets_both_ways() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let mut harness = start_server(&rt);

    let json = serde_json::to_string(&client_config(harness.addr)).expect("config serializes");
    let cjson = std::ffi::CString::new(json).expect("no NUL in the config");
    // SAFETY: valid NUL-terminated string.
    let handle = unsafe { bproto_connect(cjson.as_ptr()) };
    assert!(!handle.is_null(), "handshake failed");

    // Exactly what the Kotlin service feeds to Builder.addAddress().
    let mut octets = [0u8; 4];
    // SAFETY: `octets` is 4 writable bytes and the handle is live.
    assert_eq!(
        unsafe { bproto_assigned_ip(handle, octets.as_mut_ptr()) },
        0
    );
    let client_ip = Ipv4Addr::from(octets);
    assert_eq!(client_ip.to_string(), "10.66.0.2");

    let (tun_end, app_end) = socketpair();
    let tun_fd = tun_end.as_raw_fd();
    let app_fd = app_end.as_raw_fd();

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let wrapped = Handle(handle);
    let pump_thread = std::thread::spawn(move || {
        // Hold the descriptor open for the whole pump call.
        let _keep = tun_end;
        let rc = run_pump(wrapped.get(), tun_fd);
        // SAFETY: `pump` has returned; nothing else references the handle.
        unsafe { bproto_free(wrapped.get()) };
        let _ = done_tx.send(rc);
    });

    // Uplink: descriptor -> server TUN.
    let up = ip_packet([10, 66, 0, 2], [10, 66, 0, 1], 0xA1);
    write_packet(app_fd, &up);
    let arrived = rt
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(2), harness.to_tun.recv()).await
        })
        .expect("the server must deliver within 2s")
        .expect("channel open");
    assert_eq!(arrived, up, "the packet must arrive unmodified");

    // Downlink: server -> descriptor.
    let down = ip_packet([1, 1, 1, 1], [10, 66, 0, 2], 0xB2);
    let sent = rt
        .block_on(harness.node.send_to_client(client_ip, &down, 0))
        .expect("sealing outbound must work");
    assert!(sent, "the leased address must be routable");
    let got =
        read_packet(app_fd, Duration::from_secs(2)).expect("the descriptor must receive within 2s");
    assert_eq!(got, down, "the packet must arrive unmodified");

    // Stop: the same signal the JNI `stop()` entry point raises.
    current_stop().notify_one();
    let rc = done_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("pump must return after stop()");
    assert!(rc.is_ok(), "clean stop expected, got {rc:?}");
    pump_thread.join().expect("pump thread must not panic");
}
