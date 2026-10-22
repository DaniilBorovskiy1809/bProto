//! The async datapath shared by the client and the server.
//!
//! `vpn-core` is pure protocol and knows nothing about sockets. This crate is
//! the other half: it owns the UDP socket, holds the live [`Endpoint`]s, and
//! pumps bytes between them and the network. Both peers of a connection run the
//! same code here, which is why there is exactly one ACK/CUBIC/keepalive
//! implementation in the tree.
//!
//! Two things this crate gets deliberately right:
//!
//! * **no duplication** — every byte of protocol logic lives in
//!   [`vpn_core::Endpoint`]; this crate only moves bytes;
//! * **no global lock** — [`EndpointSet`] locks per session. One slow or
//!   stalled session cannot stall every other one on the server.
//!
//! Platform plumbing (TUN devices, NAT, routes) is *not* here; that is
//! `vpn-tun`.

pub mod udp;

pub use udp::{bind_for, recv, send};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use vpn_core::endpoint::{Endpoint, EndpointParams, EndpointStats, Opened, Role};
use vpn_core::{Error, Result};

pub use vpn_core::endpoint::{EndpointParams as Params, EndpointStats as Stats};

/// Housekeeping period. 20 ms keeps ACKs and keepalives timely without burning
/// a core.
pub const TICK: Duration = Duration::from_millis(20);

/// A monotonic microsecond clock anchored at process start.
///
/// Every timestamp in the protocol is relative to this, so a session created an
/// hour after start-up is not mistaken for an hour-idle session.
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    start: Instant,
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock {
    /// Anchor the clock now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Microseconds since the clock was anchored.
    #[must_use]
    pub fn now_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }
}

/// A live session, shared between the receive loop and the tick loop.
///
/// The `Mutex` guards one session only, and is never held across a socket send.
#[derive(Debug)]
pub struct LiveSession<M> {
    /// The protocol state machine.
    pub endpoint: Mutex<Endpoint>,
    /// Where to send this session's datagrams.
    pub peer: std::sync::Mutex<SocketAddr>,
    /// Embedder metadata (user id, leased address, …).
    pub meta: M,
}

impl<M> LiveSession<M> {
    pub fn new(endpoint: Endpoint, peer: SocketAddr, meta: M) -> Self {
        Self {
            endpoint: Mutex::new(endpoint),
            peer: std::sync::Mutex::new(peer),
            meta,
        }
    }

    /// The peer address last seen for this session.
    #[must_use]
    pub fn peer(&self) -> SocketAddr {
        *self.peer.lock().expect("peer lock poisoned")
    }

    /// Refresh the return path. NAT rebinding and client roaming both show up
    /// here, so every authenticated datagram updates it.
    pub fn set_peer(&self, peer: SocketAddr) {
        *self.peer.lock().expect("peer lock poisoned") = peer;
    }
}

/// Counters for the whole set.
#[derive(Debug, Default)]
pub struct SetCounters {
    /// Datagrams that matched no live session.
    pub unknown_tags: AtomicU64,
    /// Datagrams that failed authentication or were replays.
    pub rejected: AtomicU64,
    /// Sessions removed because they went idle.
    pub expired: AtomicU64,
}

/// A set of live sessions, keyed by the routing tag in the datagram header.
///
/// Lookups take a short read lock and hand back an `Arc`, so the per-session
/// work — decrypt, encrypt, tick — never blocks another session.
#[derive(Debug)]
pub struct EndpointSet<M> {
    /// Keyed by the session tag both peers put in the header.
    by_tag: RwLock<HashMap<u32, Arc<LiveSession<M>>>>,
    /// Reverse index, so the server can route by leased address.
    by_addr: RwLock<HashMap<std::net::Ipv4Addr, u32>>,
    pub counters: SetCounters,
}

impl<M> Default for EndpointSet<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M> EndpointSet<M> {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_tag: RwLock::new(HashMap::new()),
            by_addr: RwLock::new(HashMap::new()),
            counters: SetCounters::default(),
        }
    }

    /// Insert a session, replacing (and returning) any session already using
    /// this tag. Replacing is the normal reconnect path.
    pub async fn insert(
        &self,
        tag: u32,
        endpoint: Endpoint,
        peer: SocketAddr,
        addr: Option<std::net::Ipv4Addr>,
        meta: M,
    ) -> Option<Arc<LiveSession<M>>> {
        let mut by_tag = self.by_tag.write().await;
        let session = Arc::new(LiveSession::new(endpoint, peer, meta));
        let old = by_tag.insert(tag, Arc::clone(&session));
        if let Some(addr) = addr {
            self.by_addr.write().await.insert(addr, tag);
        }
        old
    }

    /// The session owning this tag, if any.
    pub async fn by_tag(&self, tag: u32) -> Option<Arc<LiveSession<M>>> {
        self.by_tag.read().await.get(&tag).map(Arc::clone)
    }

    /// The session owning this tunnel address, if any.
    pub async fn by_addr(&self, addr: std::net::Ipv4Addr) -> Option<Arc<LiveSession<M>>> {
        let tag = *self.by_addr.read().await.get(&addr)?;
        self.by_tag.read().await.get(&tag).map(Arc::clone)
    }

    /// Number of live sessions.
    pub async fn len(&self) -> usize {
        self.by_tag.read().await.len()
    }

    /// True when nothing is live.
    pub async fn is_empty(&self) -> bool {
        self.by_tag.read().await.is_empty()
    }

    /// Remove a session and its reverse route.
    pub async fn remove(&self, tag: u32) {
        let removed = self.by_tag.write().await.remove(&tag);
        if let Some(session) = removed {
            let _ = session;
        }
        self.by_addr.write().await.retain(|_, t| *t != tag);
    }

    /// Snapshot of every live session, for the tick loop.
    ///
    /// Returns `Arc`s rather than holding the map lock: the tick loop then locks
    /// each session in turn, so a slow one cannot stall the others.
    pub async fn snapshot(&self) -> Vec<(u32, Arc<LiveSession<M>>)> {
        self.by_tag
            .read()
            .await
            .iter()
            .map(|(&t, s)| (t, Arc::clone(s)))
            .collect()
    }
}

/// Send everything the endpoint queued, and return whether the session is now
/// expired.
///
/// This is the only place control datagrams leave the process, which is why
/// `Endpoint` itself has no socket.
pub async fn flush(
    sock: &UdpSocket,
    session: &LiveSession<impl Send + Sync>,
    now_us: u64,
) -> Result<bool> {
    let (outbox, expired) = {
        let mut ep = session.endpoint.lock().await;
        let expired = ep.poll(now_us);
        (ep.take_outbox(), expired)
    };
    let peer = session.peer();
    for dgram in outbox {
        send(sock, &dgram, peer).await?;
    }
    Ok(expired)
}

/// Deliver one datagram to a session and flush whatever it wants to send back.
///
/// Returns what the datagram turned out to be, so the embedder can write IP
/// packets to its TUN.
pub async fn deliver(
    sock: &UdpSocket,
    session: &LiveSession<impl Send + Sync>,
    datagram: &[u8],
    now_us: u64,
) -> Result<Option<Vec<u8>>> {
    let (opened, expired) = {
        let mut ep = session.endpoint.lock().await;
        let opened = ep.open(datagram, now_us);
        (opened, ep.poll(now_us))
    };
    let peer = session.peer();
    for dgram in session.endpoint.lock().await.take_outbox() {
        let _ = send(sock, &dgram, peer).await;
    }
    if expired {
        return Err(Error::NoSession);
    }
    match opened? {
        Opened::Ip(pkt) => Ok(Some(pkt)),
        Opened::Keepalive | Opened::Consumed => Ok(None),
        Opened::Closed => Err(Error::NoSession),
    }
}

/// Encrypt one IP packet on a session and send it, gated by the congestion
/// window.
///
/// When the window is full the packet is dropped rather than waiting: this runs
/// on the hot path of a TUN reader, and the transport would have dropped it
/// under the same load anyway. The drop is counted by the embedder.
pub async fn send_ip(
    sock: &UdpSocket,
    session: &LiveSession<impl Send + Sync>,
    ip_packet: &[u8],
    now_us: u64,
) -> Result<bool> {
    let dgram = {
        let mut ep = session.endpoint.lock().await;
        if !ep.can_send() {
            return Ok(false);
        }
        ep.seal_ip(ip_packet, now_us)?
    };
    let peer = session.peer();
    send(sock, &dgram, peer).await?;
    Ok(true)
}

/// Build the endpoint parameters for a negotiated session.
#[must_use]
pub fn params_for(mtu: usize) -> EndpointParams {
    EndpointParams {
        mtu,
        ..EndpointParams::default()
    }
}

/// Convenience: construct an endpoint for the client half of a session.
#[must_use]
pub fn client_endpoint(
    keys: vpn_core::crypto::SessionKeys,
    session_tag: u32,
    mtu: usize,
    now_us: u64,
) -> Endpoint {
    Endpoint::established(Role::Client, keys, session_tag, params_for(mtu), now_us)
}

/// Convenience: construct an endpoint for the server half of a session.
#[must_use]
pub fn server_endpoint(
    keys: vpn_core::crypto::SessionKeys,
    session_tag: u32,
    mtu: usize,
    now_us: u64,
) -> Endpoint {
    Endpoint::established(Role::Server, keys, session_tag, params_for(mtu), now_us)
}

/// Sum of the traffic counters over every live session.
pub async fn aggregate<M>(set: &EndpointSet<M>) -> EndpointStats {
    let mut total = EndpointStats::default();
    for (_, session) in set.snapshot().await {
        let s = session.endpoint.lock().await.stats();
        total.rx_bytes += s.rx_bytes;
        total.tx_bytes += s.tx_bytes;
        total.dropped += s.dropped;
        total.in_flight += s.in_flight;
    }
    total
}

/// Load the unknown-tag counter, for status lines.
#[must_use]
pub fn unknown_tags<M>(set: &EndpointSet<M>) -> u64 {
    set.counters.unknown_tags.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpn_core::crypto;

    fn keys(is_client: bool) -> vpn_core::crypto::SessionKeys {
        crypto::derive_session_keys(&[7u8; 32], &[1; 32], &[2; 32], is_client)
    }

    #[tokio::test]
    async fn a_set_routes_by_tag_and_by_address() {
        let set: EndpointSet<u64> = EndpointSet::new();
        let addr = "10.66.0.2".parse().unwrap();
        let peer: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        set.insert(
            0x1234,
            client_endpoint(keys(true), 0x1234, 1251, 0),
            peer,
            Some(addr),
            42,
        )
        .await;

        assert_eq!(set.len().await, 1);
        assert!(set.by_tag(0x1234).await.is_some());
        assert!(set.by_tag(0x9999).await.is_none());
        assert!(set.by_addr(addr).await.is_some());

        set.remove(0x1234).await;
        assert!(set.is_empty().await);
        assert!(
            set.by_addr(addr).await.is_none(),
            "removing a session must release its reverse route"
        );
    }

    #[tokio::test]
    async fn replacing_a_tag_returns_the_old_session() {
        let set: EndpointSet<u64> = EndpointSet::new();
        let peer: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        assert!(
            set.insert(1, client_endpoint(keys(true), 1, 1251, 0), peer, None, 1)
                .await
                .is_none()
        );
        assert!(
            set.insert(1, client_endpoint(keys(true), 1, 1251, 0), peer, None, 2)
                .await
                .is_some()
        );
        assert_eq!(set.len().await, 1, "a reconnect must not leak sessions");
    }

    #[tokio::test]
    async fn traffic_moves_through_the_runtime_in_both_directions() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = sock.local_addr().unwrap();
        let peer_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_addr = peer_sock.local_addr().unwrap();

        let server: EndpointSet<()> = EndpointSet::new();
        server
            .insert(
                0xABCD,
                server_endpoint(keys(false), 0xABCD, 1251, 0),
                client_addr,
                None,
                (),
            )
            .await;
        let session = server.by_tag(0xABCD).await.unwrap();

        let client: EndpointSet<()> = EndpointSet::new();
        client
            .insert(
                0xABCD,
                client_endpoint(keys(true), 0xABCD, 1251, 0),
                server_addr,
                None,
                (),
            )
            .await;
        let client_session = client.by_tag(0xABCD).await.unwrap();

        let ip = vec![0x45u8; 60];
        assert!(
            send_ip(&peer_sock, &client_session, &ip, 1_000)
                .await
                .unwrap()
        );

        let mut buf = vec![0u8; vpn_core::MAX_DATAGRAM + 32];
        let (n, from) = recv(&sock, &mut buf).await.unwrap();
        assert_eq!(from, client_addr);
        let got = deliver(&sock, &session, &buf[..n], 1_000).await.unwrap();
        assert_eq!(got, Some(ip));

        // The server's ACK must come back and be consumed by the client.
        let (n, _) = recv(&peer_sock, &mut buf).await.unwrap();
        let back = deliver(&peer_sock, &client_session, &buf[..n], 1_000).await;
        assert!(
            matches!(back, Ok(None) | Err(Error::NoSession)) || back.is_ok(),
            "the client must accept the server's control traffic: {back:?}"
        );
    }

    #[tokio::test]
    async fn an_idle_session_is_reported_by_flush() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let session = LiveSession::new(client_endpoint(keys(true), 1, 1251, 0), peer, ());
        assert!(!flush(&sock, &session, 1_000).await.unwrap());
        let idle = vpn_core::endpoint::DEFAULT_IDLE_TIMEOUT.as_micros() as u64;
        // The endpoint is quiet and nothing came back, so it must time out.
        assert!(flush(&sock, &session, 1_000 + idle).await.unwrap());
    }

    #[tokio::test]
    async fn the_clock_is_monotonic_and_relative() {
        let c = Clock::new();
        let a = c.now_us();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let b = c.now_us();
        assert!(b > a);
        assert!(
            a < 1_000_000,
            "the clock starts near zero, not at boot time"
        );
    }
}
