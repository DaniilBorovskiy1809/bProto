//! The server node: session table, handshake acceptor, address pool.
//!
//! Everything the server does to a datagram lives here, so the binary is only
//! I/O and lifecycle and all of it is testable without a TUN device or root.
//!
//! Concurrency: sessions are held in [`EndpointSet`], which locks **per
//! session**. Looking a session up takes a brief read lock and hands back an
//! `Arc`, so two clients never serialise on each other — including when one of
//! them is stalled.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use vpn_core::auth::TAG_LEN;
use vpn_core::config::to_hex;
use vpn_core::crypto::KeyPair;
use vpn_core::handshake;
use vpn_core::{Error, IpPool, TagTable, packet, unix_now_secs};
use vpn_rt::{EndpointSet, udp};

use crate::control::SessionDelta;

/// Default housekeeping period.
pub const TICK: Duration = vpn_rt::TICK;
/// Default keepalive probe interval for a session.
pub const KEEPALIVE: Duration = vpn_core::endpoint::DEFAULT_KEEPALIVE;
/// Default idle timeout before a session is reaped.
pub const IDLE_TIMEOUT: Duration = vpn_core::endpoint::DEFAULT_IDLE_TIMEOUT;

/// Per-session bookkeeping kept alongside the protocol state.
#[derive(Debug)]
pub struct SessionMeta {
    /// Panel user id this session belongs to.
    pub user_id: u64,
    /// The routing tag the client presented.
    pub tag: [u8; TAG_LEN],
    /// The tunnel address leased to this session.
    pub ip: Ipv4Addr,
    /// Unix seconds when the session was established.
    pub started_unix: i64,
    /// Bytes already pushed to the panel, so every report is a delta.
    reported_rx: AtomicU64,
    reported_tx: AtomicU64,
}

impl SessionMeta {
    fn new(user_id: u64, tag: [u8; TAG_LEN], ip: Ipv4Addr) -> Self {
        Self {
            user_id,
            tag,
            ip,
            started_unix: unix_now_secs() as i64,
            reported_rx: AtomicU64::new(0),
            reported_tx: AtomicU64::new(0),
        }
    }

    /// Take the byte counts the panel has not seen yet.
    fn take_delta(&self, rx: u64, tx: u64) -> (i64, i64) {
        let drx = rx.saturating_sub(self.reported_rx.swap(rx, Ordering::Relaxed));
        let dtx = tx.saturating_sub(self.reported_tx.swap(tx, Ordering::Relaxed));
        (drx as i64, dtx as i64)
    }
}

/// Counters exposed to the operator and the panel.
#[derive(Debug, Default)]
pub struct Counters {
    /// Successful handshakes.
    pub handshakes: AtomicU64,
    /// Handshakes that failed verification: probing, replays, wrong keys.
    pub rejected_handshakes: AtomicU64,
}

/// Snapshot of the whole node.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeStats {
    /// Live sessions.
    pub sessions: usize,
    /// Successful handshakes.
    pub handshakes: u64,
    /// Handshakes rejected as probes or wrong-key attempts.
    pub rejected_handshakes: u64,
    /// Datagrams whose tag matched no live session.
    pub unknown_tags: u64,
}

/// What one inbound datagram turned out to be.
#[derive(Debug)]
pub enum Outcome {
    /// A handshake was answered and a session opened.
    Handshaked { user_id: u64, ip: Ipv4Addr },
    /// An IP packet to write to the TUN.
    Packet(Vec<u8>),
    /// Consumed by the protocol itself (ACK, keepalive, …).
    Nothing,
}

/// A session that just ended, handed back so the caller can release resources
/// and report final byte counts.
#[derive(Debug)]
pub struct ClosedSession {
    /// The session tag it had.
    pub tag: u32,
    /// User id.
    pub user_id: u64,
    /// Leased address to return to the pool.
    pub ip: Ipv4Addr,
    /// Routing tag to unbind from the tag table.
    pub routing_tag: [u8; TAG_LEN],
    /// Unix seconds when it started.
    pub started_unix: i64,
    /// Bytes received that the panel has not seen.
    pub bytes_rx: i64,
    /// Bytes sent that the panel has not seen.
    pub bytes_tx: i64,
    /// Last peer address.
    pub peer_ip: String,
}

/// The server node.
#[derive(Debug)]
pub struct Node {
    tags: Arc<RwLock<TagTable>>,
    sessions: EndpointSet<SessionMeta>,
    /// Wire tag of each user's current session, keyed by the routing tag the
    /// client authenticated with. The wire tag is derived from the handshake's
    /// ephemeral secret and therefore changes on every reconnect, so identity
    /// is the only stable key to enforce "one session per user" with.
    by_identity: RwLock<HashMap<[u8; TAG_LEN], u32>>,
    pool: Mutex<IpPool>,
    mtu: usize,
    /// Final reports for sessions evicted by a reconnect, drained by
    /// [`Self::take_deltas`].
    pending: StdMutex<Vec<SessionDelta>>,
    pub counters: Counters,
}

impl Node {
    /// Build a node over a tag table and an address pool.
    #[must_use]
    pub fn new(tags: Arc<RwLock<TagTable>>, pool: IpPool, mtu: usize) -> Self {
        Self {
            tags,
            sessions: EndpointSet::new(),
            by_identity: RwLock::new(HashMap::new()),
            pool: Mutex::new(pool),
            mtu,
            pending: StdMutex::new(Vec::new()),
            counters: Counters::default(),
        }
    }

    /// The live sessions, for the outbound path.
    #[must_use]
    pub fn sessions(&self) -> &EndpointSet<SessionMeta> {
        &self.sessions
    }

    /// Snapshot of the node.
    pub async fn stats(&self) -> NodeStats {
        NodeStats {
            sessions: self.sessions.len().await,
            handshakes: self.counters.handshakes.load(Ordering::Relaxed),
            rejected_handshakes: self.counters.rejected_handshakes.load(Ordering::Relaxed),
            unknown_tags: vpn_rt::unknown_tags(&self.sessions),
        }
    }

    /// Route one inbound datagram.
    ///
    /// A datagram that fails to decrypt is silently dropped: there is nothing to
    /// say to a forgery, and answering would tell a prober it found something.
    pub async fn route(
        &self,
        sock: &UdpSocket,
        datagram: &[u8],
        from: SocketAddr,
        now_us: u64,
    ) -> Result<Outcome, Error> {
        let header = packet::Header::decode(datagram)?;
        if header.is_control() {
            return self.accept(sock, datagram, from, now_us).await;
        }

        let Some(session) = self.sessions.by_tag(header.session_tag).await else {
            self.sessions
                .counters
                .unknown_tags
                .fetch_add(1, Ordering::Relaxed);
            return Err(Error::NoSession);
        };

        // Refresh the return path on every datagram: NAT rebinding and client
        // roaming both show up here. A forgery costs nothing here because it
        // fails authentication inside `deliver`.
        session.set_peer(from);

        match vpn_rt::deliver(sock, &session, datagram, now_us).await {
            Ok(Some(pkt)) => Ok(Outcome::Packet(pkt)),
            Ok(None) => Ok(Outcome::Nothing),
            Err(Error::NoSession) => {
                self.sessions.remove(header.session_tag).await;
                Err(Error::NoSession)
            }
            Err(e) => Err(e),
        }
    }

    /// Answer a `HELLO` and open the session.
    async fn accept(
        &self,
        sock: &UdpSocket,
        datagram: &[u8],
        from: SocketAddr,
        now_us: u64,
    ) -> Result<Outcome, Error> {
        let verified = {
            let table = self
                .tags
                .read()
                .map_err(|_| Error::Config("tag table poisoned".into()))?;
            handshake::verify(&table, datagram, unix_now_secs())
        };

        let Ok(verified) = verified else {
            // Not ours: an active prober, a replayed HELLO, or a wrong key.
            self.counters
                .rejected_handshakes
                .fetch_add(1, Ordering::Relaxed);
            return Err(Error::BadLabel);
        };

        // One session per user. Evict *before* leasing an address: a reconnect
        // that took a new address first would strand the old one in the pool
        // until the old session's idle timer fired.
        if let Some(closed) = self.evict(&verified.tag).await {
            let finals = Self::final_deltas(&[closed], unix_now_secs() as i64);
            if let Ok(mut pending) = self.pending.lock() {
                pending.extend(finals);
            }
        }

        let ip = {
            let mut pool = self.pool.lock().await;
            pool.allocate().ok_or(Error::NoSession)? // pool exhausted
        };

        let server_eph = KeyPair::generate();
        let (reply, keys, session_tag) = handshake::respond(&verified, &server_eph, ip)?;

        self.sessions
            .insert(
                session_tag,
                vpn_rt::server_endpoint(keys, session_tag, self.mtu, now_us),
                from,
                Some(ip),
                SessionMeta::new(verified.user_id, verified.tag, ip),
            )
            .await;
        if let Ok(mut by_identity) = self.by_identity.write() {
            by_identity.insert(verified.tag, session_tag);
        }

        if let Ok(mut t) = self.tags.write() {
            t.bind_ip(&verified.tag, ip);
        }

        udp::send(sock, &reply, from).await?;
        self.counters.handshakes.fetch_add(1, Ordering::Relaxed);
        tracing::info!(user = verified.user_id, %ip, %from, "session established");
        Ok(Outcome::Handshaked {
            user_id: verified.user_id,
            ip,
        })
    }

    /// End the session currently owned by `identity`, if any, and free its
    /// address. Returns the closed session so its final byte counts can be
    /// reported rather than lost.
    async fn evict(&self, identity: &[u8; TAG_LEN]) -> Option<ClosedSession> {
        let old_tag = self.by_identity.write().ok()?.remove(identity)?;
        let session = self.sessions.by_tag(old_tag).await?;
        self.sessions.remove(old_tag).await;

        let stats = session.endpoint.lock().await.stats();
        let (rx, tx) = session.meta.take_delta(stats.rx_bytes, stats.tx_bytes);

        self.pool.lock().await.release(session.meta.ip);
        if let Ok(mut t) = self.tags.write() {
            t.release_ip(&session.meta.tag);
        }
        tracing::info!(user = session.meta.user_id, ip = %session.meta.ip, "replaced a session");

        Some(ClosedSession {
            tag: old_tag,
            user_id: session.meta.user_id,
            ip: session.meta.ip,
            routing_tag: session.meta.tag,
            started_unix: session.meta.started_unix,
            bytes_rx: rx,
            bytes_tx: tx,
            peer_ip: crate::control::peer_ip_string(session.peer().ip()),
        })
    }

    /// Seal and send one outbound IP packet to the session that owns `dst`.
    ///
    /// Returns `false` when no session owns the address, or when the congestion
    /// window is full and the packet was dropped.
    pub async fn send_to_client(
        &self,
        sock: &UdpSocket,
        dst: Ipv4Addr,
        packet: &[u8],
        now_us: u64,
    ) -> Result<bool, Error> {
        let Some(session) = self.sessions.by_addr(dst).await else {
            return Ok(false);
        };
        vpn_rt::send_ip(sock, &session, packet, now_us).await
    }

    /// Flush every session's ACKs and keepalives, returning the ones that went
    /// idle so the caller can release their addresses and report them.
    pub async fn reap(&self, sock: &UdpSocket, now_us: u64) -> Vec<ClosedSession> {
        let mut closed = Vec::new();
        for (tag, session) in self.sessions.snapshot().await {
            let (expired, outbox) = {
                let mut ep = session.endpoint.lock().await;
                let expired = ep.poll(now_us);
                (expired, ep.take_outbox())
            };
            let peer = session.peer();
            for dgram in outbox {
                let _ = udp::send(sock, &dgram, peer).await;
            }
            if !expired {
                continue;
            }
            let stats = session.endpoint.lock().await.stats();
            let (rx, tx) = session.meta.take_delta(stats.rx_bytes, stats.tx_bytes);
            closed.push(ClosedSession {
                tag,
                user_id: session.meta.user_id,
                ip: session.meta.ip,
                routing_tag: session.meta.tag,
                started_unix: session.meta.started_unix,
                bytes_rx: rx,
                bytes_tx: tx,
                peer_ip: crate::control::peer_ip_string(peer.ip()),
            });
        }

        let mut pool = self.pool.lock().await;
        for c in &closed {
            pool.release(c.ip);
            if let Ok(mut t) = self.tags.write() {
                t.release_ip(&c.routing_tag);
            }
            self.sessions.remove(c.tag).await;
            // Only forget the identity if it still points here: a reconnect
            // may already have replaced this session with a newer one.
            if let Ok(mut by_identity) = self.by_identity.write()
                && by_identity.get(&c.routing_tag) == Some(&c.tag)
            {
                by_identity.remove(&c.routing_tag);
            }
            tracing::info!(user = c.user_id, ip = %c.ip, "session expired");
        }
        closed
    }

    /// Traffic deltas since the last call, for the panel.
    pub async fn take_deltas(&self, now_unix: i64) -> Vec<SessionDelta> {
        let mut out = Vec::new();
        for (_, session) in self.sessions.snapshot().await {
            let stats = session.endpoint.lock().await.stats();
            let (rx, tx) = session.meta.take_delta(stats.rx_bytes, stats.tx_bytes);
            out.push(SessionDelta {
                tag: to_hex(&session.meta.tag),
                started_at: session.meta.started_unix,
                ended_at: None,
                bytes_rx: rx,
                bytes_tx: tx,
                peer_ip: Some(crate::control::peer_ip_string(session.peer().ip())),
            });
        }
        if let Ok(mut pending) = self.pending.lock() {
            out.append(&mut pending);
        }
        // Closed sessions are reported by the caller from `reap`, with an
        // `ended_at`. `now_unix` keeps the caller's clock authoritative.
        let _ = now_unix;
        out
    }

    /// Convert closed sessions into final reports.
    #[must_use]
    pub fn final_deltas(closed: &[ClosedSession], ended_at: i64) -> Vec<SessionDelta> {
        closed
            .iter()
            .map(|c| SessionDelta {
                tag: to_hex(&c.routing_tag),
                started_at: c.started_unix,
                ended_at: Some(ended_at),
                bytes_rx: c.bytes_rx,
                bytes_tx: c.bytes_tx,
                peer_ip: Some(c.peer_ip.clone()),
            })
            .collect()
    }
}

/// Convenience for tests and the binary: a node wired to a socket.
pub async fn drive(
    node: &Node,
    sock: &UdpSocket,
    datagram: &[u8],
    from: SocketAddr,
    now_us: u64,
) -> Option<Vec<u8>> {
    match node.route(sock, datagram, from, now_us).await {
        Ok(Outcome::Packet(pkt)) => Some(pkt),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;
    use vpn_core::config::TunnelConfig;
    use vpn_core::crypto::KEY_LEN;
    use vpn_core::{DonorSpec, HelloProfile};

    const TAG_KEY: [u8; 32] = [0x22; 32];
    const PSK: [u8; 32] = [0x11; 32];
    const USER: u64 = 42;

    fn tags() -> Arc<RwLock<TagTable>> {
        let mut t = TagTable::new();
        t.insert(&TAG_KEY, USER, PSK);
        Arc::new(RwLock::new(t))
    }

    fn node() -> Node {
        Node::new(
            tags(),
            IpPool::new(Ipv4Addr::new(10, 66, 0, 0), 24),
            vpn_core::packet::TUNNEL_MTU,
        )
    }

    fn cfg(server: SocketAddr) -> TunnelConfig {
        TunnelConfig {
            server,
            donor: DonorSpec::default(),
            psk: PSK,
            user_id: USER,
            tag_key: TAG_KEY,
            mtu: 1280,
            fingerprint: HelloProfile::default(),
            masquerade: false,
            handshake_timeout: StdDuration::from_secs(2),
        }
    }

    #[tokio::test]
    async fn a_probe_is_rejected_and_counted() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let node = node();
        let bogus = packet::encode_plaintext_control(
            0,
            0,
            &vpn_core::frame::Hello {
                tag: [0xAA; TAG_LEN],
                client_random: [1; 32],
                x25519_pub: [2; 32],
                window: 0,
                mac: [3; vpn_core::auth::MAC_LEN],
            }
            .encode(),
        );
        let from: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        assert!(node.route(&sock, &bogus, from, 0).await.is_err());
        let s = node.stats().await;
        assert_eq!(s.rejected_handshakes, 1);
        assert_eq!(s.sessions, 0);
    }

    #[tokio::test]
    async fn a_handshake_leases_an_address_and_a_second_replaces_it() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let node = node();
        let from: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let (_s, hello) = handshake::start(&cfg(addr), unix_now_secs()).unwrap();
        let outcome = node.route(&sock, &hello, from, 0).await.unwrap();
        let first_ip = match outcome {
            Outcome::Handshaked { ip, .. } => ip,
            other => panic!("expected a handshake, got {other:?}"),
        };
        assert_eq!(first_ip, Ipv4Addr::new(10, 66, 0, 2));
        assert_eq!(node.stats().await.sessions, 1);

        // A reconnect from the same user must replace, not leak.
        let (_s2, hello2) = handshake::start(&cfg(addr), unix_now_secs()).unwrap();
        let outcome = node.route(&sock, &hello2, from, 1_000).await.unwrap();
        assert!(matches!(outcome, Outcome::Handshaked { .. }));
        assert_eq!(node.stats().await.sessions, 1, "a reconnect must not leak");
    }

    #[tokio::test]
    async fn unknown_tags_are_counted_and_do_not_create_sessions() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let node = node();
        let mut dg = packet::Header::new(0, 0xDEAD, 1).encode().to_vec();
        dg.extend_from_slice(&[0u8; 32]);
        let from: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        assert!(node.route(&sock, &dg, from, 0).await.is_err());
        assert_eq!(node.stats().await.unknown_tags, 1);
        assert_eq!(node.stats().await.sessions, 0);
    }

    #[tokio::test]
    async fn a_session_born_late_is_not_reaped_immediately() {
        // Regression: seeding the idle timer at zero made any session created
        // more than `idle_timeout` after start-up die on the first tick.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let node = node();
        let from: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let (_s, hello) = handshake::start(&cfg(addr), unix_now_secs()).unwrap();
        let born = 300_000_000u64;
        node.route(&sock, &hello, from, born).await.unwrap();
        assert_eq!(node.stats().await.sessions, 1);

        assert!(node.reap(&sock, born + 1_000_000).await.is_empty());
        assert_eq!(node.stats().await.sessions, 1);

        let idle = IDLE_TIMEOUT.as_micros() as u64;
        let closed = node.reap(&sock, born + idle).await;
        assert_eq!(closed.len(), 1);
        assert_eq!(node.stats().await.sessions, 0);
    }

    #[tokio::test]
    async fn reaping_hands_back_the_address_and_a_final_delta() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let node = node();
        let from: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let (_s, hello) = handshake::start(&cfg(addr), unix_now_secs()).unwrap();
        node.route(&sock, &hello, from, 0).await.unwrap();

        let idle = IDLE_TIMEOUT.as_micros() as u64;
        let closed = node.reap(&sock, idle).await;
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].ip, Ipv4Addr::new(10, 66, 0, 2));
        assert_eq!(closed[0].user_id, USER);

        let finals = Node::final_deltas(&closed, 1_700_000_000);
        assert_eq!(finals[0].ended_at, Some(1_700_000_000));
        assert_eq!(finals[0].tag, vpn_core::config::to_hex(&closed[0].routing_tag));

        // The address must be reusable.
        let (_s, hello2) = handshake::start(&cfg(addr), unix_now_secs()).unwrap();
        let out = node.route(&sock, &hello2, from, idle + 1).await.unwrap();
        assert!(matches!(out, Outcome::Handshaked { ip, .. } if ip == Ipv4Addr::new(10, 66, 0, 2)));
    }

    #[tokio::test]
    async fn an_outbound_packet_without_a_route_is_dropped_not_errored() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let node = node();
        assert!(!node
            .send_to_client(&sock, Ipv4Addr::new(10, 66, 0, 9), &[0x45; 20], 0)
            .await
            .unwrap());
    }

    #[test]
    fn a_client_key_that_is_not_32_bytes_is_refused_by_the_table() {
        let mut t = TagTable::new();
        t.insert(&[0x01; KEY_LEN], 1, [0x11; KEY_LEN]);
        assert!(TagTable::build(&[0x01; KEY_LEN], &[(2, "zz".into())]).is_err());
    }
}
