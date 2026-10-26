//! Donor splice supervision — phase 1 of the masquerade.
//!
//! Flow of a datagram through the server:
//!
//! 1. If the peer already has an active splice, its bytes go to the donor
//!    verbatim (the client's side of a QUIC conversation after the Initial).
//! 2. Otherwise, a long-header (`0xC0..=0xFF`) datagram goes through
//!    [`vpn_core::masquerade::inspect_client_hello`] and, when fields lift,
//!    [`crate::interceptor::classify_initial`]. **A verified `session_id`
//!    label** means the bProto tunnel takes over and no splice is ever opened
//!    (the client's subsequent native `0x1x` datagrams flow through
//!    [`ServerNode::handle`]). A session_id that fails lookup / MAC — which is
//!    exactly what TLS-level active probes deliver — is *not* ours: it takes
//!    point 3 like every other probe. Returning silence for a stuffed
//!    session_id would itself be a probing oracle.
//! 3. Anything else — including a genuine browser/probe/h3-prober — gets a
//!    splice to the configured donor: a faithful white-site visit, byte for
//!    byte, in both directions.
//!
//! Splices end on `masquerade.splice_idle_secs` of idleness (measured on the
//! ClientHello time base, not per-byte activity) or a hard cap of
//! `max_concurrent_splices`; a splice that outlives its idle timer is torn
//! down silently. The main loop forwards datagrams to the supervisor channel
//! and sends donor replies back to their 5-tuple — from the listener itself.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::time::Instant;
use vpn_core::masquerade::relay::DonorUplink;
use vpn_core::masquerade::{InspectedClientHello, inspect_client_hello};
use vpn_core::session::unix_now_secs;

use crate::config::TagTable;
use crate::interceptor::{self, Verdict};

/// Per-flow command channel depth.
const CHANNEL_DEPTH: usize = 64;
/// UDP receive buffer on a splice's donor socket.
const BUFFER_BYTES: usize = 65_536;

/// How many peer flows may be spliced at once. Beyond the cap new splices are
/// refused: capping is a DoS guard, not part of the masquerade design.
const MAX_SPLICES: usize = 256;

/// Idle teardown timer.
const SPLICE_IDLE: Duration = Duration::from_secs(30);

/// What a caller that received a datagram does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// The datagram was handed to a splice (or an active one); nothing else
    /// to do on the bProto side.
    Spliced,
    /// The datagram is a parseable client Initial carrying a label-shaped
    /// `session_id`: the interceptor and the bProto half take the flow.
    Tunnel,
    /// Native bProto datagram (version nibble = 1): straight to
    /// [`vpn_core::ServerNode::handle`].
    Native,
    /// No splice was possible (cap, or the peer datagram is an unparseable
    /// short-header datagram with no active splice): drop it.
    Drop,
}

/// The splice supervisor. One instance per UDP listener.
#[derive(Debug)]
pub struct Splicer {
    sock: Arc<UdpSocket>,
    donor: SocketAddr,
    /// Label-verification source: the tag table is shared with the admin API.
    tags: Arc<std::sync::RwLock<TagTable>>,
    flows: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
    spliced: Arc<std::sync::atomic::AtomicUsize>,
}

/// Whether a fully parsed Initial carries a *verified* label — an
/// [`interceptor::Verdict::Intercept`] verdict. Extracted so tests can drive
/// the verdict with hand-built [`InspectedClientHello`] payloads instead of
/// sealing real QUIC flights.
fn labeled_initial_is_ours(hello: &InspectedClientHello, tags: &TagTable, now: u64) -> bool {
    matches!(
        interceptor::classify_initial(hello, tags, now),
        Verdict::Intercept(_)
    )
}

impl Splicer {
    /// Build a splicer for an already-resolved donor.
    pub fn start(
        sock: Arc<UdpSocket>,
        donor: SocketAddr,
        tags: Arc<std::sync::RwLock<TagTable>>,
    ) -> Self {
        Self {
            sock,
            donor,
            tags,
            flows: Arc::new(Mutex::new(HashMap::new())),
            spliced: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Number of currently active splices.
    #[must_use]
    pub fn active(&self) -> usize {
        self.spliced.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether a peer flow currently has a splice.
    pub async fn is_spliced(&self, peer: SocketAddr) -> bool {
        self.flows.lock().await.contains_key(&peer)
    }

    /// Feed one client datagram into the splice decision.
    ///
    /// `dgram` is forwarded bytes-verbatim when splicing; the caller never
    /// re-writes anything on this path.
    pub async fn on_datagram(&self, peer: SocketAddr, dgram: &[u8]) -> Action {
        // Active splice: forward, keep the flow's tick.
        let tx = self.flows.lock().await.get(&peer).cloned();
        if let Some(tx) = tx
            && tx.send(dgram.to_vec()).await.is_ok()
        {
            return Action::Spliced;
        }
        // The channel died (supervisor gone): retry as a fresh flow.

        // Native bProto byte 0 = (1 << 4) | flags = 0x10..0x1F. Never a QUIC
        // shape: hand it straight back to the protocol half.
        if dgram.first().is_some_and(|b| *b & 0xF0 == 0x10) {
            return Action::Native;
        }

        // Not an Initial long-header datagram from an unknown peer: we can't
        // classify it as ours; short-header QUIC without state is served
        // by the donor visit too, but without an open splice channel it
        // would dead-end — drop instead.
        if dgram.first().is_none_or(|b| *b & 0xC0 != 0xC0) {
            return Action::Drop;
        }

        // Try the tunnel: is this datagram a labeled Initial?
        let hello = match inspect_client_hello(dgram) {
            Ok(h) => h,
            // Parse failed — treat as prober traffic and splice it through.
            Err(_) => return self.open(peer, dgram).await,
        };
        let (Some(_sid), Some(_cr), Some(_kp)) = (
            hello.session_id.as_ref(),
            hello.client_random.as_ref(),
            hello.x25519_share.as_ref(),
        ) else {
            return self.open(peer, dgram).await;
        };
        // The label decision needs the tag table: only a fully verified label
        // is ours. A stuffed or forged session_id — precisely what active
        // TLS probes send — must get the same white-site visit as an empty
        // one, otherwise the server leaks "this port special-cases sid"
        // as a probing oracle.
        let ours = self.tags.read().is_ok_and(|table| {
            labeled_initial_is_ours(&hello, &table, unix_now_secs())
        });
        if !ours {
            return self.open(peer, dgram).await;
        }
        Action::Tunnel
    }

    /// Open a splice for `peer` and forward `first_dgram` as its first bytes.
    async fn open(&self, peer: SocketAddr, first_dgram: &[u8]) -> Action {
        let active = self.spliced.load(std::sync::atomic::Ordering::Relaxed);
        if active >= MAX_SPLICES {
            tracing::warn!(%peer, splices = active, "splice cap reached; dropping");
            return Action::Drop;
        }
        let uplink = match DonorUplink::bind_to(self.donor).await {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(error = %e, %peer, "could not open donor uplink; dropping");
                return Action::Drop;
            }
        };
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);
        self.flows.lock().await.insert(peer, tx.clone());
        self.spliced
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let sock = Arc::clone(&self.sock);
        let flows = Arc::clone(&self.flows);
        let spliced = Arc::clone(&self.spliced);
        tokio::spawn(async move {
            supervise(sock, uplink, peer, &mut rx, flows, spliced).await;
        });
        // Ship the first datagram down the brand-new channel.
        let _sent = tx.send(first_dgram.to_vec()).await;
        Action::Spliced
    }
}

/// Drive one splice: mirrors client→donor and donor→client until the idle
/// timer (reset on any activity) or an error ends the flow.
async fn supervise(
    sock: Arc<UdpSocket>,
    uplink: DonorUplink,
    peer: SocketAddr,
    rx: &mut mpsc::Receiver<Vec<u8>>,
    flows: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
    spliced: Arc<std::sync::atomic::AtomicUsize>,
) {
    let mut buf = vec![0u8; BUFFER_BYTES];
    let mut deadline = Instant::now() + SPLICE_IDLE;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                tracing::debug!(%peer, "splice idle timeout");
                break;
            }
            dgram = rx.recv() => {
                let Some(dgram) = dgram else { break };
                if uplink.forward(&dgram).await.is_err() {
                    break;
                }
                deadline = Instant::now() + SPLICE_IDLE;
            }
            reply = uplink.recv(&mut buf) => {
                let Ok(n) = reply else { break };
                if sock.send_to(&buf[..n], peer).await.is_err() {
                    break;
                }
                deadline = Instant::now() + SPLICE_IDLE;
            }
        }
    }
    flows.lock().await.remove(&peer);
    spliced.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A loopback stand-in for the donor: echoes every datagram back to its
    /// apparent sender, the way the donor's QUIC stack replies.
    async fn echo_donor() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; BUFFER_BYTES];
            loop {
                if let Ok((n, from)) = sock.recv_from(&mut buf).await
                    && sock.send_to(&buf[..n], from).await.is_err()
                {
                    break;
                }
            }
        });
        (addr, handle)
    }

    async fn listener() -> Arc<UdpSocket> {
        // Bound immediately; tests only send_to through it.
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
    }

    /// Empty tag table: nothing is ours, every Initial takes the donor path.
    fn no_tags() -> Arc<std::sync::RwLock<TagTable>> {
        Arc::new(std::sync::RwLock::new(TagTable::new()))
    }

    #[tokio::test]
    async fn label_stuffed_session_id_takes_the_donor_path() {
        // Verdict-level test of the probing oracle: with no tag entry the
        // label check fails no matter what session_id the prober stuffs, and
        // with the right PSK+tag the derived label verifies.
        let tag_key = [0x11u8; vpn_core::crypto::KEY_LEN];
        let psk = [0x22u8; vpn_core::crypto::KEY_LEN];
        let mut table = TagTable::new();
        table.insert(&tag_key, 7, psk);
        let table = Arc::new(std::sync::RwLock::new(table));

        let cr = [0xA5u8; 32];
        let pubk = vpn_core::crypto::KeyPair::generate().public_bytes();
        let good_sid = vpn_core::auth::derive_session_id(
            &psk,
            &vpn_core::auth::compute_tag(&tag_key, 7),
            &cr,
            &pubk,
            unix_now_secs(),
        );
        let mk = |sid: Option<[u8; 32]>| InspectedClientHello {
            dcid: vec![1, 2, 3],
            scid: vec![9],
            token: Vec::new(),
            sni: None,
            session_id: sid,
            client_random: Some(cr),
            x25519_share: Some(pubk),
        };
        let now = unix_now_secs();

        // Our own labeled Initial: intercept.
        assert!(labeled_initial_is_ours(&mk(Some(good_sid)), &table.read().unwrap(), now));

        // A prober that stuffs 32 random bytes into session_id: not ours —
        // the donor visit, never silence.
        assert!(!labeled_initial_is_ours(&mk(Some([0x77u8; 32])), &table.read().unwrap(), now));

        // A valid tag with a *stale* label byte (e.g. a replay across window):
        // the MAC over it fails, so still not ours.
        let mut stale = vpn_core::auth::derive_session_id(
            &psk,
            &vpn_core::auth::compute_tag(&tag_key, 7),
            &cr,
            &pubk,
            unix_now_secs(),
        );
        stale[31] ^= 0x01;
        assert!(!labeled_initial_is_ours(&mk(Some(stale)), &table.read().unwrap(), now));
    }

    #[tokio::test]
    async fn non_initial_short_datagram_is_dropped() {
        let donor = echo_donor().await.0;
        let splicer = Splicer::start(listener().await, donor, no_tags());
        // bProto native header byte 0x11: version 1 — must reach
        // node.handle, never the masquerade paths.
        assert_eq!(
            splicer
                .on_datagram("127.0.0.1:40000".parse().unwrap(), &[0x11])
                .await,
            Action::Native
        );
        assert_eq!(splicer.active(), 0);
    }

    #[tokio::test]
    async fn unknown_initial_opens_and_drives_a_splice() {
        let (donor_addr, donor_task) = echo_donor().await;
        let sock = listener().await;
        let local = sock.local_addr().unwrap();
        let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = client.local_addr().unwrap();

        let splicer = Splicer::start(Arc::clone(&sock), donor_addr, no_tags());
        // A fake "Initial": any 0xC0-prefixed datagram the inspector can't
        // classify takes the donor visit path.
        let dgram = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0xEE];
        assert_eq!(splicer.on_datagram(peer, &dgram).await, Action::Spliced);
        assert_eq!(splicer.active(), 1);

        // The stand-in donor receives it and echoes; the client must get
        // those echo bytes back from the listener's address, byte-alike.
        let mut reply = vec![0u8; BUFFER_BYTES];
        let (n, from) = client.recv_from(&mut reply).await.unwrap();
        assert_eq!(from, local, "replies must come from the listener socket");
        assert_eq!(&reply[..n], &dgram[..n]);

        // A follow-up datagram rides the same flow.
        let again = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0xFF];
        assert_eq!(splicer.on_datagram(peer, &again).await, Action::Spliced);
        let mut second = vec![0u8; BUFFER_BYTES];
        let (n2, _) = client.recv_from(&mut second).await.unwrap();
        assert_eq!(&second[..n2], &again[..n2]);

        drop(splicer);
        donor_task.abort();
    }

    #[tokio::test]
    async fn short_datagram_on_active_splice_still_forwards() {
        // After an open splice, follow-up short-header datagrams (the
        // client's 1-RTT traffic) ride the same flow to the donor.
        let (donor_addr, donor_task) = echo_donor().await;
        let sock = listener().await;
        let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = client.local_addr().unwrap();
        let splicer = Splicer::start(Arc::clone(&sock), donor_addr, no_tags());

        let first = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0xEE];
        assert_eq!(splicer.on_datagram(peer, &first).await, Action::Spliced);
        let short = vec![0x42u8; 12]; // 1-RTT-ish short header
        assert_eq!(splicer.on_datagram(peer, &short).await, Action::Spliced);

        let mut reply = vec![0u8; BUFFER_BYTES];
        client.recv_from(&mut reply).await.unwrap(); // echo of `first`
        let (n, _) = client.recv_from(&mut reply).await.unwrap(); // echo of `short`
        assert_eq!(&reply[..n], &short[..]);
        drop(splicer);
        donor_task.abort();
    }
}
