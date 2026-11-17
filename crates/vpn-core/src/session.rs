//! Session state and the public client [`Tunnel`].
//!
//! Two layers live here:
//!
//! * [`Session`] — the pure crypto state of one established session: seal an IP
//!   packet, open a datagram, count bytes, enforce anti-replay. It is shared by
//!   the client ([`Tunnel`]) and the server ([`crate::server::ServerNode`]).
//! * [`Tunnel`] — the client endpoint: owns the UDP socket, runs the handshake,
//!   and drives a background task that decrypts inbound datagrams, acknowledges
//!   them, estimates RTT, feeds CUBIC and keeps the path alive.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify, mpsc};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::ack::{AckRanges, RttEstimator, SentPackets};
use crate::config::TunnelConfig;
use crate::congestion::Cubic;
use crate::crypto::{self, SessionKeys};
use crate::error::{Error, Result};
use crate::frame::{self, FrameType};
use crate::handshake;
use crate::packet::{self, Header, InnerType, MAX_DATAGRAM};
use crate::replay::ReplayWindow;
use crate::transport::udp;

/// How many received packets trigger an immediate ACK.
const ACK_EVERY: u64 = 8;
/// Housekeeping tick period.
const TICK: Duration = Duration::from_millis(20);
/// Handshake retransmit interval.
const HANDSHAKE_RETRY: Duration = Duration::from_millis(500);
/// Declare the session dead after this much inbound silence.
const IDLE_TIMEOUT: Duration = Duration::from_secs(45);

// --- Firefox-shaped pacing (measured from a real HTTP/3 capture) -----------

/// Size band of the tiny QUIC control/ack datagrams Firefox emits: jittered
/// inside 43–51 B so the cadence cannot be fingerprinted by exact size.
const CONTROL_SIZE_MIN: usize = 43;
/// Upper end of the control-size band.
const CONTROL_SIZE_MAX: usize = 51;
/// Spacing between the two padded Initial datagrams (Firefox's anti-loss
/// duplicate first flight).
const INITIAL_GAP: Duration = Duration::from_micros(200);
/// An ACK goes out 0.3–2 ms after the first inbound datagram of a burst, never
/// on a fixed timer. This is Firefox's quinn ack-delay policy, measured.
const ACK_DELAY_MIN_US: u64 = 300;
/// Upper end of the ack-delay jitter.
const ACK_DELAY_MAX_US: u64 = 2_000;

/// Jittered control-datagram size: a fresh random draw inside the measured band
/// for every frame we send.
fn control_size() -> usize {
    crate::crypto::random_32()[0] as usize % (CONTROL_SIZE_MAX - CONTROL_SIZE_MIN + 1)
        + CONTROL_SIZE_MIN
}

/// Snapshot of tunnel health, polled by the GUI/service.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TunnelStats {
    /// Smoothed RTT estimate, microseconds.
    pub rtt_us: u64,
    /// Current congestion window in bytes.
    pub cwnd_bytes: u64,
    /// Bytes received from the server (post-decrypt).
    pub rx_bytes: u64,
    /// Bytes sent to the server (pre-encrypt).
    pub tx_bytes: u64,
    /// Datagrams dropped as replays or for failed authentication.
    pub dropped: u64,
    /// Whole seconds since the session was established.
    pub uptime_s: u64,
}

/// A decrypted datagram's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    /// One IP packet for the embedder's TUN.
    Ip(Vec<u8>),
    /// An encrypted control frame.
    Control(Vec<u8>),
    /// A keepalive with no payload.
    Keepalive,
}

/// Crypto and accounting state of one established session.
#[derive(Debug)]
pub struct Session {
    keys: SessionKeys,
    session_tag: AtomicU32,
    tx_pn: AtomicU64,
    rx_replay: Mutex<ReplayWindow>,
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    dropped: AtomicU64,
    mtu: usize,
}

impl Session {
    /// Build a session from a negotiated key schedule.
    #[must_use]
    pub fn new(keys: SessionKeys, session_tag: u32, mtu: usize) -> Self {
        Self {
            keys,
            session_tag: AtomicU32::new(session_tag),
            tx_pn: AtomicU64::new(0),
            rx_replay: Mutex::new(ReplayWindow::new()),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            mtu,
        }
    }

    /// The routing tag currently in use.
    #[must_use]
    pub fn session_tag(&self) -> u32 {
        self.session_tag.load(Ordering::Relaxed)
    }

    /// Rotate the routing tag. Both peers must agree, so this is only called by
    /// the rekey path once that exists.
    pub fn set_session_tag(&self, tag: u32) {
        self.session_tag.store(tag, Ordering::Relaxed);
    }

    /// Effective tunnel MTU in bytes.
    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Bytes received and authenticated.
    #[must_use]
    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }

    /// Bytes sent.
    #[must_use]
    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }

    /// Datagrams dropped (replay or auth failure).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Encrypt one IP packet. Returns `(packet_number, datagram)`.
    pub fn seal_ip(&self, ip: &[u8]) -> Result<(u64, Vec<u8>)> {
        if ip.len() > self.mtu {
            return Err(Error::PayloadTooLarge(ip.len(), self.mtu));
        }
        let pn = self.tx_pn.fetch_add(1, Ordering::Relaxed);
        let (aad, ct) = self.seal_inner(InnerType::Ip, ip, pn)?;
        self.tx_bytes.fetch_add(ip.len() as u64, Ordering::Relaxed);
        Ok((pn, join(aad, ct)))
    }

    /// Encrypt one control frame. Returns `(packet_number, datagram)`.
    pub fn seal_control(&self, frame: &[u8]) -> Result<(u64, Vec<u8>)> {
        let pn = self.tx_pn.fetch_add(1, Ordering::Relaxed);
        let (aad, ct) = self.seal_inner(InnerType::Control, frame, pn)?;
        Ok((pn, join(aad, ct)))
    }

    /// Encrypt an empty keepalive.
    pub fn seal_keepalive(&self) -> Result<(u64, Vec<u8>)> {
        let pn = self.tx_pn.fetch_add(1, Ordering::Relaxed);
        let (aad, ct) = self.seal_inner(InnerType::Keepalive, &[], pn)?;
        Ok((pn, join(aad, ct)))
    }

    /// Encrypt one control frame with zero-padding inside the AEAD, so the
    /// finished datagram is exactly `target` bytes on the wire.
    ///
    /// The padding lives inside the ciphertext, so it is indistinguishable from
    /// payload: the outer datagram stays uniformly random, exactly like a real
    /// QUIC packet. Used to keep control flights inside the measured Firefox
    /// size band instead of exposing the tiny 30–42 B raw frame sizes.
    pub fn seal_control_padded(&self, frame: &[u8], target: usize) -> Result<(u64, Vec<u8>)> {
        let plain = packet::bucket_plaintext(target);
        if plain < packet::INNER_HDR_LEN + frame.len() {
            return Err(Error::PayloadTooLarge(frame.len(), plain));
        }
        let pn = self.tx_pn.fetch_add(1, Ordering::Relaxed);
        let (aad, ct) = self.seal_inner_padded(InnerType::Control, frame, pn, Some(plain))?;
        Ok((pn, join(aad, ct)))
    }

    fn seal_inner(&self, ty: InnerType, payload: &[u8], pn: u64) -> Result<([u8; 12], Vec<u8>)> {
        self.seal_inner_padded(ty, payload, pn, None)
    }

    fn seal_inner_padded(
        &self,
        ty: InnerType,
        payload: &[u8],
        pn: u64,
        bucket: Option<usize>,
    ) -> Result<([u8; 12], Vec<u8>)> {
        let header = Header::new(0, self.session_tag(), pn);
        let aad = header.encode();
        let inner = packet::encode_inner(ty, payload, bucket);
        let ct = crypto::seal(
            &self.keys.tx_key,
            &self.keys.tx_nonce_prefix,
            &aad,
            pn,
            &inner,
        )?;
        Ok((aad, ct))
    }

    /// Authenticate and decrypt one datagram.
    ///
    /// Order: authenticate first (so an attacker cannot poison the replay window
    /// with forged packet numbers), then check replay.
    pub async fn open(&self, datagram: &[u8]) -> Result<(u64, Opened)> {
        let header = Header::decode(datagram)?;
        if header.reserved != 0 {
            return Err(Error::Config("non-zero reserved header field".into()));
        }
        let aad = &datagram[..packet::HEADER_LEN];
        let ct = &datagram[packet::HEADER_LEN..];
        let plaintext = crypto::open(
            &self.keys.rx_key,
            &self.keys.rx_nonce_prefix,
            aad,
            header.packet_number,
            ct,
        )
        .inspect_err(|_| {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        })?;

        {
            let mut w = self.rx_replay.lock().await;
            if w.check_and_mark(header.packet_number).is_err() {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return Err(Error::Replay(header.packet_number));
            }
        }

        let (ty, payload) = packet::decode_inner(&plaintext)?;
        let pn = header.packet_number;
        match ty {
            InnerType::Ip => {
                self.rx_bytes
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                Ok((pn, Opened::Ip(payload.to_vec())))
            }
            InnerType::Control => Ok((pn, Opened::Control(payload.to_vec()))),
            InnerType::Keepalive => Ok((pn, Opened::Keepalive)),
        }
    }
}

fn join(aad: [u8; 12], ct: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(aad.len() + ct.len());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&ct);
    out
}

/// Timestamp in whole seconds since the Unix epoch.
#[must_use]
pub fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ---------------------------------------------------------------------------
// Client endpoint
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ClientShared {
    session: Session,
    wire: Arc<Wire>,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    rtt: Mutex<RttEstimator>,
    cc: Mutex<Cubic>,
    sent: Mutex<SentPackets>,
    ack: Mutex<AckRanges>,
    pending_acks: AtomicU64,
    last_rx_ms: AtomicU64,
    room: Notify,
    start: Instant,
}

/// The client's wire link: QUIC-shaped UDP datagrams, or length-prefixed
/// frames over one TCP stream (for paths where UDP is throttled or blocked).
#[derive(Debug)]
enum Wire {
    Udp {
        sock: Arc<UdpSocket>,
        peer: SocketAddr,
    },
    Tcp {
        /// Outbound datagrams, framed by a dedicated writer task.
        tx: mpsc::Sender<Vec<u8>>,
        /// Inbound datagrams fed by the reader task.
        rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    },
}

/// TCP framing: one u16 big-endian length prefix per datagram.
const TCP_MAX_FRAME: usize = MAX_DATAGRAM + 32;

impl Wire {
    /// Open the link. UDP binds a browser-shaped socket from the shape
    /// profile; TCP opens a framed stream.
    async fn connect(
        peer: SocketAddr,
        kind: crate::TransportKind,
        shape: &crate::shape::ShapeProfile,
    ) -> Result<Self> {
        match kind {
            crate::TransportKind::Udp | crate::TransportKind::Auto => {
                let sock = udp::bind_for(peer, shape.ttl, shape.df).await?;
                Ok(Self::Udp {
                    sock: Arc::new(sock),
                    peer,
                })
            }
            crate::TransportKind::Tcp => Self::tcp(peer).await,
        }
    }

    async fn tcp(peer: SocketAddr) -> Result<Self> {
        let stream = tokio::net::TcpStream::connect(peer)
            .await
            .map_err(|e| Error::Transport(format!("tcp connect {peer}: {e}")))?;
        stream.set_nodelay(true).ok();
        let (mut read_half, mut write_half) = stream.into_split();
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(2048);

        // Writer task: u16 BE length prefix + datagram.
        tokio::spawn(async move {
            while let Some(datagram) = out_rx.recv().await {
                if datagram.len() > TCP_MAX_FRAME {
                    continue;
                }
                let mut frame = Vec::with_capacity(2 + datagram.len());
                frame.extend_from_slice(&(datagram.len() as u16).to_be_bytes());
                frame.extend_from_slice(&datagram);
                if write_half.write_all(&frame).await.is_err() {
                    break;
                }
            }
        });

        // Reader task: split frames, hand each to the tunnel.
        tokio::spawn(async move {
            let mut len_buf = [0u8; 2];
            loop {
                if read_half.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                if len == 0 || len > TCP_MAX_FRAME {
                    break;
                }
                let mut datagram = vec![0u8; len];
                if read_half.read_exact(&mut datagram).await.is_err() {
                    break;
                }
                if in_tx.send(datagram).await.is_err() {
                    break;
                }
            }
        });

        Ok(Self::Tcp {
            tx: out_tx,
            rx: tokio::sync::Mutex::new(in_rx),
        })
    }

    async fn send(&self, datagram: &[u8]) -> Result<()> {
        match self {
            Self::Udp { sock, peer } => udp::send(sock, datagram, *peer).await,
            Self::Tcp { tx, .. } => tx
                .send(datagram.to_vec())
                .await
                .map_err(|_| Error::Transport("tcp link closed".into())),
        }
    }

    /// Next inbound datagram from the server (UDP: from the expected peer
    /// only; TCP: the next frame). Returns `None` when the link is closed.
    async fn recv(&self, buf: &mut [u8]) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Udp { sock, peer } => loop {
                let (n, from) = udp::recv(sock, buf).await?;
                if from != *peer {
                    continue;
                }
                return Ok(Some(buf[..n].to_vec()));
            },
            Self::Tcp { rx, .. } => Ok(rx.lock().await.recv().await),
        }
    }
}

impl ClientShared {
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn now_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    async fn send_ack(&self) -> Result<()> {
        let ranges = {
            let mut a = self.ack.lock().await;
            if a.is_empty() {
                return Ok(());
            }
            std::mem::take(&mut *a)
        };
        self.pending_acks.store(0, Ordering::Relaxed);
        let (_, datagram) = self
            .session
            .seal_control_padded(&ranges.encode(), control_size())?;
        self.wire.send(&datagram).await
    }

    async fn send_control(&self, frame: &[u8]) -> Result<()> {
        let (_, datagram) = self.session.seal_control_padded(frame, control_size())?;
        self.wire.send(&datagram).await
    }

    async fn mark_ack(&self, pn: u64) -> bool {
        {
            let mut a = self.ack.lock().await;
            a.insert(pn);
        }
        let pending = self.pending_acks.fetch_add(1, Ordering::Relaxed) + 1;
        pending >= ACK_EVERY
    }
}

/// A live client tunnel.
#[derive(Debug)]
pub struct Tunnel {
    shared: Arc<ClientShared>,
    assigned_ip: Ipv4Addr,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    task: JoinHandle<()>,
}

impl Tunnel {
    /// Establish a tunnel: run the handshake, derive keys, start the datapath.
    ///
    /// `transport = "auto"` tries UDP first and, if the handshake does not
    /// complete in time, retries over the TCP transport.
    pub async fn connect(cfg: TunnelConfig) -> Result<Self> {
        match cfg.transport {
            crate::TransportKind::Auto => {
                let mut udp_cfg = cfg.clone();
                udp_cfg.transport = crate::TransportKind::Udp;
                match Self::connect_once(udp_cfg.clone()).await {
                    Ok(t) => Ok(t),
                    Err(
                        Error::HandshakeTimeout
                        | Error::Transport(_)
                        | Error::Io(_)
                        | Error::Decrypt,
                    ) => {
                        let mut tcp_cfg = cfg.clone();
                        tcp_cfg.transport = crate::TransportKind::Tcp;
                        Self::connect_once(tcp_cfg).await
                    }
                    Err(e) => Err(e),
                }
            }
            _ => Self::connect_once(cfg).await,
        }
    }

    async fn connect_once(cfg: TunnelConfig) -> Result<Self> {
        cfg.validate()?;
        let peer = cfg.server;
        let mtu = cfg.effective_mtu();
        let shape = crate::shape::ShapeProfile::resolve(&cfg.shape)?;
        let wire = Arc::new(Wire::connect(peer, cfg.transport, &shape).await?);

        let deadline = Instant::now() + cfg.handshake_timeout;
        let (state, hello) = handshake::start(&cfg, unix_now_secs())?;
        let mut attempt = 0u32;
        let mut buf = vec![0u8; MAX_DATAGRAM + 32];

        let established = loop {
            if Instant::now() >= deadline {
                return Err(Error::HandshakeTimeout);
            }
            if attempt == 0 {
                // Pre-flight noise (Xray finalmask/noise style): the profile's
                // random datagrams blur the moment the real flight starts.
                for _ in 0..shape.noise.count {
                    wire.send(&shape.noise_datagram()).await?;
                }
                // The browser flight: a real QUIC Initial carrying the labeled
                // ClientHello goes out first when the profile crafts one.
                if !state.parrot().is_empty() {
                    wire.send(state.parrot()).await?;
                }
                // Chrome's anti-loss opening: the padded Initial goes out
                // twice, ~0.2 ms apart, both bytes-identical.
                wire.send(&hello).await?;
                tokio::time::sleep(INITIAL_GAP).await;
            }
            attempt += 1;
            wire.send(&hello).await?;
            match tokio::time::timeout(HANDSHAKE_RETRY, wire.recv(&mut buf)).await {
                Ok(Ok(Some(ack))) => {
                    if let Ok(est) = handshake::finish(&state, &ack) {
                        break est;
                    }
                    // A forged or stale datagram: keep retrying until timeout.
                }
                Ok(Ok(None)) => return Err(Error::Transport("link closed".into())),
                Ok(Err(e)) => return Err(Error::Transport(format!("recv: {e}"))),
                Err(_elapsed) => {} // retransmit
            }
        };

        let session = Session::new(established.keys, established.session_tag, mtu);
        let (inbound_tx, inbound_rx) = mpsc::channel(2048);
        let shared = Arc::new(ClientShared {
            session,
            wire,
            inbound_tx,
            rtt: Mutex::new(RttEstimator::default()),
            cc: Mutex::new(Cubic::new(mtu as u32)),
            sent: Mutex::new(SentPackets::default()),
            ack: Mutex::new(AckRanges::new()),
            pending_acks: AtomicU64::new(0),
            last_rx_ms: AtomicU64::new(0),
            room: Notify::new(),
            start: Instant::now(),
        });
        let task = tokio::spawn(client_loop(Arc::clone(&shared)));

        Ok(Self {
            shared,
            assigned_ip: established.assigned_ip,
            rx: Mutex::new(inbound_rx),
            task,
        })
    }

    /// The address the server leased to us.
    #[must_use]
    pub fn assigned_ip(&self) -> Ipv4Addr {
        self.assigned_ip
    }

    /// Effective tunnel MTU.
    #[must_use]
    pub fn mtu(&self) -> usize {
        self.shared.session.mtu()
    }

    /// Raw descriptor of the tunnel's UDP socket.
    ///
    /// Android needs this to call `VpnService.protect(fd)`: without it the
    /// tunnel's own traffic to the server is routed back into the tunnel and
    /// nothing gets through. The descriptor is owned by the tunnel; do not
    /// close it. Returns `-1` when the tunnel rides the TCP transport (no UDP
    /// socket to protect; the TCP stream needs no protection).
    #[cfg(unix)]
    #[must_use]
    pub fn socket_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        match &*self.shared.wire {
            Wire::Udp { sock, .. } => sock.as_raw_fd(),
            Wire::Tcp { .. } => -1,
        }
    }

    /// Encrypt and send one IP packet.
    ///
    /// Sends are gated by the CUBIC window: if it is full we wait briefly (2 ms)
    /// for ACKs to free room, then send anyway — the tunnel is datagram-based,
    /// so a drop here is a packet the transport would have dropped under load.
    pub async fn send_ip_packet(&self, ip_packet: &[u8]) -> Result<()> {
        let in_flight = self.shared.sent.lock().await.bytes_in_flight();
        if !self.shared.cc.lock().await.can_send(in_flight) {
            let _ =
                tokio::time::timeout(Duration::from_millis(2), self.shared.room.notified()).await;
        }
        let (pn, datagram) = self.shared.session.seal_ip(ip_packet)?;
        self.shared
            .sent
            .lock()
            .await
            .on_sent(pn, self.shared.now_us(), datagram.len() as u64);
        self.shared.wire.send(&datagram).await
    }

    /// Wait for the next inbound IP packet. Returns [`Error::NoSession`] once the
    /// session has gone idle.
    pub async fn recv_ip_packet(&self) -> Result<Vec<u8>> {
        self.rx.lock().await.recv().await.ok_or(Error::NoSession)
    }

    /// Best-effort graceful teardown.
    pub async fn close(&self) {
        let _ = self
            .shared
            .send_control(&frame::simple(FrameType::Close))
            .await;
    }

    /// Current stats. Never blocks: fields that are momentarily locked read 0.
    #[must_use]
    pub fn stats(&self) -> TunnelStats {
        TunnelStats {
            rtt_us: self.shared.rtt.try_lock().map_or(0, |r| r.smoothed()),
            cwnd_bytes: self.shared.cc.try_lock().map_or(0, |c| c.cwnd()),
            rx_bytes: self.shared.session.rx_bytes(),
            tx_bytes: self.shared.session.tx_bytes(),
            dropped: self.shared.session.dropped(),
            uptime_s: self.shared.start.elapsed().as_secs(),
        }
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One-shot delayed ACK task: fires 0.3–2 ms after an inbound burst started.
/// Safe against races — `send_ack` no-ops when the ranges were already
/// acked by a concurrent immediate flush.
fn schedule_delayed_ack(shared: &Arc<ClientShared>) {
    let shared = Arc::clone(shared);
    tokio::spawn(async move {
        let jitter = crate::crypto::random_32()[0] as u64 % (ACK_DELAY_MAX_US - ACK_DELAY_MIN_US);
        tokio::time::sleep(Duration::from_micros(ACK_DELAY_MIN_US + jitter)).await;
        let _ = shared.send_ack().await;
    });
}

async fn client_loop(shared: Arc<ClientShared>) {
    let mut buf = vec![0u8; MAX_DATAGRAM + 32];
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            received = shared.wire.recv(&mut buf) => {
                let Ok(Some(datagram)) = received else { break };
                let n = datagram.len();
                buf[..n].copy_from_slice(&datagram);
                // Plaintext control datagrams have no place in an established
                // session: what arrives here is the duplicate HELLO_ACK of the
                // Firefox-shaped double first flight (the connect loop already
                // consumed one). Consume silently instead of keeping it on
                // the packet-reject counter, which would read as corruption.
                if packet::Header::decode(&buf[..n])
                    .map(|h| h.is_control())
                    .unwrap_or(false)
                {
                    continue;
                }
                let Ok((pn, opened)) = shared.session.open(&buf[..n]).await else {
                    continue;
                };
                shared.last_rx_ms.store(shared.now_ms(), Ordering::Relaxed);
                let flush = shared.mark_ack(pn).await;
                // Response-driven ACKs only: either the buffer is full, or the
                // ack goes out 0.3–2 ms after the burst started — Firefox's
                // quinn ack-delay cadence, never a fixed period.
                if flush {
                    let _ = shared.send_ack().await;
                } else if shared.pending_acks.load(Ordering::Relaxed) == 1 {
                    schedule_delayed_ack(&shared);
                }
                match opened {
                    Opened::Ip(pkt) => {
                        if shared.inbound_tx.send(pkt).await.is_err() {
                            break;
                        }
                    }
                    Opened::Control(f) => {
                        handle_control(&shared, &f).await;
                    }
                    Opened::Keepalive => {}
                }
            }
            _ = tick.tick() => {
                // Firefox stays silent when idle: no timer-driven ACKs or
                // pings at all. Liveness is the server's job (its probe gets
                // our ACK below); the client only speaks after inbound
                // traffic. Exponential backoff on the server ensures the
                // channel stays alive without a 20 ms ping storm.
                let now = shared.now_ms();
                let idle = now.saturating_sub(shared.last_rx_ms.load(Ordering::Relaxed));
                if idle >= IDLE_TIMEOUT.as_millis() as u64 {
                    break;
                }
                // Loss detected by timeout still applies backpressure to CUBIC.
                let pto = shared.rtt.lock().await.pto();
                let expired = shared.sent.lock().await.timed_out(shared.now_us(), pto);
                if !expired.is_empty() {
                    shared.cc.lock().await.on_loss(shared.now_us());
                }
            }
        }
    }
}

async fn handle_control(shared: &Arc<ClientShared>, frame_bytes: &[u8]) {
    match frame::peek_type(frame_bytes) {
        Ok(FrameType::Ack) => {
            let Ok(ranges) = AckRanges::decode(frame_bytes) else {
                return;
            };
            let now_us = shared.now_us();
            let srtt = shared.rtt.lock().await.smoothed();

            let mut acked_bytes = 0u64;
            let mut newest: Option<(u64, u64)> = None; // (pn, sample)
            {
                let mut sent = shared.sent.lock().await;
                ranges.for_each(|pn| {
                    if let Some((t, bytes)) = sent.ack(pn) {
                        acked_bytes += bytes;
                        let sample = now_us.saturating_sub(t);
                        if newest.is_none_or(|(prev, _)| pn > prev) {
                            newest = Some((pn, sample));
                        }
                    }
                });
            }
            if acked_bytes > 0 {
                shared.cc.lock().await.on_ack(acked_bytes, now_us, srtt);
                shared.room.notify_waiters();
            }
            if let Some((_, sample)) = newest {
                shared.rtt.lock().await.update(sample);
            }
        }
        Ok(FrameType::Ping) => {
            let _ = shared.send_control(&frame::simple(FrameType::Pong)).await;
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DonorSpec, Fingerprint, StealthLevel};

    fn keys(seed: u8, is_client: bool) -> SessionKeys {
        crypto::derive_session_keys(&[seed; 32], &[1; 32], &[2; 32], is_client)
    }

    fn session(seed: u8, is_client: bool, tag: u32) -> Session {
        Session::new(keys(seed, is_client), tag, packet::TUNNEL_MTU)
    }

    #[tokio::test]
    async fn seal_then_open_across_peers() {
        let client = session(7, true, 0x1234);
        let server = session(7, false, 0x1234);

        let ip = vec![0x45u8; 60];
        let (pn, dg) = client.seal_ip(&ip).unwrap();
        assert_eq!(pn, 0);
        assert_eq!(Header::decode(&dg).unwrap().session_tag, 0x1234);
        let (rpn, opened) = server.open(&dg).await.unwrap();
        assert_eq!(rpn, 0);
        assert_eq!(opened, Opened::Ip(ip));
        assert_eq!(server.rx_bytes(), 60);
        assert_eq!(client.tx_bytes(), 60);
    }

    #[tokio::test]
    async fn control_frames_roundtrip() {
        let client = session(3, true, 9);
        let server = session(3, false, 9);
        let frame = frame::simple(FrameType::Ping);
        let (_, dg) = client.seal_control(&frame).unwrap();
        let (_, opened) = server.open(&dg).await.unwrap();
        assert_eq!(opened, Opened::Control(frame));
    }

    #[tokio::test]
    async fn keepalive_roundtrips() {
        let client = session(4, true, 9);
        let server = session(4, false, 9);
        let (_, dg) = client.seal_keepalive().unwrap();
        assert_eq!(server.open(&dg).await.unwrap().1, Opened::Keepalive);
    }

    #[tokio::test]
    async fn padded_control_lands_exactly_in_the_firefox_band() {
        let client = session(1, true, 9);
        let server = session(1, false, 9);
        for target in [43usize, 47, 51] {
            let frame = frame::simple(FrameType::Ping);
            let (_, dg) = client.seal_control_padded(&frame, target).unwrap();
            assert_eq!(dg.len(), target, "datagram must hit the requested size");
            let (_, opened) = server.open(&dg).await.unwrap();
            // Padding rides inside the AEAD: the decoders treat trailing zero
            // bytes past the frame as shaping padding, like real live paths do.
            let Opened::Control(plain) = opened else {
                panic!("control target missed");
            };
            assert_eq!(&plain[..frame.len()], &frame);
            assert!(plain[frame.len()..].iter().all(|&b| b == 0));
        }
    }

    #[tokio::test]
    async fn replay_is_rejected_and_counted() {
        let client = session(7, true, 1);
        let server = session(7, false, 1);
        let (_, dg) = client.seal_ip(&[0x45u8; 20]).unwrap();
        server.open(&dg).await.unwrap();
        assert!(matches!(server.open(&dg).await, Err(Error::Replay(_))));
        assert_eq!(server.dropped(), 1);
    }

    #[tokio::test]
    async fn oversized_payload_rejected() {
        let client = Session::new(keys(7, true), 1, packet::TUNNEL_MTU);
        let too_big = vec![0u8; packet::TUNNEL_MTU + 1];
        assert!(matches!(
            client.seal_ip(&too_big),
            Err(Error::PayloadTooLarge(_, _))
        ));
        assert!(client.seal_ip(&vec![0u8; packet::TUNNEL_MTU]).is_ok());
    }

    #[tokio::test]
    async fn tampered_header_fails_auth() {
        let client = session(7, true, 5);
        let server = session(7, false, 5);
        let (_, mut dg) = client.seal_ip(&[0x45u8; 20]).unwrap();
        dg[10] ^= 0xFF; // reserved byte is in the AAD
        assert!(matches!(server.open(&dg).await, Err(Error::Config(_))));
    }

    #[tokio::test]
    async fn forged_ciphertext_is_rejected() {
        let client = session(7, true, 5);
        let server = session(7, false, 5);
        let (_, mut dg) = client.seal_ip(&[0x45u8; 20]).unwrap();
        let last = dg.len() - 1;
        dg[last] ^= 0x80;
        assert!(matches!(server.open(&dg).await, Err(Error::Decrypt)));
    }

    #[test]
    fn stats_start_empty() {
        let s = TunnelStats::default();
        assert_eq!(s.rtt_us, 0);
        assert_eq!(s.cwnd_bytes, 0);
    }

    #[allow(dead_code)]
    fn demo_config() -> TunnelConfig {
        TunnelConfig {
            server: "127.0.0.1:443".parse().unwrap(),
            donor: DonorSpec::default(),
            psk: [0x11; 32],
            user_id: 1,
            tag_key: [0x22; 32],
            mtu: 1280,
            fingerprint: Fingerprint::Chrome112,
            stealth: StealthLevel::Off,
            handshake_timeout: Duration::from_secs(10),
            shape: crate::shape::ShapeConfig::default(),
            transport: crate::TransportKind::Udp,
        }
    }
}
