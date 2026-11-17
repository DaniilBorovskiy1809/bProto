//! Local SOCKS5 proxy over a bProto tunnel — the `bproto socks5` mode.
//!
//! Instead of a TUN device (which needs root) the CLI exposes a SOCKS5
//! listener on loopback. Applications point curl or a browser at it and their
//! TCP connections and DNS queries are carried through the encrypted tunnel:
//!
//! ```text
//! app ─TCP─▶ SOCKS5 (127.0.0.1:1080) ─TCP/UDP inside bProto─▶ server ─NAT─▶ internet
//! ```
//!
//! The client side of TCP runs on a small purpose-built stack: one connection
//! per SOCKS CONNECT, a sliding send window, RTO-based retransmission with
//! fast retransmit on triple duplicate ACKs, and a half-close. It is
//! deliberately not a general TCP implementation — just enough to proxy bulk
//! HTTP/TLS flows without a kernel interface.
//!
//! Hostnames from SOCKS CONNECT (ATYP=3) are resolved by sending a UDP DNS
//! query *through* the tunnel, so names never leak to the local resolver.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use vpn_core::Tunnel;

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

/// The `[socks5]` section of `client.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct Socks5Config {
    /// Local listen address of the proxy.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// DNS resolver queried through the tunnel for hostnames.
    #[serde(default = "default_dns")]
    pub dns: Ipv4Addr,
    /// SOCKS5 username (RFC 1929). When set, clients must authenticate.
    #[serde(default)]
    pub username: Option<String>,
    /// SOCKS5 password.
    #[serde(default)]
    pub password: Option<String>,
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:1080".parse().expect("valid literal")
}

fn default_dns() -> Ipv4Addr {
    Ipv4Addr::new(1, 1, 1, 1)
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            dns: default_dns(),
            username: None,
            password: None,
        }
    }
}

// ---------------------------------------------------------------------------
// runner
// ---------------------------------------------------------------------------

/// Serve SOCKS5 on `cfg.listen`, tunnelling everything through `tunnel`.
///
/// Runs until Ctrl-C or tunnel failure. Closes the tunnel before returning.
pub async fn run(tunnel: Arc<Tunnel>, cfg: Socks5Config) -> Result<()> {
    let local_ip = tunnel.assigned_ip();
    let shared = Arc::new(Registry::new());

    let pump = {
        let tunnel = Arc::clone(&tunnel);
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            loop {
                match tunnel.recv_ip_packet().await {
                    Ok(pkt) => dispatch(&shared, &pkt).await,
                    Err(e) => {
                        tracing::error!(error = %e, "tunnel closed; SOCKS5 proxy stopping");
                        break;
                    }
                }
            }
        })
    };

    let listener = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("bind SOCKS5 listener on {}", cfg.listen))?;
    println!("SOCKS5 proxy listening on {}", cfg.listen);
    println!("  tunnel address: {local_ip}");
    println!(
        "  try: curl --socks5-hostname {} http://example.com",
        cfg.listen
    );

    let res = serve(listener, Arc::clone(&tunnel), shared, cfg).await;
    tunnel.close().await;
    pump.abort();
    res
}

async fn serve(
    listener: TcpListener,
    tunnel: Arc<Tunnel>,
    shared: Arc<Registry>,
    cfg: Socks5Config,
) -> Result<()> {
    let local_ip = tunnel.assigned_ip();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                return Ok(());
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let tunnel = Arc::clone(&tunnel);
                        let shared = Arc::clone(&shared);
                        let cfg = cfg.clone();
                        tokio::spawn(async move {
                            if let Err(e) =
                                socks_session(stream, peer, tunnel, shared, cfg, local_ip).await
                            {
                                tracing::debug!(%peer, error = %e, "SOCKS5 session ended");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// shared registries (tunnel pump → flows / DNS waiters)
// ---------------------------------------------------------------------------

/// Identifies one TCP flow by its 4-tuple as seen by the remote side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    remote: Ipv4Addr,
    rport: u16,
    local: Ipv4Addr,
    lport: u16,
}

struct Registry {
    flows: Mutex<HashMap<FlowKey, mpsc::Sender<Vec<u8>>>>,
    dns: Mutex<HashMap<u16, mpsc::Sender<Vec<u8>>>>,
    dns_sport: Mutex<u16>,
    next_port: AtomicU32,
    /// Resolved A records, keyed by hostname. Saves one tunnel RTT per repeat
    /// lookup: every proxied connection otherwise pays a full DNS round trip
    /// (up to three on loss) before the TCP handshake even starts.
    dns_cache: Mutex<HashMap<String, DnsEntry>>,
}

struct DnsEntry {
    ip: Ipv4Addr,
    expires: Instant,
}

/// TTL clamp for cached answers: never shorter than 5 s, never longer than
/// 10 min, and answers with TTL 0 are not cached at all.
const DNS_CACHE_MIN_TTL: Duration = Duration::from_secs(5);
const DNS_CACHE_MAX_TTL: Duration = Duration::from_secs(600);

impl Registry {
    fn new() -> Self {
        Self {
            flows: Mutex::new(HashMap::new()),
            dns: Mutex::new(HashMap::new()),
            dns_sport: Mutex::new(0),
            next_port: AtomicU32::new(0x4000_0000 | random_u32()),
            dns_cache: Mutex::new(HashMap::new()),
        }
    }

    fn dns_cached(&self, name: &str, now: Instant) -> Option<Ipv4Addr> {
        let mut cache = self.dns_cache.lock().expect("dns cache");
        cache.retain(|_, e| e.expires > now);
        cache.get(name).map(|e| e.ip)
    }

    fn dns_store(&self, name: &str, ip: Ipv4Addr, ttl_secs: u32, now: Instant) {
        if ttl_secs == 0 {
            return;
        }
        let ttl =
            (Duration::from_secs(u64::from(ttl_secs))).clamp(DNS_CACHE_MIN_TTL, DNS_CACHE_MAX_TTL);
        let mut cache = self.dns_cache.lock().expect("dns cache");
        cache.insert(
            name.to_owned(),
            DnsEntry {
                ip,
                expires: now + ttl,
            },
        );
    }

    fn insert_flow(&self, key: FlowKey, tx: mpsc::Sender<Vec<u8>>) {
        self.flows.lock().expect("flows").insert(key, tx);
    }

    fn remove_flow(&self, key: &FlowKey) {
        self.flows.lock().expect("flows").remove(key);
    }

    fn flow(&self, key: &FlowKey) -> Option<mpsc::Sender<Vec<u8>>> {
        self.flows.lock().expect("flows").get(key).cloned()
    }

    /// Pick a free local port for a new outbound flow.
    fn alloc_lport(&self, remote: Ipv4Addr, rport: u16, local: Ipv4Addr) -> u16 {
        let flows = self.flows.lock().expect("flows");
        for _ in 0..200 {
            let n = self.next_port.fetch_add(1, Ordering::Relaxed);
            let port = 10_000 + (n % 55_000) as u16;
            let key = FlowKey {
                remote,
                rport,
                local,
                lport: port,
            };
            if !flows.contains_key(&key) {
                return port;
            }
        }
        10_000
    }

    fn add_dns_waiter(&self, id: u16, tx: mpsc::Sender<Vec<u8>>) {
        self.dns.lock().expect("dns").insert(id, tx);
    }

    fn remove_dns_waiter(&self, id: u16) {
        self.dns.lock().expect("dns").remove(&id);
    }

    fn dns_waiter(&self, id: u16) -> Option<mpsc::Sender<Vec<u8>>> {
        self.dns.lock().expect("dns").get(&id).cloned()
    }

    fn set_dns_sport(&self, port: u16) {
        *self.dns_sport.lock().expect("dns_sport") = port;
    }

    fn dns_port(&self) -> u16 {
        *self.dns_sport.lock().expect("dns_sport")
    }
}

/// Fan one inbound IP packet out to the flow (TCP) or DNS waiter (UDP) it
/// belongs to. Runs on the single tunnel consumer task.
async fn dispatch(shared: &Registry, pkt: &[u8]) {
    let Some(ip) = IpPacket::parse(pkt) else {
        return;
    };
    match ip.proto {
        6 => {
            if ip.l4.len() < 20 {
                return;
            }
            let sport = u16::from_be_bytes([ip.l4[0], ip.l4[1]]);
            let dport = u16::from_be_bytes([ip.l4[2], ip.l4[3]]);
            let key = FlowKey {
                remote: ip.src,
                rport: sport,
                local: ip.dst,
                lport: dport,
            };
            if let Some(tx) = shared.flow(&key) {
                let _ = tx.send(pkt.to_vec()).await;
            }
        }
        17 => {
            if ip.l4.len() < 8 {
                return;
            }
            let dport = u16::from_be_bytes([ip.l4[2], ip.l4[3]]);
            if dport != shared.dns_port() {
                return;
            }
            let payload = &ip.l4[8..];
            if payload.len() < 12 {
                return;
            }
            let id = u16::from_be_bytes([payload[0], payload[1]]);
            if let Some(tx) = shared.dns_waiter(id) {
                let _ = tx.send(payload.to_vec()).await;
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// minimal IPv4/TCP/UDP packet codec
// ---------------------------------------------------------------------------

struct IpPacket<'a> {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    l4: &'a [u8],
}

impl IpPacket<'_> {
    /// Parse the IPv4 header. Non-first fragments are rejected so callers
    /// always see the L4 header.
    fn parse(pkt: &[u8]) -> Option<IpPacket<'_>> {
        if pkt.len() < 20 {
            return None;
        }
        let vhl = pkt[0];
        if vhl >> 4 != 4 {
            return None;
        }
        let ihl = usize::from(vhl & 0x0f) * 4;
        if ihl < 20 || pkt.len() < ihl {
            return None;
        }
        let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
        if frag & 0x1fff != 0 {
            return None; // not the first fragment
        }
        let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]])).min(pkt.len());
        if total < ihl {
            return None;
        }
        Some(IpPacket {
            src: Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
            dst: Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
            proto: pkt[9],
            l4: &pkt[ihl..total],
        })
    }
}

/// Internet checksum (RFC 1071).
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a complete IPv4 packet around a pre-built L4 payload.
fn ip_packet(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4: &[u8]) -> Vec<u8> {
    let mut ip = vec![0u8; 20 + l4.len()];
    ip[0] = 0x45; // v4, IHL 5
    let total = ip.len() as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip[4..6].copy_from_slice(&(random_u32() as u16).to_be_bytes());
    ip[6] = 0x40; // DF: our MSS keeps every packet within the tunnel MTU
    ip[8] = 64; // TTL
    ip[9] = proto;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let csum = checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());
    ip[20..].copy_from_slice(l4);
    ip
}

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;

/// Serialize one TCP segment inside an IPv4 packet.
#[allow(clippy::too_many_arguments)]
fn tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    opts: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + opts.len() + payload.len());
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push((((20 + opts.len()) / 4) as u8) << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&window.to_be_bytes());
    tcp.extend_from_slice(&[0, 0]); // checksum placeholder
    tcp.extend_from_slice(&[0, 0]); // urgent pointer
    tcp.extend_from_slice(opts);
    tcp.extend_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12 + tcp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&tcp);
    let csum = checksum(&pseudo);
    tcp[16..18].copy_from_slice(&csum.to_be_bytes());

    ip_packet(src, dst, 6, &tcp)
}

/// Serialize a UDP datagram inside an IPv4 packet (checksum computed, since
/// conntrack on the server validates NATed flows).
fn udp_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum placeholder
    udp.extend_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&udp);
    let csum = checksum(&pseudo);
    udp[6..8].copy_from_slice(&csum.to_be_bytes());

    ip_packet(src, dst, 17, &udp)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opt {
    Mss(u16),
    Wscale(u8),
}

fn parse_tcp_opts(data: &[u8]) -> Vec<Opt> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            0 | 1 => i += 1,
            kind => {
                let len = data.get(i + 1).copied().unwrap_or(0) as usize;
                if len < 2 || i + len > data.len() {
                    break;
                }
                match (kind, len) {
                    (2, 4) => {
                        out.push(Opt::Mss(u16::from_be_bytes([data[i + 2], data[i + 3]])));
                    }
                    (3, 3) => out.push(Opt::Wscale(data[i + 2])),
                    _ => {}
                }
                i += len;
            }
        }
    }
    out
}

struct TcpHdr<'a> {
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    opts: Vec<Opt>,
    payload: &'a [u8],
}

impl TcpHdr<'_> {
    fn parse(l4: &[u8]) -> Option<TcpHdr<'_>> {
        if l4.len() < 20 {
            return None;
        }
        let off = usize::from(l4[12] >> 4) * 4;
        if off < 20 || off > l4.len() {
            return None;
        }
        Some(TcpHdr {
            seq: u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]),
            ack: u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]),
            flags: l4[13],
            window: u16::from_be_bytes([l4[14], l4[15]]),
            opts: parse_tcp_opts(&l4[20..off]),
            payload: &l4[off..],
        })
    }
}

/// Sequence-space comparison with wrap-around (RFC 1982).
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

/// Tiny xorshift PRNG; not cryptographic, only for ISNs, ports and DNS ids.
fn random_u32() -> u32 {
    static STATE: AtomicU32 = AtomicU32::new(0);
    let mut x = STATE.load(Ordering::Relaxed);
    if x == 0 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() ^ (d.as_secs() as u32))
            .unwrap_or(0x9e37_79b9);
        x = nanos | 1;
    }
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    STATE.store(x, Ordering::Relaxed);
    x
}

// ---------------------------------------------------------------------------
// TCP over the tunnel: one agent task per connection
// ---------------------------------------------------------------------------

const IP_TCP_OVERHEAD: usize = 40;
const RCV_WND: u32 = 65535;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const INITIAL_RTO: Duration = Duration::from_millis(1000);
const MAX_RTO: Duration = Duration::from_millis(10_000);
const SYN_RETRIES: u32 = 5;
const REXMIT_LIMIT: u32 = 8;

enum State {
    SynSent,
    Established,
    FinSent,
    Closed,
}

/// Inbound command from the SOCKS session.
enum Cmd {
    Data(Vec<u8>),
    Fin,
}

/// Outbound chunk delivered to the SOCKS session.
enum Chunk {
    Data(Vec<u8>),
    Eof,
    Reset,
}

#[derive(Clone)]
struct Unacked {
    seq: u32,
    data: Vec<u8>,
    is_fin: bool,
    sent: Instant,
}

/// Why a connection failed to establish.
#[derive(Debug)]
enum ConnectError {
    Timeout,
    Reset,
}

/// Handle to one tunneled TCP connection, owned by the SOCKS session.
struct TcpConn {
    cmd_tx: mpsc::Sender<Cmd>,
    data_rx: mpsc::Receiver<Chunk>,
}

impl TcpConn {
    /// Open a TCP connection to `remote:remote_port` through the tunnel.
    async fn open(
        tunnel: &Arc<Tunnel>,
        shared: &Arc<Registry>,
        local_ip: Ipv4Addr,
        remote: Ipv4Addr,
        remote_port: u16,
    ) -> Result<TcpConn, ConnectError> {
        let lport = shared.alloc_lport(remote, remote_port, local_ip);
        let key = FlowKey {
            remote,
            rport: remote_port,
            local: local_ip,
            lport,
        };
        let (seg_tx, seg_rx) = mpsc::channel(64);
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let (data_tx, data_rx) = mpsc::channel(64);
        let (ready_tx, ready_rx) = oneshot::channel();
        shared.insert_flow(key, seg_tx);

        let mss = (tunnel.mtu().saturating_sub(IP_TCP_OVERHEAD)) as u16;
        let agent = TcpAgent {
            key,
            state: State::SynSent,
            isn: random_u32(),
            snd_una: 0,
            snd_next: 0,
            rcv_next: 0,
            snd_wnd: RCV_WND,
            peer_mss: mss,
            wscale: 0,
            unacked: VecDeque::new(),
            pending: VecDeque::new(),
            want_fin: false,
            fin_sent: false,
            peer_fin: false,
            dup_acks: 0,
            srtt: None,
            rto: INITIAL_RTO,
            retx_count: 0,
            syn_tries: 0,
            last_activity: Instant::now(),
            last_sent: Instant::now(),
        };
        tokio::spawn(agent.run(
            Arc::clone(tunnel),
            Arc::clone(shared),
            seg_rx,
            cmd_rx,
            data_tx,
            ready_tx,
        ));

        match tokio::time::timeout(CONNECT_TIMEOUT, ready_rx).await {
            Ok(Ok(Ok(()))) => Ok(TcpConn { cmd_tx, data_rx }),
            Ok(Ok(Err(_))) => Err(ConnectError::Reset),
            Ok(Err(_)) | Err(_) => Err(ConnectError::Timeout),
        }
    }

    /// Queue bytes for transmission (backpressured by the agent's window).
    async fn send(&self, data: &[u8]) -> io::Result<()> {
        self.cmd_tx
            .send(Cmd::Data(data.to_vec()))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "flow closed"))
    }

    /// Half-close: all queued bytes, then FIN.
    async fn fin(&self) {
        let _ = self.cmd_tx.send(Cmd::Fin).await;
    }

    /// Next delivered chunk; `None` when the flow is gone.
    async fn recv(&mut self) -> Option<Chunk> {
        self.data_rx.recv().await
    }
}

struct TcpAgent {
    key: FlowKey,
    state: State,
    isn: u32,
    snd_una: u32,
    snd_next: u32,
    rcv_next: u32,
    snd_wnd: u32,
    peer_mss: u16,
    wscale: u8,
    unacked: VecDeque<Unacked>,
    pending: VecDeque<u8>,
    want_fin: bool,
    fin_sent: bool,
    peer_fin: bool,
    dup_acks: u8,
    srtt: Option<Duration>,
    rto: Duration,
    retx_count: u32,
    syn_tries: u32,
    last_activity: Instant,
    last_sent: Instant,
}

impl TcpAgent {
    #[allow(clippy::too_many_arguments)]
    async fn run(
        mut self,
        tunnel: Arc<Tunnel>,
        shared: Arc<Registry>,
        mut seg_rx: mpsc::Receiver<Vec<u8>>,
        mut cmd_rx: mpsc::Receiver<Cmd>,
        data_tx: mpsc::Sender<Chunk>,
        ready: oneshot::Sender<Result<(), String>>,
    ) {
        let mut ready = Some(ready);
        self.send_syn(&tunnel).await;
        let mut ticker = tokio::time::interval(Duration::from_millis(100));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut cmd_open = true;

        loop {
            tokio::select! {
                seg = seg_rx.recv() => {
                    match seg {
                        Some(pkt) => {
                            if !self
                                .on_segment(&tunnel, &shared, &data_tx, &pkt, &mut ready)
                                .await
                            {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                cmd = cmd_rx.recv(), if cmd_open => {
                    match cmd {
                        Some(Cmd::Data(d)) => {
                            self.pending.extend(d);
                            self.pump_send(&tunnel).await;
                        }
                        Some(Cmd::Fin) => {
                            self.want_fin = true;
                            self.pump_send(&tunnel).await;
                        }
                        None => {
                            cmd_open = false;
                            self.want_fin = true;
                            self.pump_send(&tunnel).await;
                        }
                    }
                }
                _ = ticker.tick() => {
                    if !self.on_tick(&tunnel, &data_tx, &mut ready).await {
                        break;
                    }
                }
            }
            if matches!(self.state, State::Closed) {
                break;
            }
        }

        // Abrupt teardown after establishment: tell the peer we are gone.
        if !matches!(self.state, State::Closed) {
            self.send(
                &tunnel,
                self.snd_next,
                self.rcv_next,
                TCP_FLAG_RST | TCP_FLAG_ACK,
                &[],
                &[],
            )
            .await;
        }
        shared.remove_flow(&self.key);
        if let Some(tx) = ready.take() {
            let _ = tx.send(Err("connection aborted".to_string()));
        }
    }

    fn seq_opts(&self) -> Vec<u8> {
        let mss = self.peer_mss.to_be_bytes();
        vec![2, 4, mss[0], mss[1]]
    }

    async fn send_syn(&mut self, tunnel: &Arc<Tunnel>) {
        let opts = self.seq_opts();
        self.send(tunnel, self.isn, 0, TCP_FLAG_SYN, &opts, &[])
            .await;
        self.syn_tries += 1;
    }

    /// Transmit one segment and record bookkeeping.
    #[allow(clippy::too_many_arguments)]
    async fn send(
        &mut self,
        tunnel: &Arc<Tunnel>,
        seq: u32,
        ack: u32,
        flags: u8,
        opts: &[u8],
        payload: &[u8],
    ) {
        let pkt = tcp_packet(
            self.key.local,
            self.key.remote,
            self.key.lport,
            self.key.rport,
            seq,
            ack,
            flags,
            RCV_WND as u16,
            opts,
            payload,
        );
        self.last_sent = Instant::now();
        self.last_activity = self.last_sent;
        if let Err(e) = tunnel.send_ip_packet(&pkt).await {
            tracing::debug!(error = %e, "tunnel send failed");
        }
    }

    async fn resend(&mut self, tunnel: &Arc<Tunnel>, seg: &Unacked) {
        let flags = if seg.is_fin {
            TCP_FLAG_FIN | TCP_FLAG_ACK
        } else {
            TCP_FLAG_PSH | TCP_FLAG_ACK
        };
        self.send(tunnel, seg.seq, self.rcv_next, flags, &[], &seg.data)
            .await;
    }

    /// Feed outbound bytes into the sliding window.
    async fn pump_send(&mut self, tunnel: &Arc<Tunnel>) {
        let window_cap = self.snd_wnd.min(self.peer_mss as u32 * 24);
        loop {
            if self.want_fin && self.pending.is_empty() && !self.fin_sent && self.unacked.is_empty()
            {
                let seq = self.snd_next;
                self.snd_next = seq.wrapping_add(1);
                self.unacked.push_back(Unacked {
                    seq,
                    data: Vec::new(),
                    is_fin: true,
                    sent: Instant::now(),
                });
                self.fin_sent = true;
                self.state = State::FinSent;
                self.send(
                    tunnel,
                    seq,
                    self.rcv_next,
                    TCP_FLAG_FIN | TCP_FLAG_ACK,
                    &[],
                    &[],
                )
                .await;
                return;
            }
            if self.pending.is_empty() {
                return;
            }
            if self.snd_wnd == 0 || window_cap == 0 {
                return; // wait for a window update / probe
            }
            let inflight = self.snd_next.wrapping_sub(self.snd_una);
            if inflight >= window_cap {
                return;
            }
            let room = usize::try_from(window_cap - inflight).unwrap_or(0);
            let take = room.min(usize::from(self.peer_mss)).min(self.pending.len());
            if take == 0 {
                return;
            }
            let data: Vec<u8> = self.pending.drain(..take).collect();
            let seq = self.snd_next;
            self.snd_next = seq.wrapping_add(take as u32);
            self.send(
                tunnel,
                seq,
                self.rcv_next,
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                &[],
                &data,
            )
            .await;
            self.unacked.push_back(Unacked {
                seq,
                data,
                is_fin: false,
                sent: Instant::now(),
            });
        }
    }

    /// Handle one inbound TCP segment. Returns `false` when the flow is done.
    async fn on_segment(
        &mut self,
        tunnel: &Arc<Tunnel>,
        shared: &Arc<Registry>,
        data_tx: &mpsc::Sender<Chunk>,
        pkt: &[u8],
        ready: &mut Option<oneshot::Sender<Result<(), String>>>,
    ) -> bool {
        let Some(ip) = IpPacket::parse(pkt) else {
            return true;
        };
        if ip.proto != 6 {
            return true;
        }
        let Some(hdr) = TcpHdr::parse(ip.l4) else {
            return true;
        };
        self.last_activity = Instant::now();

        if hdr.flags & TCP_FLAG_RST != 0 {
            tracing::debug!(remote = %self.key.remote, "connection reset by peer");
            self.finish_failure(data_tx, ready, Chunk::Reset, "reset by peer")
                .await;
            return false;
        }

        match self.state {
            State::SynSent => self.on_syn_sent(tunnel, &hdr, ready).await,
            State::Established | State::FinSent => self.on_data(tunnel, data_tx, &hdr).await,
            State::Closed => {
                let _ = shared;
                false
            }
        }
    }

    async fn on_syn_sent(
        &mut self,
        tunnel: &Arc<Tunnel>,
        hdr: &TcpHdr<'_>,
        ready: &mut Option<oneshot::Sender<Result<(), String>>>,
    ) -> bool {
        if hdr.flags & TCP_FLAG_SYN != 0
            && hdr.flags & TCP_FLAG_ACK != 0
            && hdr.ack == self.isn.wrapping_add(1)
        {
            self.rcv_next = hdr.seq.wrapping_add(1);
            self.snd_una = self.isn.wrapping_add(1);
            self.snd_next = self.snd_una;
            self.rto = INITIAL_RTO;
            self.retx_count = 0;
            self.syn_tries = 0;
            for opt in &hdr.opts {
                match *opt {
                    Opt::Mss(m) if m >= 216 => self.peer_mss = self.peer_mss.min(m),
                    Opt::Wscale(w) => self.wscale = w.min(14),
                    _ => {}
                }
            }
            self.snd_wnd = u32::from(hdr.window) << self.wscale;
            self.state = State::Established;
            // Handshake final ACK, then release queued application data.
            self.send(tunnel, self.snd_next, self.rcv_next, TCP_FLAG_ACK, &[], &[])
                .await;
            if let Some(tx) = ready.take() {
                let _ = tx.send(Ok(()));
            }
            self.pump_send(tunnel).await;
        } else if hdr.flags & TCP_FLAG_ACK != 0 && hdr.ack == self.isn.wrapping_add(1) {
            // Retransmitted SYN-ACK: our ACK may have been lost; re-ACK.
            self.send(
                tunnel,
                self.snd_next,
                hdr.seq.wrapping_add(1),
                TCP_FLAG_ACK,
                &[],
                &[],
            )
            .await;
        }
        !matches!(self.state, State::Closed)
    }

    async fn on_data(
        &mut self,
        tunnel: &Arc<Tunnel>,
        data_tx: &mpsc::Sender<Chunk>,
        hdr: &TcpHdr<'_>,
    ) -> bool {
        if hdr.flags & TCP_FLAG_ACK != 0 {
            // Window update (scaled by the peer's wscale factor).
            self.snd_wnd = u32::from(hdr.window) << self.wscale;
        }

        if hdr.flags & TCP_FLAG_ACK != 0 {
            let ack = hdr.ack;
            if seq_lt(self.snd_una, ack) && seq_le(ack, self.snd_next) {
                // Sample RTT from the head segment, then reset the RTO.
                if let Some(front) = self.unacked.front() {
                    let rtt = front.sent.elapsed();
                    self.srtt = Some(match self.srtt {
                        Some(s) => s.mul_f64(0.7) + rtt.mul_f64(0.3),
                        None => rtt,
                    });
                    self.rto = (self.srtt.unwrap_or(INITIAL_RTO) * 2)
                        .max(Duration::from_millis(300))
                        .min(MAX_RTO);
                }
                self.snd_una = ack;
                self.dup_acks = 0;
                self.retx_count = 0;
                while let Some(front) = self.unacked.front() {
                    let end = front
                        .seq
                        .wrapping_add(front.data.len() as u32)
                        .wrapping_add(u32::from(front.is_fin));
                    if seq_le(end, ack) {
                        self.unacked.pop_front();
                    } else {
                        break;
                    }
                }
                // Freed window / queued FIN can now go out.
                self.pump_send(tunnel).await;
            } else if ack == self.snd_una && hdr.payload.is_empty() {
                self.dup_acks = self.dup_acks.saturating_add(1);
                if self.dup_acks == 3 {
                    // Fast retransmit of the oldest unacknowledged segment.
                    if let Some(front) = self.unacked.front().cloned() {
                        self.resend(tunnel, &front).await;
                        if let Some(f) = self.unacked.front_mut() {
                            f.sent = Instant::now();
                        }
                    }
                }
            }
        }

        let payload = hdr.payload;
        let seg_end = hdr.seq.wrapping_add(payload.len() as u32);
        if hdr.seq == self.rcv_next {
            if !payload.is_empty() {
                self.rcv_next = seg_end;
                if data_tx.send(Chunk::Data(payload.to_vec())).await.is_err() {
                    return false;
                }
                self.send(tunnel, self.snd_next, self.rcv_next, TCP_FLAG_ACK, &[], &[])
                    .await;
            }
            if hdr.flags & TCP_FLAG_FIN != 0 {
                self.rcv_next = seg_end.wrapping_add(1);
                self.peer_fin = true;
                if data_tx.send(Chunk::Eof).await.is_err() {
                    return false;
                }
                self.send(tunnel, self.snd_next, self.rcv_next, TCP_FLAG_ACK, &[], &[])
                    .await;
            }
        } else if seq_lt(self.rcv_next, hdr.seq)
            || !payload.is_empty()
            || hdr.flags & TCP_FLAG_FIN != 0
        {
            // Out-of-order or retransmitted data: we do not buffer ahead;
            // a duplicate ACK with the current left edge triggers retransmit.
            self.send(tunnel, self.snd_next, self.rcv_next, TCP_FLAG_ACK, &[], &[])
                .await;
        }

        // Fully closed when both directions are done.
        if self.peer_fin && !self.unacked.iter().any(|s| s.is_fin) && self.want_fin {
            self.state = State::Closed;
            return false;
        }
        true
    }

    /// Periodic housekeeping. Returns `false` when the flow is done.
    async fn on_tick(
        &mut self,
        tunnel: &Arc<Tunnel>,
        data_tx: &mpsc::Sender<Chunk>,
        ready: &mut Option<oneshot::Sender<Result<(), String>>>,
    ) -> bool {
        let now = Instant::now();

        if matches!(self.state, State::SynSent) {
            if self.syn_tries > SYN_RETRIES {
                self.finish_failure(data_tx, ready, Chunk::Reset, "no SYN-ACK")
                    .await;
                return false;
            }
            if now - self.last_sent >= self.rto {
                self.rto = (self.rto * 2).min(MAX_RTO);
                self.send_syn(tunnel).await;
            }
            return true;
        }

        // Retransmit every segment whose RTO elapsed.
        let rto = self.rto;
        let stale: Vec<usize> = self
            .unacked
            .iter()
            .enumerate()
            .filter(|(_, s)| now - s.sent >= rto)
            .map(|(i, _)| i)
            .collect();
        let resent = !stale.is_empty();
        for i in stale {
            let seg = self.unacked[i].clone();
            self.resend(tunnel, &seg).await;
            if let Some(s) = self.unacked.get_mut(i) {
                s.sent = Instant::now();
            }
        }
        if resent {
            self.retx_count += 1;
            self.rto = (self.rto * 2).min(MAX_RTO);
            if self.retx_count > REXMIT_LIMIT {
                self.finish_failure(data_tx, ready, Chunk::Reset, "too many retransmits")
                    .await;
                return false;
            }
        }

        // Zero-window probe: one byte keeps the window negotiation alive.
        if self.snd_wnd == 0
            && self.unacked.is_empty()
            && !self.pending.is_empty()
            && now - self.last_sent >= rto
        {
            let byte = self.pending.pop_front().expect("pending non-empty");
            let seq = self.snd_next;
            self.snd_next = seq.wrapping_add(1);
            self.send(
                tunnel,
                seq,
                self.rcv_next,
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                &[],
                &[byte],
            )
            .await;
            self.unacked.push_back(Unacked {
                seq,
                data: vec![],
                is_fin: false,
                sent: Instant::now(),
            });
        }

        if now - self.last_activity >= IDLE_TIMEOUT {
            tracing::debug!(remote = %self.key.remote, "flow idle timeout");
            self.finish_failure(data_tx, ready, Chunk::Reset, "idle timeout")
                .await;
            return false;
        }
        true
    }

    /// Mark the flow closed, notify the session, and stop.
    async fn finish_failure(
        &mut self,
        data_tx: &mpsc::Sender<Chunk>,
        ready: &mut Option<oneshot::Sender<Result<(), String>>>,
        chunk: Chunk,
        reason: &str,
    ) {
        self.state = State::Closed;
        if let Some(tx) = ready.take() {
            let _ = tx.send(Err(reason.to_string()));
        }
        let _ = data_tx.send(chunk).await;
    }
}

// ---------------------------------------------------------------------------
// DNS over the tunnel
// ---------------------------------------------------------------------------

struct DnsClient {
    tunnel: Arc<Tunnel>,
    shared: Arc<Registry>,
    src: Ipv4Addr,
    server: Ipv4Addr,
    sport: u16,
}

impl DnsClient {
    fn new(tunnel: Arc<Tunnel>, shared: Arc<Registry>, src: Ipv4Addr, server: Ipv4Addr) -> Self {
        let sport = 20_000 + (random_u32() % 40_000) as u16;
        shared.set_dns_sport(sport);
        Self {
            tunnel,
            shared,
            src,
            server,
            sport,
        }
    }

    /// Resolve a hostname through the tunnel. `None` on any failure.
    async fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        let now = Instant::now();
        if let Some(ip) = self.shared.dns_cached(name, now) {
            tracing::debug!(name, %ip, "dns cache hit");
            return Some(ip);
        }
        for _ in 0..2 {
            let id = random_u32() as u16;
            let (tx, mut rx) = mpsc::channel(1);
            self.shared.add_dns_waiter(id, tx);
            let query = dns_query(id, name);
            let pkt = udp_packet(self.src, self.server, self.sport, 53, &query);
            match self.tunnel.send_ip_packet(&pkt).await {
                Ok(()) => {}
                Err(e) => {
                    tracing::debug!(error = %e, "dns send failed");
                    self.shared.remove_dns_waiter(id);
                    return None;
                }
            }
            match tokio::time::timeout(Duration::from_secs(4), rx.recv()).await {
                Ok(Some(reply)) => {
                    self.shared.remove_dns_waiter(id);
                    if let Some((ip, ttl)) = parse_a_reply(&reply, id) {
                        self.shared.dns_store(name, ip, ttl, now);
                        return Some(ip);
                    }
                }
                _ => {
                    self.shared.remove_dns_waiter(id);
                }
            }
        }
        tracing::debug!(name, "dns lookup failed");
        None
    }
}

/// Encode a DNS A query.
fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(23 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // RD=1
    q.extend_from_slice(&[0, 1]); // QDCOUNT=1
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ANCOUNT, NSCOUNT, ARCOUNT = 0
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0, 1]); // QTYPE=A
    q.extend_from_slice(&[0, 1]); // QCLASS=IN
    q
}

/// Skip a (possibly compressed) domain name starting at `off`.
fn skip_name(msg: &[u8], mut off: usize) -> Option<usize> {
    let mut jumps = 0;
    loop {
        let len = *msg.get(off)?;
        if len & 0xc0 == 0xc0 {
            if jumps >= 32 {
                return None;
            }
            return Some(off + 2);
        }
        if len == 0 {
            return Some(off + 1);
        }
        off += 1 + usize::from(len);
        jumps += 1;
        if jumps > 32 || off >= msg.len() {
            return None;
        }
    }
}

/// Extract the first A record of a DNS reply, with its TTL.
fn parse_a_reply(reply: &[u8], id: u16) -> Option<(Ipv4Addr, u32)> {
    if reply.len() < 12 {
        return None;
    }
    if u16::from_be_bytes([reply[0], reply[1]]) != id {
        return None;
    }
    if reply[2] & 0x80 == 0 {
        return None; // not a response
    }
    if reply[3] & 0x0f != 0 {
        return None; // non-zero RCODE
    }
    let answers = u16::from_be_bytes([reply[6], reply[7]]);
    let mut off = skip_name(reply, 12)? + 4; // question name + QTYPE/QCLASS
    for _ in 0..answers {
        off = skip_name(reply, off)?;
        if off + 10 > reply.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([reply[off], reply[off + 1]]);
        let rdlen = u16::from_be_bytes([reply[off + 8], reply[off + 9]]) as usize;
        let rdata = off + 10;
        if rtype == 1 && rdlen == 4 && rdata + 4 <= reply.len() {
            let ttl = u32::from_be_bytes([
                reply[off + 4],
                reply[off + 5],
                reply[off + 6],
                reply[off + 7],
            ]);
            return Some((
                Ipv4Addr::new(
                    reply[rdata],
                    reply[rdata + 1],
                    reply[rdata + 2],
                    reply[rdata + 3],
                ),
                ttl,
            ));
        }
        off = rdata + rdlen;
    }
    None
}

// ---------------------------------------------------------------------------
// SOCKS5 protocol (RFC 1928 + RFC 1929)
// ---------------------------------------------------------------------------

const SOCKS_VER: u8 = 5;

async fn socks_session(
    mut stream: TcpStream,
    peer: SocketAddr,
    tunnel: Arc<Tunnel>,
    shared: Arc<Registry>,
    cfg: Socks5Config,
    local_ip: Ipv4Addr,
) -> Result<()> {
    negotiate_auth(&mut stream, &cfg).await?;

    // CONNECT request
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != SOCKS_VER {
        anyhow::bail!("not a SOCKS5 request");
    }
    if req[1] != 1 {
        // 2 = BIND, 3 = UDP ASSOCIATE: unsupported.
        write_reply(&mut stream, 0x07).await;
        anyhow::bail!("only the CONNECT command is supported");
    }
    let target = match req[3] {
        1 => {
            let mut o = [0u8; 6];
            stream.read_exact(&mut o).await?;
            Target::Addr(
                Ipv4Addr::new(o[0], o[1], o[2], o[3]),
                u16::from_be_bytes([o[4], o[5]]),
            )
        }
        3 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            if l[0] == 0 || usize::from(l[0]) > 253 {
                write_reply(&mut stream, 0x01).await;
                anyhow::bail!("bad hostname length");
            }
            let mut name = vec![0u8; usize::from(l[0])];
            stream.read_exact(&mut name).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            match std::str::from_utf8(&name)
                .ok()
                .filter(|n| valid_hostname(n))
                .map(str::to_owned)
            {
                Some(n) => Target::Name(n, u16::from_be_bytes(port)),
                None => {
                    write_reply(&mut stream, 0x01).await;
                    anyhow::bail!("invalid hostname");
                }
            }
        }
        _ => {
            // ATYP=4 (IPv6) and anything else.
            write_reply(&mut stream, 0x08).await;
            anyhow::bail!("only IPv4 and hostname targets are supported");
        }
    };

    let (host, port) = match &target {
        Target::Name(n, p) => (n.clone(), *p),
        Target::Addr(a, p) => (a.to_string(), *p),
    };

    // Refuse loopback/tunnel-subnet targets: they would loop or reach the
    // server's internal addresses instead of the internet.
    if let Target::Addr(a, _) = &target
        && (a.is_loopback() || a.is_broadcast() || a.is_unspecified() || tunnel_subnet_contains(a))
    {
        write_reply(&mut stream, 0x02).await;
        anyhow::bail!("refusing connection to {a}");
    }

    let ip = match target {
        Target::Addr(a, _) => a,
        Target::Name(name, _) => {
            match DnsClient::new(Arc::clone(&tunnel), Arc::clone(&shared), local_ip, cfg.dns)
                .resolve(&name)
                .await
            {
                Some(ip) => ip,
                None => {
                    write_reply(&mut stream, 0x04).await;
                    anyhow::bail!("cannot resolve {name} through the tunnel");
                }
            }
        }
    };
    if ip.is_loopback() || tunnel_subnet_contains(&ip) {
        write_reply(&mut stream, 0x02).await;
        anyhow::bail!("refusing connection to {ip}");
    }

    tracing::debug!(%peer, %host, port, "SOCKS5 CONNECT");
    let conn = match TcpConn::open(&tunnel, &shared, local_ip, ip, port).await {
        Ok(c) => c,
        Err(e) => {
            let code = match e {
                ConnectError::Timeout => 0x03, // network unreachable
                ConnectError::Reset => 0x05,
            };
            write_reply(&mut stream, code).await;
            anyhow::bail!("connect {host}:{port} failed: {e:?}");
        }
    };

    write_reply(&mut stream, 0x00).await;
    pipe(stream, conn).await
}

enum Target {
    Name(String, u16),
    Addr(Ipv4Addr, u16),
}

fn valid_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// `10.66.0.0/24` — the server's pool (see `vpn-core::pool`). Connections
/// into the tunnel's own subnet are refused rather than looped.
fn tunnel_subnet_contains(a: &Ipv4Addr) -> bool {
    let o = a.octets();
    o[0] == 10 && o[1] == 66 && o[2] == 0
}

async fn negotiate_auth(stream: &mut TcpStream, cfg: &Socks5Config) -> Result<()> {
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != SOCKS_VER {
        anyhow::bail!("not a SOCKS5 greeting");
    }
    let n = usize::from(hdr[1]);
    if n == 0 || n > 255 {
        anyhow::bail!("bad method count");
    }
    let mut methods = vec![0u8; n];
    stream.read_exact(&mut methods).await?;

    let want_auth = cfg.username.is_some();
    let chosen: u8 = if want_auth {
        if methods.contains(&0x02) { 0x02 } else { 0xff }
    } else if methods.contains(&0x00) {
        0x00
    } else {
        0xff
    };
    stream.write_all(&[SOCKS_VER, chosen]).await?;
    if chosen == 0xff {
        anyhow::bail!("no acceptable auth method");
    }

    if chosen == 0x02 {
        let mut sub = [0u8; 2]; // ver, ulen
        stream.read_exact(&mut sub).await?;
        let mut user = vec![0u8; usize::from(sub[1])];
        stream.read_exact(&mut user).await?;
        let mut plen = [0u8; 1];
        stream.read_exact(&mut plen).await?;
        let mut pass = vec![0u8; usize::from(plen[0])];
        stream.read_exact(&mut pass).await?;
        let ok = cfg.username.as_deref() == Some(std::str::from_utf8(&user).unwrap_or(""))
            && cfg.password.as_deref() == Some(std::str::from_utf8(&pass).unwrap_or(""));
        stream.write_all(&[0x01, u8::from(!ok)]).await?;
        if !ok {
            anyhow::bail!("SOCKS5 authentication failed");
        }
    }
    Ok(())
}

/// SOCKS5 reply: status only, with a zeroed IPv4 bound address.
///
/// Write errors are swallowed: a client that vanished needs no reply.
async fn write_reply(stream: &mut TcpStream, status: u8) {
    let _ = stream
        .write_all(&[SOCKS_VER, status, 0, 1, 0, 0, 0, 0, 0, 0])
        .await;
}

/// Relay bytes between the SOCKS client and the tunneled flow.
async fn pipe(stream: TcpStream, mut conn: TcpConn) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut buf = vec![0u8; 16 * 1024];
    let mut client_closed = false;
    loop {
        tokio::select! {
            n = rd.read(&mut buf), if !client_closed => {
                match n {
                    Ok(0) => {
                        client_closed = true;
                        conn.fin().await;
                    }
                    Ok(n) => {
                        if let Err(e) = conn.send(&buf[..n]).await {
                            break Err(anyhow::Error::new(e).context("tunnel write failed"));
                        }
                    }
                    Err(e) => break Err(anyhow::Error::new(e).context("client read failed")),
                }
            }
            chunk = conn.recv() => {
                match chunk {
                    Some(Chunk::Data(d)) => {
                        if let Err(e) = wr.write_all(&d).await {
                            break Err(anyhow::Error::new(e).context("client write failed"));
                        }
                    }
                    Some(Chunk::Eof) | None => {
                        // Server finished: half-close the client socket and
                        // stop relaying (any pending client data is lost, as
                        // with a normal connection teardown).
                        let _ = wr.shutdown().await;
                        break Ok(());
                    }
                    Some(Chunk::Reset) => {
                        break Err(anyhow::anyhow!("connection reset through tunnel"));
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_a_correct_header_verifies_to_zero() {
        let mut h = vec![0u8; 20];
        h[0] = 0x45;
        h[2..4].copy_from_slice(&20u16.to_be_bytes());
        h[9] = 6;
        h[12..16].copy_from_slice(&[10, 0, 0, 1]);
        h[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let c = checksum(&h);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        assert_eq!(checksum(&h), 0);
    }

    #[test]
    fn sequence_ordering_handles_wraparound() {
        assert!(seq_lt(1, 2));
        assert!(seq_le(2, 2));
        assert!(!seq_lt(2, 1));
        // near the 32-bit wrap
        let big = u32::MAX - 2;
        assert!(seq_lt(big, 0));
        assert!(seq_lt(big, 1));
        assert!(!seq_lt(1, big));
    }

    #[test]
    fn tcp_packet_roundtrips_through_the_parser() {
        let src = Ipv4Addr::new(10, 66, 0, 2);
        let dst = Ipv4Addr::new(93, 184, 216, 34);
        let pkt = tcp_packet(
            src,
            dst,
            40001,
            443,
            1234,
            5678,
            TCP_FLAG_PSH | TCP_FLAG_ACK,
            32100,
            &[],
            b"hello",
        );
        let ip = IpPacket::parse(&pkt).expect("parse ip");
        assert_eq!(ip.src, src);
        assert_eq!(ip.dst, dst);
        assert_eq!(ip.proto, 6);
        let tcp = TcpHdr::parse(ip.l4).expect("parse tcp");
        assert_eq!(tcp.seq, 1234);
        assert_eq!(tcp.ack, 5678);
        assert_eq!(tcp.window, 32100);
        assert_eq!(tcp.payload, b"hello");
        assert!(tcp.flags & TCP_FLAG_PSH != 0);
        assert!(tcp.flags & TCP_FLAG_ACK != 0);
    }

    #[test]
    fn tcp_options_are_parsed() {
        let mut opts = vec![2, 4, 0x04, 0xb8]; // MSS 1211
        opts.extend_from_slice(&[1, 1]); // NOPs
        opts.extend_from_slice(&[3, 3, 7]); // wscale 7
        let parsed = parse_tcp_opts(&opts);
        assert_eq!(parsed, vec![Opt::Mss(1208), Opt::Wscale(7)]);
    }

    #[test]
    fn dns_query_and_reply_parse_roundtrip() {
        let q = dns_query(0x1234, "example.com");
        assert_eq!(&q[0..2], &0x1234u16.to_be_bytes());
        // Full 12-byte header: ID, flags, QDCOUNT=1, then zeroed AN/NS/AR counts.
        assert_eq!(q[2], 0x01); // RD=1
        assert_eq!(&q[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        // A reply with a compressed question name and one A record.
        let mut r = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        r.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        r.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
        r.extend_from_slice(&[0, 1, 0, 1]); // QTYPE/QCLASS
        r.extend_from_slice(&[0xc0, 0x0c]); // pointer to the question name
        r.extend_from_slice(&[0, 1, 0, 1]); // TYPE=A CLASS=IN
        r.extend_from_slice(&[0, 0, 0, 60]); // TTL
        r.extend_from_slice(&[0, 4]); // RDLENGTH
        r.extend_from_slice(&[93, 184, 216, 34]);
        assert_eq!(
            parse_a_reply(&r, 0x1234),
            Some((Ipv4Addr::new(93, 184, 216, 34), 60))
        );
        // wrong id
        assert_eq!(parse_a_reply(&r, 0x9999), None);
    }

    #[test]
    fn hostnames_and_subnets_are_screened() {
        assert!(valid_hostname("example.com"));
        assert!(valid_hostname("a-b.c.d"));
        assert!(!valid_hostname("bad hostname"));
        assert!(!valid_hostname("-leading.example"));
        assert!(tunnel_subnet_contains(&Ipv4Addr::new(10, 66, 0, 7)));
        assert!(!tunnel_subnet_contains(&Ipv4Addr::new(10, 67, 0, 7)));
    }
}
