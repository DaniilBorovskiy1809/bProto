//! The bProto client.
//!
//! This is what a device runs: it performs the handshake, then moves IP packets
//! between the embedder (a TUN device, a `VpnService` fd) and the server. It is
//! deliberately small — every byte of protocol logic lives in
//! [`vpn_core::Endpoint`] and every byte of socket handling in `vpn-rt`, so this
//! crate is only the handshake plus the glue.
//!
//! The same type backs the Linux CLI, the C-ABI library used by the mobile apps,
//! and any future desktop client.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use vpn_core::config::TunnelConfig;
use vpn_core::handshake;
use vpn_core::{Error, Result, MAX_DATAGRAM};
use vpn_rt::{Clock, LiveSession, udp};

/// Retransmit interval while the handshake is outstanding.
const HANDSHAKE_RETRY: Duration = Duration::from_millis(500);
/// Depth of the inbound queue; enough to smooth a scheduling hiccup.
const INBOUND_DEPTH: usize = 2048;

/// Health snapshot for status lines and GUIs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TunnelStats {
    /// Smoothed RTT in microseconds. `0` until the first ACK arrives — it is
    /// **not** a measurement before then.
    pub rtt_us: u64,
    /// Congestion window in bytes.
    pub cwnd_bytes: u64,
    /// Bytes received and authenticated.
    pub rx_bytes: u64,
    /// Bytes sealed and sent.
    pub tx_bytes: u64,
    /// Datagrams dropped as replays or for failed authentication.
    pub dropped: u64,
    /// Whole seconds since the session was established.
    pub uptime_s: u64,
}

/// A live client tunnel.
#[derive(Debug)]
pub struct Tunnel {
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    session: Arc<LiveSession<()>>,
    assigned_ip: Ipv4Addr,
    clock: Clock,
    started: Instant,
    inbound_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    task: JoinHandle<()>,
}

impl Tunnel {
    /// Run the handshake and start the datapath.
    pub async fn connect(cfg: TunnelConfig) -> Result<Self> {
        cfg.validate()?;
        let peer = cfg.server;
        let sock = Arc::new(udp::bind_for(peer).await?);
        let deadline = Instant::now() + cfg.handshake_timeout;

        let (state, hello) = handshake::start(&cfg, vpn_core::unix_now_secs())?;
        let mut buf = vec![0u8; MAX_DATAGRAM + 32];

        let established = loop {
            if Instant::now() >= deadline {
                return Err(Error::HandshakeTimeout);
            }
            udp::send(&sock, &hello, peer).await?;
            match tokio::time::timeout(HANDSHAKE_RETRY, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) if from == peer => {
                    if let Ok(est) = handshake::finish(&state, &buf[..n]) {
                        break est;
                    }
                    // Forged or stale: keep retransmitting until the deadline.
                }
                Ok(Ok(_)) => {} // wrong source, ignore
                Ok(Err(e)) => return Err(Error::Transport(format!("recv: {e}"))),
                Err(_) => {} // elapsed; retransmit
            }
        };

        let clock = Clock::new();
        let session = Arc::new(LiveSession::new(
            vpn_rt::client_endpoint(
                established.keys,
                established.session_tag,
                cfg.effective_mtu(),
                clock.now_us(),
            ),
            peer,
            (),
        ));

        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_DEPTH);
        let task = tokio::spawn(run(
            Arc::clone(&sock),
            Arc::clone(&session),
            inbound_tx,
            clock,
        ));

        Ok(Self {
            sock,
            peer,
            session,
            assigned_ip: established.assigned_ip,
            clock,
            started: Instant::now(),
            inbound_rx: Mutex::new(inbound_rx),
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
        self.session.endpoint.blocking_lock().mtu()
    }

    /// Raw descriptor of the tunnel's UDP socket.
    ///
    /// Android needs this to call `VpnService.protect(fd)`: without it the
    /// tunnel's own traffic is routed back into the tunnel and nothing gets
    /// through. The descriptor stays owned by the tunnel; do not close it.
    #[cfg(unix)]
    #[must_use]
    pub fn socket_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.sock.as_raw_fd()
    }

    /// Health snapshot.
    #[must_use]
    pub fn stats(&self) -> TunnelStats {
        let s = self.session.endpoint.blocking_lock().stats();
        TunnelStats {
            rtt_us: s.rtt_us,
            cwnd_bytes: s.cwnd_bytes,
            rx_bytes: s.rx_bytes,
            tx_bytes: s.tx_bytes,
            dropped: s.dropped,
            uptime_s: self.started.elapsed().as_secs(),
        }
    }

    /// Encrypt and send one IP packet.
    ///
    /// Returns `false` when the congestion window is full. The packet is then
    /// dropped rather than queued: this is the hot path of a TUN reader, and
    /// queueing here would just move the loss inside the process.
    pub async fn send_ip_packet(&self, ip_packet: &[u8]) -> Result<bool> {
        vpn_rt::send_ip(&self.sock, &self.session, ip_packet, self.clock.now_us()).await
    }

    /// Wait for the next inbound IP packet.
    pub async fn recv_ip_packet(&self) -> Result<Vec<u8>> {
        self.inbound_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(Error::NoSession)
    }

    /// Best-effort graceful teardown.
    pub async fn close(&self) {
        let dgrams = {
            let mut ep = self.session.endpoint.lock().await;
            ep.close();
            ep.take_outbox()
        };
        for d in dgrams {
            let _ = udp::send(&self.sock, &d, self.peer).await;
        }
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The client datapath: decrypt inbound datagrams, deliver IP packets, flush
/// whatever the protocol wants to send, and reap the session when it goes idle.
async fn run(
    sock: Arc<UdpSocket>,
    session: Arc<LiveSession<()>>,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    clock: Clock,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM + 32];
    let mut tick = tokio::time::interval(vpn_rt::TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut expired = false;

    while !expired {
        tokio::select! {
            received = sock.recv_from(&mut buf) => {
                let Ok((n, from)) = received else { continue };
                if from != session.peer() { continue; }
                match vpn_rt::deliver(&sock, &session, &buf[..n], clock.now_us()).await {
                    Ok(Some(pkt)) => {
                        if inbound_tx.send(pkt).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(Error::NoSession) => expired = true,
                    Err(e) => tracing::debug!(error = %e, "datagram rejected"),
                }
            }
            _ = tick.tick() => {
                match vpn_rt::flush(&sock, &session, clock.now_us()).await {
                    Ok(true) => expired = true,
                    Ok(false) => {}
                    Err(e) => tracing::debug!(error = %e, "housekeeping failed"),
                }
            }
        }
    }
    tracing::debug!("session loop ended");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> TunnelConfig {
        TunnelConfig {
            server: "127.0.0.1:1".parse().unwrap(),
            donor: vpn_core::DonorSpec::default(),
            psk: [0x11; 32],
            user_id: 42,
            tag_key: [0x22; 32],
            mtu: 1280,
            fingerprint: vpn_core::HelloProfile::default(),
            masquerade: false,
            handshake_timeout: Duration::from_millis(300),
        }
    }

    #[tokio::test]
    async fn a_config_with_no_server_times_out_instead_of_hanging() {
        let err = Tunnel::connect(cfg())
            .await
            .expect_err("nothing is listening on port 1");
        assert!(matches!(err, Error::HandshakeTimeout), "got {err}");
    }

    #[tokio::test]
    async fn an_invalid_config_is_refused_before_any_io() {
        let mut c = cfg();
        c.donor.sni = String::new();
        assert!(matches!(
            Tunnel::connect(c).await,
            Err(Error::Config(_))
        ));
    }
}
