//! The donor relay: what a prober gets instead of a refusal.
//!
//! This is the whole point of the masquerade layer. Our server sits on a port
//! that is supposed to belong to the donor site, so anyone who knocks — a
//! censor scanning with a real TLS or QUIC stack, a bored port scanner, a
//! client whose key we revoked — must get the donor's answer, not ours. The
//! bytes go upstream untouched and the donor's response comes back untouched.
//! From outside there is no way to tell this process from a UDP forwarder.
//!
//! One upstream socket per peer, because QUIC and TLS both key on the
//! 4-tuple: a fresh socket per datagram would make the donor see a new
//! connection each time and the prober's handshake would never complete.
//!
//! Flows are bounded. Every one of them is an open socket and a task, and a
//! peer that can create them faster than they time out is a resource attack,
//! not a client.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use vpn_core::{Error, MAX_DATAGRAM, Result};
use vpn_rt::udp;

/// How long a silent flow is kept before its socket is closed.
pub const FLOW_IDLE: Duration = Duration::from_secs(30);

/// How many relayed peers at once. Past this, new peers are dropped rather
/// than the process being exhausted.
pub const MAX_FLOWS: usize = 4_096;

/// Depth of the queue between the listener and a flow's upstream socket.
const QUEUE_DEPTH: usize = 64;

/// Forwards datagrams from unknown peers to the donor and back.
#[derive(Debug)]
pub struct Relay {
    donor: SocketAddr,
    /// One sending end per peer; the receiving end lives in the flow's task.
    flows: Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>,
    idle: Duration,
}

impl Relay {
    /// A relay towards `donor`, which must be a pinned address — see
    /// [`crate::config::ServerConfig::validate`].
    #[must_use]
    pub fn new(donor: SocketAddr) -> Self {
        Self::with_idle(donor, FLOW_IDLE)
    }

    /// Same, with a caller-chosen idle timeout. Tests use a short one.
    #[must_use]
    pub fn with_idle(donor: SocketAddr, idle: Duration) -> Self {
        Self {
            donor,
            flows: Mutex::new(HashMap::new()),
            idle,
        }
    }

    /// The donor everything is forwarded to.
    #[must_use]
    pub fn donor(&self) -> SocketAddr {
        self.donor
    }

    /// Live flows, for the operator.
    pub async fn len(&self) -> usize {
        self.flows.lock().await.len()
    }

    /// Whether there are no live flows.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Forward one datagram from `peer`, and arrange for the donor's answers to
    /// reach `peer` through `downstream`.
    ///
    /// `downstream` is the socket the datagram arrived on: the reply has to go
    /// out from the same address the peer sent to, or it will be dropped as
    /// unsolicited.
    pub async fn forward(
        &self,
        downstream: &Arc<UdpSocket>,
        peer: SocketAddr,
        bytes: &[u8],
    ) -> Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_DATAGRAM {
            return Err(Error::PayloadTooLarge(bytes.len(), MAX_DATAGRAM));
        }

        let tx = match self.existing(&peer).await {
            Some(tx) => tx,
            None => self.open(downstream, peer).await?,
        };

        tx.send(bytes.to_vec())
            .await
            .map_err(|_| Error::Transport("relay flow closed".into()))
    }

    /// The live sender for `peer`, if its task is still running.
    async fn existing(&self, peer: &SocketAddr) -> Option<mpsc::Sender<Vec<u8>>> {
        let flows = self.flows.lock().await;
        let tx = flows.get(peer)?;
        // A closed channel means the task exited (idle timeout). Treat it as
        // no flow at all and let the caller open a fresh one.
        (!tx.is_closed()).then(|| tx.clone())
    }

    /// Open a flow for `peer` and spawn the task that owns its socket.
    async fn open(
        &self,
        downstream: &Arc<UdpSocket>,
        peer: SocketAddr,
    ) -> Result<mpsc::Sender<Vec<u8>>> {
        let mut flows = self.flows.lock().await;
        if let Some(tx) = flows.get(&peer)
            && !tx.is_closed()
        {
            return Ok(tx.clone());
        }
        if flows.len() >= MAX_FLOWS {
            return Err(Error::Transport("too many open relay flows".into()));
        }

        let (tx, rx) = mpsc::channel(QUEUE_DEPTH);
        flows.insert(peer, tx.clone());
        drop(flows);

        // Bind an unspecified address in the donor's family, so an IPv6 donor
        // is not reached from an IPv4 socket.
        let up = Arc::new(udp::bind_for(self.donor).await?);
        up.connect(self.donor).await?;

        tokio::spawn(pump(up, rx, Arc::clone(downstream), peer, self.idle));

        tracing::debug!(%peer, donor = %self.donor, "opened a relay flow");
        Ok(tx)
    }
}

/// Move bytes in both directions until the flow goes quiet.
///
/// This task owns the upstream socket, so closing the flow is just returning:
/// the receiver drops, the sender reports closed, and the next datagram from
/// that peer opens a new one.
async fn pump(
    up: Arc<UdpSocket>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    downstream: Arc<UdpSocket>,
    peer: SocketAddr,
    idle: Duration,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM + 64];
    loop {
        tokio::select! {
            Some(bytes) = rx.recv() => {
                if up.send(&bytes).await.is_err() {
                    return;
                }
            }
            Ok(n) = up.recv(&mut buf) => {
                if downstream.send_to(&buf[..n], peer).await.is_err() {
                    return;
                }
            }
            // Restarted on every iteration, so this is an inactivity timer.
            _ = tokio::time::sleep(idle) => {
                tracing::debug!(%peer, "relay flow went idle");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Bind a loopback socket, returning it with its address.
    async fn bind() -> (Arc<UdpSocket>, SocketAddr) {
        let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let a = s.local_addr().unwrap();
        (s, a)
    }

    async fn recv(s: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = vec![0u8; MAX_DATAGRAM + 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), s.recv_from(&mut buf))
            .await
            .expect("timed out waiting for a datagram")
            .expect("recv");
        (buf[..n].to_vec(), from)
    }

    #[tokio::test]
    async fn a_probe_reaches_the_donor_and_the_donors_answer_reaches_the_probe() {
        let (donor, donor_addr) = bind().await;
        let (listener, listener_addr) = bind().await;
        let (probe, probe_addr) = bind().await;
        let relay = Relay::with_idle(donor_addr, Duration::from_secs(5));

        relay
            .forward(&listener, probe_addr, b"ClientHello")
            .await
            .unwrap();

        // The donor sees the prober's bytes, unmodified, from our upstream.
        let (got, upstream) = recv(&donor).await;
        assert_eq!(got, b"ClientHello");

        // The donor answers; the prober must receive it from our listener.
        donor.send_to(b"ServerHello", upstream).await.unwrap();
        let (got, from) = recv(&probe).await;
        assert_eq!(got, b"ServerHello");
        assert_eq!(
            from, listener_addr,
            "the answer must come from the address the probe sent to"
        );
    }

    #[tokio::test]
    async fn one_peer_keeps_one_upstream_socket() {
        let (donor, donor_addr) = bind().await;
        let (listener, _) = bind().await;
        // Only the probe's address matters here; nothing is read back.
        let (_probe, probe_addr) = bind().await;
        let relay = Relay::with_idle(donor_addr, Duration::from_secs(5));

        relay.forward(&listener, probe_addr, b"one").await.unwrap();
        let (_, first) = recv(&donor).await;
        relay.forward(&listener, probe_addr, b"two").await.unwrap();
        let (got, second) = recv(&donor).await;

        assert_eq!(got, b"two");
        assert_eq!(
            first, second,
            "a peer's flow must reuse its upstream 4-tuple"
        );
        assert_eq!(relay.len().await, 1);
    }

    #[tokio::test]
    async fn two_peers_get_two_flows() {
        let (donor, donor_addr) = bind().await;
        let (listener, _) = bind().await;
        let (p1, a1) = bind().await;
        let (p2, a2) = bind().await;
        let relay = Relay::with_idle(donor_addr, Duration::from_secs(5));

        relay.forward(&listener, a1, b"a").await.unwrap();
        let (_, f1) = recv(&donor).await;
        relay.forward(&listener, a2, b"b").await.unwrap();
        let (_, f2) = recv(&donor).await;

        assert_ne!(f1, f2);
        assert_eq!(relay.len().await, 2);
        drop((p1, p2));
    }

    #[tokio::test]
    async fn an_oversized_datagram_is_refused_without_opening_a_flow() {
        // The donor must exist to be a valid relay target, but nothing reaches
        // it: that is the assertion.
        let (_donor, donor_addr) = bind().await;
        let (listener, _) = bind().await;
        let (_probe, probe_addr) = bind().await;
        let relay = Relay::with_idle(donor_addr, Duration::from_secs(5));

        let huge = vec![0u8; MAX_DATAGRAM + 1];
        assert!(relay.forward(&listener, probe_addr, &huge).await.is_err());
        assert!(relay.is_empty().await);
    }
}
