//! The donor relay.
//!
//! Phase 1 (this module): [`DonorUplink`] — a transparent UDP splice. The
//! client's sealed Initial packets go to the real donor and the donor's genuine
//! handshake flows back unaltered; the server only *reads* along the way
//! (the masquerade label comes from `inspect_client_hello`, which needs the
//! publicly-derivable Initial keys, not a MITM). A failed or unlabeled probe
//! keeps being spliced forever: it *is* a white-site visit.
//!
//! Phase 2 (future, `craftls` + `quinn`): [`DonorRelay`] — speaking QUIC/HTTP-3
//! to the donor ourselves so post-handshake messages (NewSessionTicket) can be
//! faithfully forwarded. The Aparecium detection of ShadowTLS v3 came from
//! (a) an HMAC tag added to `ServerFinished` records and (b) dropped
//! NewSessionTickets; bProto does neither: auth lives in `session_id` (length
//! unchanged) and donor messages are preserved byte-for-byte.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::net::UdpSocket;

use crate::error::{Error, Result};

/// Splice crypto material from a client to the donor over a dedicated local
/// UDP socket (one per inspected connection).
///
/// The owning server loop does `client  ⇄  [server socket]`
/// and, while splicing, mirrors each Initial datagram through the
/// `DonorUplink` and vice versa until the label decides the tunnel takes
/// over. Donor datagrams larger than the tunnel path are the same ~1200-byte
/// QUIC-sized probes plus server Initials — indistinguishable from the
/// donor's real traffic mixture.
#[derive(Debug)]
pub struct DonorUplink {
    socket: UdpSocket,
    donor: SocketAddr,
}

impl DonorUplink {
    /// Bind a local socket to talk to an already-resolved donor.
    pub async fn bind_to(donor: SocketAddr) -> Result<Self> {
        // Port 0: ephemeral local port; the donor addresses replies here.
        let socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
            .await
            .map_err(Error::Io)?;
        Ok(Self { socket, donor })
    }

    /// Bind a local socket and record the donor address to talk to.
    pub async fn bind(donor_host: &str, donor_port: u16) -> Result<Self> {
        let addr = resolve_v4(donor_host, donor_port).await?;
        Self::bind_to(addr).await
    }

    /// Forward an exact client datagram (unmodified bytes!) to the donor.
    pub async fn forward(&self, dgram: &[u8]) -> Result<()> {
        self.socket
            .send_to(dgram, self.donor)
            .await
            .map(|_| ())
            .map_err(Error::Io)
    }

    /// Await one donor datagram, unmodified.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        self.socket.recv(buf).await.map_err(Error::Io)
    }

    /// The donor address in use (for tracing and tests).
    #[must_use]
    pub fn donor(&self) -> SocketAddr {
        self.donor
    }
}

/// Resolve a hostname to its first v4 address (donors are v4 web servers in
/// this protocol's threat model). No-async recursion, no happy-eyeballs
/// cleverness — Chrome's QUIC uses v4 endpoints routinely.
async fn resolve_v4(host: &str, port: u16) -> Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    // tokio's blocking DNS via spawn_blocking isn't spawned in tests without
    // a runtime — resolve synchronously behind `tokio::task::busy` semantics
    // is out of scope; ToSocketAddrs is fine for the handful of configured
    // donor hosts, resolved once per uplink.
    let _ = port;
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(Error::Io)?
        .filter(|a| a.is_ipv4())
        .collect::<Vec<_>>();
    addrs
        .first()
        .copied()
        .ok_or(Error::Config(format!("donor {host} has no IPv4 address")))
}

/// Future work (phase 2): speaks QUIC/HTTP-3 to the donor for faithful
/// post-handshake relaying. Nothing calls it yet; wiring lands together with
/// the `craftls` federation and the tunnel switch in `vpn-server`.
#[derive(Debug)]
pub struct DonorRelay {
    /// Donor hostname.
    pub sni: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn donor_address_is_recorded() {
        // 127.0.0.1 resolves instantly; no network needed.
        let uplink = DonorUplink::bind("127.0.0.1", 443).await.expect("bind");
        assert_eq!(
            uplink.donor(),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443))
        );
    }

    #[tokio::test]
    async fn unresolvable_donor_fails_cleanly() {
        assert!(
            DonorUplink::bind("this-domain-cannot-exist.invalid", 443)
                .await
                .is_err()
        );
    }
}
