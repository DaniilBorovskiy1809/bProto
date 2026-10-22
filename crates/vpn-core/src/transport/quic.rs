//! QUIC-backed transport (feature `quic`).
//!
//! Stage 1 uses `quinn` for: UDP socket handling, connection IDs, RTT
//! estimation (RFC 9002), loss detection and CUBIC congestion control. bProto
//! datagrams ride in QUIC 1-RTT packets; the handshake rides in Initial/Handshake
//! CRYPTO frames so the donor's certificate can be relayed.
//!
//! Congestion control is selected through [`crate::transport::Congestion`].
//! BBRv3 is deliberately not offered.

use std::net::SocketAddr;

use crate::error::{Error, Result};

/// Placeholder endpoint wrapper. Real wiring lands with the handshake.
#[derive(Debug, Default)]
pub struct QuicTransport {
    local: Option<SocketAddr>,
}

impl QuicTransport {
    /// Bind the transport to a local UDP address.
    pub fn bind(local: SocketAddr) -> Result<Self> {
        Ok(Self { local: Some(local) })
    }

    /// The bound local address.
    #[must_use]
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.local
            .ok_or_else(|| Error::Transport("transport not bound".into()))
    }
}
