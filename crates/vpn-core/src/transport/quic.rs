//! Unfinished QUIC transport scaffold (feature `quic`).
//!
//! This wrapper stores an address only: it does not bind a socket, negotiate
//! TLS, send QUIC packets, or relay a donor certificate. Production sessions
//! continue to use the native UDP transport even when this feature is enabled.

use std::net::SocketAddr;

use crate::error::{Error, Result};

/// Placeholder endpoint wrapper. Real wiring lands with the handshake.
#[derive(Debug, Default)]
pub struct QuicTransport {
    local: Option<SocketAddr>,
}

impl QuicTransport {
    /// Record the intended local address; no socket is bound.
    pub fn bind(local: SocketAddr) -> Result<Self> {
        Ok(Self { local: Some(local) })
    }

    /// The configured local address (not an actual socket address).
    #[must_use]
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.local
            .ok_or_else(|| Error::Transport("transport not bound".into()))
    }
}
