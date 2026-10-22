//! UDP datagram transport.
//!
//! The wire format is deliberately shaped like QUIC so a passive observer sees
//! a short-header UDP flow to :443 that matches the donor's traffic profile.
//! Reliability, RTT estimation and congestion control are QUIC-grade:
//!
//! * ACK frames carry acknowledged packet-number ranges (RFC 9002 style),
//! * packet numbers are never reused and are covered by the replay window,
//! * NACK is sent as an explicit fast-loss hint, *in addition* to ACK, so loss
//!   recovery does not wait for a timeout,
//! * congestion control is CUBIC by default (via `quinn` when the `quic`
//!   feature is on), BBR as an opt-in experiment, BBRv3 is explicitly avoided.
//!
//! This module defines the `Transport` trait; the QUIC implementation lives in
//! `transport::quic` behind the `quic` feature.

use std::net::SocketAddr;

use crate::error::Result;

/// One datagram received from the network.
#[derive(Debug, Clone)]
pub struct Datagram {
    /// Raw bytes as they appeared on the wire.
    pub bytes: Vec<u8>,
    /// Source address.
    pub from: SocketAddr,
}

/// Pluggable datagram transport.
///
/// Implementations must be safe to call concurrently from the send and receive
/// halves of the tunnel.
pub trait Transport: Send + Sync {
    /// Send one already-encrypted datagram.
    fn send(&self, datagram: &[u8]) -> Result<()>;

    /// Send an explicit loss hint for the given packet numbers.
    fn send_nack(&self, missing: &[u64]) -> Result<()>;

    /// Rebind to a new local address after a network change.
    fn rebind(&self, new_local: SocketAddr) -> Result<()>;

    /// Current smoothed RTT estimate in microseconds, if known.
    fn rtt_us(&self) -> Option<u64>;

    /// Current congestion window in bytes, if known.
    fn cwnd_bytes(&self) -> Option<u64>;
}

/// Congestion control algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Congestion {
    /// CUBIC — the default. Predictable, well understood, no known panics.
    #[default]
    Cubic,
    /// BBR — opt-in, evaluate with telemetry before defaulting.
    Bbr,
    // BBRv3 is intentionally absent: it has a reproducible underflow/panic in
    // the quinn implementation and is not safe to ship.
}

/// Sizing buckets that all datagrams should snap to, so the outgoing packet
/// size distribution resembles the donor's QUIC traffic rather than a
/// tell-tale constant MTU.
pub const SIZE_BUCKETS: [usize; 5] = [128, 256, 512, 1024, 1252];

/// Snap a plaintext length to the nearest bucket at or above it.
#[must_use]
pub fn snap_to_bucket(len: usize) -> usize {
    SIZE_BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= len)
        .unwrap_or(crate::packet::MAX_DATAGRAM)
}

#[cfg(feature = "quic")]
pub mod quic;
pub mod udp;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_snapping() {
        assert_eq!(snap_to_bucket(1), 128);
        assert_eq!(snap_to_bucket(128), 128);
        assert_eq!(snap_to_bucket(129), 256);
        assert_eq!(snap_to_bucket(2000), crate::packet::MAX_DATAGRAM);
    }
}
