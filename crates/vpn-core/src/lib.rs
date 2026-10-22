//! bProto protocol core.
//!
//! This crate is **pure protocol**. It performs no I/O: it has no sockets, no
//! timers and no async runtime, and it does not know what a TUN device is. The
//! caller hands it bytes and a monotonic timestamp; it hands back bytes to send
//! and payloads to deliver. Everything above this line — sockets, event loops,
//! TUN devices, JNI — lives in other crates.
//!
//! Layout:
//!
//! * [`packet`]   – the 12-byte datagram header and inner framing
//! * [`crypto`]   – X25519, ChaCha20-Poly1305, HKDF key schedule
//! * [`auth`]     – the routing tag and the `session_id` / `HELLO` label
//! * [`handshake`]– the three-datagram native handshake
//! * [`frame`]    – control-frame codec (HELLO, HELLO_ACK, ACK, PING, …)
//! * [`endpoint`] – [`Endpoint`], the one session state machine both peers use
//! * [`ack`]      – ACK ranges, RTT estimation, in-flight tracking
//! * [`congestion`]– CUBIC congestion control
//! * [`replay`]   – anti-replay sliding window
//! * [`ip`]       – minimal IP header inspection
//! * [`pool`]     – tunnel address leases
//! * [`tags`]     – the `tag -> (user, psk)` routing table
//! * [`hello`]    – TLS ClientHello codec (the masquerade carrier)
//! * [`masquerade`]– the “own client or active probe” decision
//! * [`config`]   – [`TunnelConfig`]

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod ack;
pub mod auth;
pub mod config;
pub mod congestion;
pub mod crypto;
pub mod endpoint;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod hello;
pub mod ip;
pub mod masquerade;
pub mod packet;
pub mod pool;
pub mod replay;
pub mod tags;

pub use ack::{AckRanges, RttEstimator, SentPackets};
pub use config::{DonorSpec, TunnelConfig};
pub use congestion::Cubic;
pub use endpoint::{Endpoint, EndpointParams, EndpointStats, Opened, Role};
pub use error::{Error, Result};
pub use hello::{ClientHello, ClientHelloBuilder, HelloProfile};
pub use masquerade::{Verdict, classify, craft_client_hello};
pub use packet::{HEADER_LEN, InnerType, MAX_DATAGRAM, TUNNEL_MTU};
pub use pool::IpPool;
pub use tags::TagTable;

/// Protocol version carried in the header version nibble.
pub const PROTOCOL_VERSION: u8 = 0x1;

/// Timestamp in whole seconds since the Unix epoch.
#[must_use]
pub fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
