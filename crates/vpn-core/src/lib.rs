//! bProto protocol core.
//!
//! This crate is platform-agnostic: it knows nothing about TUN devices, JNI or
//! Swift. It exchanges raw IP packets with its embedder and nothing else.
//!
//! Layout (see `docs/PLAN.md` section 3):
//!
//! * [`packet`]     – the 12-byte datagram header and inner framing
//! * [`crypto`]     – X25519, ChaCha20-Poly1305, HKDF key schedule
//! * [`auth`]       – the `session_id` / `HELLO` authentication label
//! * [`handshake`]  – the three-datagram native handshake
//! * [`frame`]      – control-frame codec (HELLO, HELLO_ACK, ACK, PING, …)
//! * [`ack`]        – ACK ranges, RTT estimation, loss detection
//! * [`congestion`] – CUBIC congestion control
//! * [`replay`]     – anti-replay sliding window
//! * [`session`]    – [`Session`] crypto state and the client [`Tunnel`]
//! * [`server`]     – [`ServerNode`], the server-side protocol half
//! * [`pool`]       – tunnel address leases
//! * [`tags`]       – the `tag -> (user, psk)` routing table
//! * [`ip`]         – minimal IP header inspection
//! * [`transport`]  – UDP datagram transport (QUIC-shaped)
//! * [`masquerade`] – ClientHello crafting and donor relay (stage 2)
//! * [`config`]     – [`TunnelConfig`]

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod ack;
pub mod auth;
pub mod config;
pub mod congestion;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod ip;
pub mod masquerade;
pub mod packet;
pub mod pool;
pub mod replay;
pub mod server;
pub mod session;
pub mod tags;
pub mod transport;

pub use ack::{AckRanges, RttEstimator, SentPackets};
pub use config::{DonorSpec, Fingerprint, StealthLevel, TunnelConfig};
pub use congestion::Cubic;
pub use error::{Error, Result};
pub use packet::{HEADER_LEN, InnerType, MAX_DATAGRAM, TUNNEL_MTU};
pub use pool::IpPool;
pub use server::{ServerNode, ServerParams, ServerStats};
pub use session::{Opened, Session, Tunnel, TunnelStats, unix_now_secs};
pub use tags::TagTable;

/// Protocol version carried in the header version nibble.
pub const PROTOCOL_VERSION: u8 = 0x1;
