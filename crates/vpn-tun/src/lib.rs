//! Linux network plumbing for bProto: the TUN device, NAT masquerade and the
//! client-side route takeover.
//!
//! Kept out of `vpn-core` on purpose — the protocol crate is platform-agnostic
//! and forbids `unsafe`; opening `/dev/net/tun` needs one small ioctl, so it
//! lives here instead.
//!
//! Only Linux is implemented. macOS/iOS clients use `utun` through
//! NetworkExtension and Android uses the `VpnService` file descriptor; both
//! hand the resulting fd to the same datapath rather than going through this
//! crate.

#![allow(unsafe_code)]

pub mod dev;
pub mod nat;
pub mod route;

pub use dev::TunDevice;
pub use dev::can_configure_network;

/// Default TUN interface name.
pub const DEFAULT_IFACE: &str = "bproto0";
