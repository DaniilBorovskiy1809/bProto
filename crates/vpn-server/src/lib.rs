//! bProto server library.
//!
//! The binary is a thin `main`; everything testable lives here so the modules
//! are real public API with unit tests, not dead scaffolding in a binary.
//!
//! * [`config`]      – `server.toml` and the derived [`config::TagTable`]
//! * [`interceptor`] – ClientHello classification (the masquerade path)
//! * [`splicer`]     – donor splice supervision (the probe path)
//! * [`nst`]         – post-handshake (NewSessionTicket) policy guard
//! * [`admin`]       – loopback-only admin API for the panel
//!
//! The datapath itself lives in `vpn-core` ([`vpn_core::ServerNode`]) and the
//! TUN/route plumbing in `vpn-tun`.

pub mod admin;
pub mod config;
pub mod interceptor;
pub mod nst;
pub mod splicer;
