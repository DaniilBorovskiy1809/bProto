//! bProto server library.
//!
//! The binary is a thin `main`; everything testable lives here so the modules
//! are real public API with unit tests, not dead scaffolding in a binary.
//!
//! * [`config`]  – `server.toml`
//! * [`control`] – the control plane: keys in from the panel, traffic out
//! * [`server`]  – [`server::Node`]: the session table, acceptor and pool
//!
//! The datapath is `vpn-rt` driving [`vpn_core::Endpoint`]; the TUN and route
//! plumbing is `vpn-tun`.

pub mod config;
pub mod control;
pub mod relay;
pub mod server;
