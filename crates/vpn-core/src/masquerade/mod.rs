//! Masquerade: crafting the ClientHello and relaying to the donor site.
//!
//! Two halves:
//!
//! * [`hello`] — build the TLS ClientHello with a browser fingerprint (via
//!   `craftls`) and inject the [`crate::auth`] label into `session_id`.
//! * [`relay`] — talk to the donor so the server can borrow its certificate and
//!   continue relaying (or faithfully synthesize) the post-handshake messages,
//!   including `NewSessionTicket`.
//!
//! The Aparecium attack works against ShadowTLS v3 because (a) it tags every
//! handshake frame with an HMAC, adding 4 bytes to `ServerFinished`, and (b) it
//! stops relaying the donor's `NewSessionTicket` messages. bProto does neither:
//! authentication lives in `session_id`, whose length is unchanged, and the
//! donor's post-handshake messages are preserved.

use crate::config::Fingerprint;
use crate::error::{Error, Result};

pub mod hello;
pub mod relay;

/// Everything the ClientHello builder needs.
#[derive(Debug, Clone)]
pub struct HelloParams {
    /// Donor hostname, used as SNI.
    pub sni: String,
    /// ALPN protocols to offer.
    pub alpn: Vec<String>,
    /// Browser fingerprint to imitate.
    pub fingerprint: Fingerprint,
    /// The 32-byte authentication label to place in `session_id`.
    pub session_id: [u8; crate::auth::SESSION_ID_LEN],
}

/// A fully built ClientHello record, ready to be carried inside a QUIC Initial
/// packet, plus the X25519 public key and random that went into the label.
#[derive(Debug)]
pub struct CraftedHello {
    /// The raw TLS handshake bytes.
    pub handshake: Vec<u8>,
    /// Client random used in the label MAC.
    pub client_random: [u8; 32],
    /// Client's X25519 public key.
    pub x25519_pub: [u8; 32],
}

/// Build the ClientHello for a session.
///
/// Stage 1 status: the fingerprint plumbing is delegated to the `craftls` fork
/// (see `crates/craftls/PATCH.md`); until it is vendored this returns
/// [`Error::Unimplemented`] so nobody mistakes a stub for a working handshake.
pub fn craft_client_hello(_params: &HelloParams) -> Result<CraftedHello> {
    Err(Error::Unimplemented(
        "craftls vendoring + session_id patch (crates/craftls/PATCH.md)",
    ))
}
