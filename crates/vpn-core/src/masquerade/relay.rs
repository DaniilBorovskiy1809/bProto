//! Key schedule for the relay path. Stage 1 stub with the exact interface the
//! server uses, so the server compiles and the wiring can be reviewed before the
//! handshake lands.

use crate::error::{Error, Result};

/// A live relay to the donor: we spoke TLS/QUIC to the donor and can forward
/// post-handshake messages (including NewSessionTicket) verbatim.
#[derive(Debug)]
pub struct DonorRelay {
    /// Donor hostname.
    pub sni: String,
}

impl DonorRelay {
    /// Open a relay to the donor with the given SNI/ALPN.
    pub async fn connect(_sni: &str, _alpn: &[String]) -> Result<Self> {
        Err(Error::Unimplemented(
            "donor handshake: quinn/craftls client (stage 1)",
        ))
    }

    /// Relay a ClientHello to the donor and stream back its handshake bytes.
    ///
    /// Used for the transparent path: when the `session_id` label does not
    /// verify, the server forwards the client's handshake to the donor verbatim
    /// so the prober sees the real site.
    pub async fn relay_client_hello(&self, _client_hello: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Unimplemented("relay_client_hello"))
    }

    /// Return post-handshake messages the donor has produced (e.g.
    /// `NewSessionTicket`). The server must forward these to the client so their
    /// absence cannot be used as a detector (the Aparecium NST vector).
    pub async fn drain_post_handshake(&self) -> Result<Vec<Vec<u8>>> {
        Err(Error::Unimplemented("drain_post_handshake"))
    }
}
