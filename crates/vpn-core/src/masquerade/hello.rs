//! ClientHello crafting.
//!
//! The fingerprint engine is the `craftls` fork of `rustls` (a drop-in
//! replacement exposing `ClientConfig::with_fingerprint`). We add exactly one
//! capability: injecting our 32-byte authentication label into `session_id`
//! without changing the ClientHello length. See `crates/craftls/PATCH.md`.

use crate::error::{Error, Result};

use super::HelloParams;

/// Client-side per-session material generated before the handshake.
#[derive(Debug)]
pub struct ClientSecrets {
    /// Ephemeral X25519 keypair, zeroized on drop.
    pub ephemeral: crate::crypto::KeyPair,
    /// 32 random bytes placed in ClientHello.
    pub client_random: [u8; 32],
}

impl ClientSecrets {
    /// Generate fresh per-session material.
    #[must_use]
    pub fn generate() -> Self {
        let mut client_random = [0u8; 32];
        getrandom::getrandom(&mut client_random).expect("OS RNG");
        Self {
            ephemeral: crate::crypto::KeyPair::generate(),
            client_random,
        }
    }

    /// Build the 32-byte `session_id` label from the supplied PSK and tag.
    #[must_use]
    pub fn session_id(
        &self,
        psk: &[u8; crate::crypto::KEY_LEN],
        tag: &[u8; crate::auth::TAG_LEN],
        unix_secs: u64,
    ) -> [u8; crate::auth::SESSION_ID_LEN] {
        crate::auth::derive_session_id(
            psk,
            tag,
            &self.client_random,
            &self.ephemeral.public_bytes(),
            unix_secs,
        )
    }
}

/// Build the ClientHello record with the given params and secrets.
///
/// Returned bytes are the raw TLS handshake, ready to be wrapped in a QUIC
/// Initial packet by the transport.
pub fn build(_params: &HelloParams, _secrets: &ClientSecrets) -> Result<Vec<u8>> {
    // Wiring depends on the vendored craftls fork:
    //   let mut cfg = rustls::ClientConfig::builder()
    //       .with_root_certificates(roots)
    //       .with_no_client_auth()
    //       .with_fingerprint(params.fingerprint.into())
    //       .with_session_id(params.session_id);
    let _ = (_params, _secrets);
    Err(Error::Unimplemented(
        "craftls vendoring + session_id patch (crates/craftls/PATCH.md)",
    ))
}
