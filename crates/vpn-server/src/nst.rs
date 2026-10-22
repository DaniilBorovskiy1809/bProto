//! `NewSessionTicket` handling.
//!
//! This module exists to make the Aparecium mitigation explicit in the code,
//! not just in the design doc.
//!
//! Aparecium (May 2025) kills ShadowTLS v3 with two vectors:
//!   1. it HMAC-tags every handshake frame, so `ServerFinished` is 4 bytes
//!      longer than a real one;
//!   2. it stops relaying the donor's `NewSessionTicket` messages after
//!      `ClientFinished`, and their absence is detectable by comparing against a
//!      direct connection to the donor.
//!
//! bProto's answers:
//!   1. authentication lives in `session_id` (`vpn_core::auth`); no frame is
//!      modified, so `ServerFinished` keeps its real length;
//!   2. we keep the donor connection alive and forward its post-handshake
//!      messages, including `NewSessionTicket`, verbatim — see
//!      [`PostHandshakePolicy`].
//!
//! A real TLS 1.3 server (OpenSSL) emits one or two tickets; a synthesized
//! ticket must mirror the donor's observed count and timing, not a constant.

/// What the interception path does with the donor's post-handshake messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PostHandshakePolicy {
    /// Forward the donor's messages verbatim (default; safest against Aparecium).
    Relay,
    /// Synthesize a plausible ticket when the donor produced none, so the count
    /// and timing still match what a direct connection would show.
    #[default]
    RelayOrSynthesize,
    /// Do not send tickets. Only for debugging; this is the ShadowTLS failure
    /// mode and must never ship.
    Suppress,
}

/// Number of `NewSessionTicket` messages a real TLS 1.3 server typically emits.
pub const TYPICAL_TICKET_COUNT: usize = 2;

/// Decide whether a post-handshake message must be forwarded to the client.
#[must_use]
pub fn must_forward(policy: PostHandshakePolicy, donor_sent_any: bool) -> bool {
    match policy {
        PostHandshakePolicy::Relay => true,
        PostHandshakePolicy::RelayOrSynthesize => true,
        PostHandshakePolicy::Suppress => {
            let _ = donor_sent_any;
            false
        }
    }
}

/// Guard used in debug builds and tests to ensure we never ship `Suppress`.
pub fn assert_safe_policy(policy: PostHandshakePolicy, release: bool) -> Result<(), &'static str> {
    if release && policy == PostHandshakePolicy::Suppress {
        return Err("PostHandshakePolicy::Suppress is detectable (Aparecium) and must not ship");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_forwards_tickets() {
        assert!(must_forward(PostHandshakePolicy::default(), true));
        assert!(must_forward(PostHandshakePolicy::default(), false));
    }

    #[test]
    fn suppress_is_blocked_in_release() {
        assert!(assert_safe_policy(PostHandshakePolicy::Suppress, true).is_err());
        assert!(assert_safe_policy(PostHandshakePolicy::Relay, true).is_ok());
        assert!(assert_safe_policy(PostHandshakePolicy::Suppress, false).is_ok());
    }
}
