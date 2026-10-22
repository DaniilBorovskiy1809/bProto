//! Integration test for the acceptance criterion:
//! "a censor with the wrong password gets the real site".
//!
//! This test is a harness skeleton. It needs a real donor (or a local TLS stub)
//! and the handshake implementation, so it is `#[ignore]`d in MVP and run in CI
//! once `masquerade` lands. Run with:
//!
//! ```sh
//! cargo test -p vpn-core --test censor_gets_real_site -- --ignored --nocapture
//! ```
//!
//! What it asserts (see docs/PLAN.md section 7):
//!   1. A ClientHello with a VALID label is intercepted: the server answers with
//!      a bProto session, not with the donor's handshake.
//!   2. A ClientHello with a random session_id is relayed transparently: the
//!      prober receives the donor's real certificate chain.
//!   3. A ClientHello with the right tag but wrong MAC is ALSO relayed.
//!   4. After a valid handshake, the donor's NewSessionTicket messages are
//!      present, byte-for-byte, so Aparecium's NST vector does not fire.

use vpn_core::auth::{compute_tag, derive_session_id, verify_session_id};
use vpn_core::crypto::{self, KEY_LEN};

/// Stand-in for the server-side label check. Returns true when the datagram
/// belongs to a bProto client and must be intercepted.
fn server_would_intercept(
    psk: &[u8; KEY_LEN],
    sid: &[u8],
    client_random: &[u8; 32],
    x25519_pub: &[u8; 32],
    now: u64,
) -> bool {
    verify_session_id(psk, sid, client_random, x25519_pub, now)
}

#[test]
fn classify_valid_vs_probe_without_network() {
    let psk = [0x77u8; KEY_LEN];
    let tag = compute_tag(&[0x88; KEY_LEN], 1);
    let cr = [0x0Au8; 32];
    let pubk = [0x0Bu8; 32];
    let now = 1_800_000_000;

    // valid client -> intercept
    let good = derive_session_id(&psk, &tag, &cr, &pubk, now);
    assert!(server_would_intercept(&psk, &good, &cr, &pubk, now));

    // censor probe with a random session id -> relay to donor (not intercepted)
    let probe = crypto::KeyPair::generate();
    let _ = probe;
    let random_sid = [0xC3u8; 32];
    assert!(!server_would_intercept(&psk, &random_sid, &cr, &pubk, now));

    // censor with a wrong psk -> relay to donor
    let mut wrong = psk;
    wrong[0] ^= 0xFF;
    assert!(!server_would_intercept(&wrong, &good, &cr, &pubk, now));
}

#[test]
#[ignore = "requires donor + handshake; run with --ignored in CI once masquerade lands"]
fn censor_with_wrong_password_receives_real_donor_handshake() {
    // TODO(stage 1): boot `vpn-server` against a local donor stub, send a
    // ClientHello with a random session_id, assert the returned Certificate
    // message equals the donor's, and assert NewSessionTicket frames are
    // present after ClientFinished.
    unimplemented!("implemented together with vpn-server::interceptor");
}
