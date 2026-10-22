//! The authentication label: the core of "the censor with the wrong password
//! gets the real site". A genuine random session id, or a label from a wrong
//! PSK, must never verify.

use vpn_core::auth::{
    SESSION_ID_LEN, WINDOW_SECS, compute_tag, derive_session_id, extract_tag, verify_session_id,
};
use vpn_core::crypto::KEY_LEN;

fn fixed() -> ([u8; KEY_LEN], [u8; 8], [u8; 32], [u8; 32]) {
    (
        [0x10; KEY_LEN],
        compute_tag(&[0x20; KEY_LEN], 99),
        [0xA1; 32],
        [0xB2; 32],
    )
}

#[test]
fn label_length_matches_a_browser_session_id() {
    let (psk, tag, cr, pubk) = fixed();
    let sid = derive_session_id(&psk, &tag, &cr, &pubk, 1_700_000_000);
    // 32 bytes: identical length to the random session id Chrome sends in
    // middlebox-compat mode. Nothing about the handshake length changes.
    assert_eq!(sid.len(), SESSION_ID_LEN);
    assert_eq!(sid.len(), 32);
}

#[test]
fn correct_label_verifies_inside_window() {
    let (psk, tag, cr, pubk) = fixed();
    let now = 1_700_000_000;
    let sid = derive_session_id(&psk, &tag, &cr, &pubk, now);
    assert!(verify_session_id(&psk, &sid, &cr, &pubk, now));
    assert!(verify_session_id(
        &psk,
        &sid,
        &cr,
        &pubk,
        now + WINDOW_SECS - 1
    ));
}

#[test]
fn wrong_psk_never_verifies() {
    let (psk, tag, cr, pubk) = fixed();
    let sid = derive_session_id(&psk, &tag, &cr, &pubk, 1_700_000_000);
    let mut wrong = psk;
    wrong[31] ^= 0x01;
    assert!(!verify_session_id(&wrong, &sid, &cr, &pubk, 1_700_000_000));
}

#[test]
fn random_session_id_never_verifies() {
    let (psk, _, cr, pubk) = fixed();
    // What a legitimate browser probe would send.
    let random = [0x5Au8; 32];
    assert!(!verify_session_id(&psk, &random, &cr, &pubk, 1_700_000_000));
    assert!(extract_tag(&random).is_some()); // tag parses, MAC fails
}

#[test]
fn stale_label_is_rejected() {
    let (psk, tag, cr, pubk) = fixed();
    let now = 1_700_000_000;
    let sid = derive_session_id(&psk, &tag, &cr, &pubk, now);
    // far outside the +-1 window
    assert!(!verify_session_id(
        &psk,
        &sid,
        &cr,
        &pubk,
        now + 4 * WINDOW_SECS
    ));
}
