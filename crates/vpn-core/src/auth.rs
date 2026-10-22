//! Authentication labels and MACs derived from the pre-shared key.
//!
//! Two consumers share one MAC construction:
//!
//! * the TLS `session_id` label (`derive_session_id` / `verify_session_id`),
//!   used when the handshake is carried inside a real ClientHello;
//! * the native bProto `HELLO` handshake used when the traffic is not wrapped in
//!   a borrowed TLS handshake (`label_mac` / `verify_label_mac`).
//!
//! Both MAC over the same tuple, so a deployment only has one thing to reason
//! about. The `HELLO_ACK` MAC additionally covers the server random and the
//! assigned address.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::crypto::KEY_LEN;

type HmacSha256 = Hmac<Sha256>;

/// Length of the TLS `session_id` we emit. Must stay 32 to look like a browser.
pub const SESSION_ID_LEN: usize = 32;
/// Length of the routing tag.
pub const TAG_LEN: usize = 8;
/// Length of every label MAC.
pub const MAC_LEN: usize = 24;
/// Replay window in seconds; the server accepts `T-1, T, T+1`.
pub const WINDOW_SECS: u64 = 300;

fn mac(key: &[u8; KEY_LEN], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// Routing tag for a user. Precomputed by the panel into the `tag -> user` table
/// the server holds in memory.
#[must_use]
pub fn compute_tag(tag_key: &[u8; KEY_LEN], user_id: u64) -> [u8; TAG_LEN] {
    let out = mac(tag_key, &[b"bproto-tag", &user_id.to_be_bytes()]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&out[..TAG_LEN]);
    tag
}

/// The time window index for a unix timestamp.
#[must_use]
pub const fn time_window(unix_secs: u64) -> u64 {
    unix_secs / WINDOW_SECS
}

/// The client-proof MAC, over the routing tag, client random, ephemeral public
/// key and time window. Identical bytes whether they travel in a `session_id` or
/// in a native `HELLO`.
#[must_use]
pub fn label_mac(
    psk: &[u8; KEY_LEN],
    tag: &[u8; TAG_LEN],
    client_random: &[u8; 32],
    x25519_pub: &[u8; 32],
    window: u64,
) -> [u8; MAC_LEN] {
    let out = mac(
        psk,
        &[
            b"bproto-label",
            tag,
            client_random,
            x25519_pub,
            &window.to_be_bytes(),
        ],
    );
    let mut m = [0u8; MAC_LEN];
    m.copy_from_slice(&out[..MAC_LEN]);
    m
}

/// Server-side verification of [`label_mac`], accepting the current window and
/// its neighbours. Constant-time.
#[must_use]
pub fn verify_label_mac(
    psk: &[u8; KEY_LEN],
    tag: &[u8; TAG_LEN],
    client_random: &[u8; 32],
    x25519_pub: &[u8; 32],
    unix_secs: u64,
    presented: &[u8],
) -> bool {
    if presented.len() != MAC_LEN {
        return false;
    }
    let now = time_window(unix_secs);
    for delta in [-1i64, 0, 1] {
        let w = now.wrapping_add_signed(delta);
        if label_mac(psk, tag, client_random, x25519_pub, w)
            .ct_eq(presented)
            .into()
        {
            return true;
        }
    }
    false
}

/// The server's proof, binding the client random, the server random, the
/// server's ephemeral key and the address handed to the client.
#[must_use]
pub fn ack_mac(
    psk: &[u8; KEY_LEN],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    x25519_pub: &[u8; 32],
    assigned_ip: &[u8; 4],
) -> [u8; MAC_LEN] {
    let out = mac(
        psk,
        &[
            b"bproto-ack",
            client_random,
            server_random,
            x25519_pub,
            assigned_ip,
        ],
    );
    let mut m = [0u8; MAC_LEN];
    m.copy_from_slice(&out[..MAC_LEN]);
    m
}

/// Client-side verification of [`ack_mac`]. Constant-time.
#[must_use]
pub fn verify_ack_mac(
    psk: &[u8; KEY_LEN],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    x25519_pub: &[u8; 32],
    assigned_ip: &[u8; 4],
    presented: &[u8],
) -> bool {
    if presented.len() != MAC_LEN {
        return false;
    }
    ack_mac(psk, client_random, server_random, x25519_pub, assigned_ip)
        .ct_eq(presented)
        .into()
}

/// Client side: build the full 32-byte `session_id` label for the TLS path.
#[must_use]
pub fn derive_session_id(
    psk: &[u8; KEY_LEN],
    tag: &[u8; TAG_LEN],
    client_random: &[u8; 32],
    x25519_pub: &[u8; 32],
    unix_secs: u64,
) -> [u8; SESSION_ID_LEN] {
    let mut sid = [0u8; SESSION_ID_LEN];
    sid[..TAG_LEN].copy_from_slice(tag);
    let m = label_mac(psk, tag, client_random, x25519_pub, time_window(unix_secs));
    sid[TAG_LEN..].copy_from_slice(&m);
    sid
}

/// Server side: verify a 32-byte `session_id` label. Constant-time.
#[must_use]
pub fn verify_session_id(
    psk: &[u8; KEY_LEN],
    session_id: &[u8],
    client_random: &[u8; 32],
    x25519_pub: &[u8; 32],
    unix_secs: u64,
) -> bool {
    let Some(tag) = extract_tag(session_id) else {
        return false;
    };
    verify_label_mac(
        psk,
        &tag,
        client_random,
        x25519_pub,
        unix_secs,
        &session_id[TAG_LEN..],
    )
}

/// Extract the routing tag from a session id, if it has the right length.
#[must_use]
pub fn extract_tag(session_id: &[u8]) -> Option<[u8; TAG_LEN]> {
    if session_id.len() != SESSION_ID_LEN {
        return None;
    }
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&session_id[..TAG_LEN]);
    Some(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psk() -> [u8; KEY_LEN] {
        [0x11; KEY_LEN]
    }

    #[test]
    fn tag_is_deterministic_and_user_specific() {
        let k = [0x22u8; KEY_LEN];
        assert_eq!(compute_tag(&k, 1), compute_tag(&k, 1));
        assert_ne!(compute_tag(&k, 1), compute_tag(&k, 2));
    }

    #[test]
    fn derive_and_verify_roundtrip() {
        let p = psk();
        let tag = compute_tag(&[0x33; 32], 7);
        let cr = [0xAB; 32];
        let pubk = [0xCD; 32];
        let now = 1_700_000_000;
        let sid = derive_session_id(&p, &tag, &cr, &pubk, now);
        assert_eq!(sid.len(), SESSION_ID_LEN);
        assert_eq!(extract_tag(&sid), Some(tag));

        assert!(verify_session_id(&p, &sid, &cr, &pubk, now));
        assert!(verify_session_id(&p, &sid, &cr, &pubk, now + WINDOW_SECS));
        assert!(verify_session_id(&p, &sid, &cr, &pubk, now - WINDOW_SECS));
        assert!(!verify_session_id(
            &p,
            &sid,
            &cr,
            &pubk,
            now + 3 * WINDOW_SECS
        ));
    }

    #[test]
    fn rejects_wrong_psk_or_random_sid() {
        let tag = compute_tag(&[0x33; 32], 7);
        let cr = [1u8; 32];
        let pubk = [2u8; 32];
        let sid = derive_session_id(&psk(), &tag, &cr, &pubk, 1000);

        let mut wrong = psk();
        wrong[0] ^= 0xFF;
        assert!(!verify_session_id(&wrong, &sid, &cr, &pubk, 1000));
        assert!(!verify_session_id(&psk(), &[0x5A; 32], &cr, &pubk, 1000));
        assert!(!verify_session_id(&psk(), &[0x5A; 31], &cr, &pubk, 1000));
    }

    #[test]
    fn native_label_mac_matches_session_id_bytes() {
        // the same MAC construction backs both paths
        let p = psk();
        let tag = compute_tag(&[0x33; 32], 9);
        let cr = [7u8; 32];
        let pubk = [9u8; 32];
        let now = 1_800_000_000;
        let sid = derive_session_id(&p, &tag, &cr, &pubk, now);
        assert!(verify_label_mac(&p, &tag, &cr, &pubk, now, &sid[TAG_LEN..]));
        let mut forged = sid[TAG_LEN..].to_vec();
        forged[0] ^= 1;
        assert!(!verify_label_mac(&p, &tag, &cr, &pubk, now, &forged));
    }

    #[test]
    fn ack_mac_binds_the_address() {
        let p = psk();
        let cr = [1u8; 32];
        let sr = [2u8; 32];
        let pubk = [3u8; 32];
        let ip = [10, 66, 0, 2];
        let m = ack_mac(&p, &cr, &sr, &pubk, &ip);
        assert!(verify_ack_mac(&p, &cr, &sr, &pubk, &ip, &m));
        assert!(!verify_ack_mac(&p, &cr, &sr, &pubk, &[10, 66, 0, 3], &m));
        assert!(!verify_ack_mac(&p, &cr, &sr, &pubk, &ip, &m[..23]));
    }
}
