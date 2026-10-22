//! Deciding “our client” from “someone else’s”, the only decision that matters.
//!
//! The server sits on a port that is supposed to look like an ordinary QUIC/HTTP-3
//! endpoint for the donor site. Every inbound handshake therefore gets exactly
//! one of two fates, and the *only* input to that decision is the
//! [`crate::auth`] label carried in `ClientHello.session_id`:
//!
//! * [`Verdict::Intercept`] – the label verified. We know which user this is and
//!   can serve them.
//! * [`Verdict::RelayToDonor`] – the label is absent, malformed, unknown or
//!   forged. The bytes are forwarded to the donor verbatim, so whoever sent them
//!   completes a genuine handshake with the donor and receives the donor's real
//!   certificate. **This is the property the whole design exists for**: an active
//!   prober — a censor scanning with a real TLS/QUIC stack and no valid key —
//!   cannot tell our server from the site it is impersonating.
//!
//! A failed verification and a missing verification must be indistinguishable
//! from the outside, so both return the same verdict.

use crate::auth;
use crate::config::TunnelConfig;
use crate::crypto::KEY_LEN;
use crate::handshake::VerifiedHello;
use crate::hello::{BROWSER_SESSION_ID_LEN, ClientHello, ClientHelloBuilder, HelloProfile};
use crate::packet::MAX_DATAGRAM;
use crate::tags::TagTable;

/// What the server should do with an inbound handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The label verified: serve this client. Carries everything the server
    /// needs to answer, so the identity is looked up exactly once.
    Intercept(VerifiedHello),
    /// Not ours: forward the bytes to the donor untouched.
    RelayToDonor,
}

/// Largest `ClientHello` we will parse before treating the sender as hostile.
///
/// A real browser `ClientHello` is a few hundred bytes; a 64 KiB one is either a
/// broken peer or someone trying to make us allocate.
pub const MAX_CLIENT_HELLO: usize = MAX_DATAGRAM;

/// Classify one `ClientHello` against the tag table.
///
/// `now_unix_secs` is server wall-clock time; a skew of ±1 window (5 minutes) is
/// tolerated, matching the native handshake.
///
/// The MAC covers the client random *and* the X25519 key share, both read out of
/// the hello itself — nothing the client asserts in another field is trusted.
#[must_use]
pub fn classify(hello: &ClientHello, tags: &TagTable, now_unix_secs: u64) -> Verdict {
    let Some(label) = hello.session_id_label() else {
        return Verdict::RelayToDonor;
    };
    let Some(x25519_pub) = hello.x25519_key_share() else {
        return Verdict::RelayToDonor;
    };
    let Ok(tag) = label[..auth::TAG_LEN].try_into() else {
        return Verdict::RelayToDonor;
    };
    let Some((psk, user_id)) = tags.lookup(&tag) else {
        return Verdict::RelayToDonor;
    };
    if !auth::verify_label_mac(
        &psk,
        &tag,
        &hello.random,
        &x25519_pub,
        now_unix_secs,
        &label[auth::TAG_LEN..],
    ) {
        return Verdict::RelayToDonor;
    }
    Verdict::Intercept(VerifiedHello {
        psk,
        user_id,
        tag,
        client_random: hello.random,
        x25519_pub,
    })
}

/// The 32-byte label this client puts in `session_id`.
///
/// It is exactly as long as the random session id a browser sends, and every
/// byte of it is bound to the PSK, the client random, the ephemeral key and a
/// 5-minute time window.
#[must_use]
pub fn client_label(
    cfg: &TunnelConfig,
    client_random: &[u8; 32],
    x25519_pub: &[u8; 32],
    now_unix_secs: u64,
) -> [u8; BROWSER_SESSION_ID_LEN] {
    let tag = auth::compute_tag(&cfg.tag_key, cfg.user_id);
    let window = auth::time_window(now_unix_secs);
    let mut label = [0u8; BROWSER_SESSION_ID_LEN];
    label[..auth::TAG_LEN].copy_from_slice(&tag);
    label[auth::TAG_LEN..].copy_from_slice(&auth::label_mac(
        &cfg.psk,
        &tag,
        client_random,
        x25519_pub,
        window,
    ));
    label
}

/// Build the masquerade `ClientHello` for one connection attempt.
///
/// The result is a complete TLS record carrying a browser-shaped `ClientHello`
/// with our label in `session_id`. Its length depends on neither the label, the
/// user nor the time — see the length test in [`crate::hello`].
#[must_use]
pub fn craft_client_hello(
    cfg: &TunnelConfig,
    profile: HelloProfile,
    client_random: [u8; 32],
    x25519_pub: [u8; 32],
    now_unix_secs: u64,
) -> Vec<u8> {
    let label = client_label(cfg, &client_random, &x25519_pub, now_unix_secs);
    ClientHelloBuilder::new(profile)
        .sni(cfg.donor.sni.clone())
        .alpn(cfg.donor.alpn.clone())
        .random(client_random)
        .key_share(x25519_pub)
        .session_id(label)
        .build()
}

/// Try to read an inbound blob as a `ClientHello`.
///
/// Returns `None` for anything that is not one; the caller relays those bytes
/// untouched.
#[must_use]
pub fn try_parse(bytes: &[u8]) -> Option<ClientHello> {
    if bytes.len() > MAX_CLIENT_HELLO {
        return None;
    }
    ClientHello::parse(bytes).ok()
}

/// Classify raw bytes, returning `None` when they cannot be parsed as a
/// `ClientHello` at all.
#[must_use]
pub fn classify_bytes(
    bytes: &[u8],
    tags: &TagTable,
    now_unix_secs: u64,
) -> Option<(Verdict, ClientHello)> {
    let hello = try_parse(bytes)?;
    Some((classify(&hello, tags, now_unix_secs), hello))
}

/// A PSK presented by the control panel, parsed from hex.
#[must_use]
pub fn parse_psk(hex: &str) -> Option<[u8; KEY_LEN]> {
    crate::config::from_hex(hex)
        .ok()
        .and_then(|v| v.try_into().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DonorSpec;
    use crate::crypto::KeyPair;

    const NOW: u64 = 1_800_000_000;

    fn table() -> TagTable {
        let mut t = TagTable::new();
        t.insert(&[0x22; KEY_LEN], 42, [0x11; KEY_LEN]);
        t
    }

    fn cfg() -> TunnelConfig {
        TunnelConfig {
            server: "127.0.0.1:443".parse().unwrap(),
            donor: DonorSpec::default(),
            psk: [0x11; KEY_LEN],
            user_id: 42,
            tag_key: [0x22; KEY_LEN],
            mtu: 1280,
            fingerprint: HelloProfile::Chrome120,
            masquerade: false,
            handshake_timeout: std::time::Duration::from_secs(10),
        }
    }

    /// The user id an intercepted hello was verified as.
    fn intercepted(verdict: Verdict) -> Option<u64> {
        match verdict {
            Verdict::Intercept(v) => Some(v.user_id),
            Verdict::RelayToDonor => None,
        }
    }

    fn hello_with(label: [u8; BROWSER_SESSION_ID_LEN], random: [u8; 32]) -> ClientHello {
        let bytes = ClientHelloBuilder::new(HelloProfile::Chrome120)
            .sni("www.cloudflare.com")
            .random(random)
            .key_share([0x22; 32])
            .session_id(label)
            .build();
        ClientHello::parse(&bytes).expect("our own hello must parse")
    }

    #[test]
    fn a_valid_label_is_intercepted_for_its_user() {
        let cr = [0x0A; 32];
        let label = client_label(&cfg(), &cr, &[0x22; 32], NOW);
        assert_eq!(
            intercepted(classify(&hello_with(label, cr), &table(), NOW)),
            Some(42)
        );
    }

    #[test]
    fn one_window_of_skew_is_tolerated() {
        let cr = [0x0B; 32];
        let label = client_label(&cfg(), &cr, &[0x22; 32], NOW);
        let hello = hello_with(label, cr);
        assert_eq!(
            intercepted(classify(&hello, &table(), NOW + auth::WINDOW_SECS)),
            Some(42)
        );
        assert_eq!(
            classify(&hello, &table(), NOW + 3 * auth::WINDOW_SECS),
            Verdict::RelayToDonor
        );
    }

    #[test]
    fn a_probe_gets_the_donor() {
        // A real browser's hello: 32 random bytes where our label would be.
        let bytes = ClientHelloBuilder::new(HelloProfile::Firefox121)
            .sni("www.cloudflare.com")
            .alpn(vec!["h3".into()])
            .random([0x01; 32])
            .key_share([0x44; 32])
            .session_id([0xC3; 32])
            .build();
        let hello = ClientHello::parse(&bytes).unwrap();
        assert_eq!(classify(&hello, &table(), NOW), Verdict::RelayToDonor);
    }

    #[test]
    fn a_hello_without_a_key_share_is_relayed() {
        let bytes = ClientHelloBuilder::new(HelloProfile::Safari17)
            .sni("www.cloudflare.com")
            .random([0x02; 32])
            .session_id(client_label(&cfg(), &[0x02; 32], &[0x22; 32], NOW))
            .build();
        let hello = ClientHello::parse(&bytes).unwrap();
        assert!(hello.x25519_key_share().is_none());
        assert_eq!(classify(&hello, &table(), NOW), Verdict::RelayToDonor);
    }

    #[test]
    fn the_right_tag_with_the_wrong_mac_is_also_relayed() {
        let cr = [0x0C; 32];
        let mut label = client_label(&cfg(), &cr, &[0x22; 32], NOW);
        label[auth::TAG_LEN] ^= 0x01; // flip a byte inside the MAC
        assert_eq!(
            classify(&hello_with(label, cr), &table(), NOW),
            Verdict::RelayToDonor
        );
    }

    #[test]
    fn a_label_bound_to_another_key_share_does_not_verify() {
        // Same user, same PSK, but the MAC covered a different ephemeral key.
        let cr = [0x0F; 32];
        let label = client_label(&cfg(), &cr, &[0x99; 32], NOW);
        let bytes = ClientHelloBuilder::new(HelloProfile::Chrome120)
            .random(cr)
            .key_share([0x22; 32])
            .session_id(label)
            .build();
        let hello = ClientHello::parse(&bytes).unwrap();
        assert_eq!(classify(&hello, &table(), NOW), Verdict::RelayToDonor);
    }

    #[test]
    fn an_unknown_user_is_relayed() {
        let mut c = cfg();
        c.user_id = 999;
        let cr = [0x0D; 32];
        let label = client_label(&c, &cr, &[0x22; 32], NOW);
        assert_eq!(
            classify(&hello_with(label, cr), &table(), NOW),
            Verdict::RelayToDonor
        );
    }

    #[test]
    fn garbage_and_oversized_input_relays_rather_than_errors() {
        assert!(try_parse(&[0x00; 8]).is_none());
        assert!(try_parse(&vec![0x16; MAX_CLIENT_HELLO + 1]).is_none());
        assert!(classify_bytes(&[0x00; 8], &table(), NOW).is_none());
    }

    #[test]
    fn what_we_build_we_recognise() {
        let cr = [0x0E; 32];
        let eph = KeyPair::generate();
        let bytes =
            craft_client_hello(&cfg(), HelloProfile::Chrome120, cr, eph.public_bytes(), NOW);
        let hello = ClientHello::parse(&bytes).unwrap();
        assert_eq!(hello.sni(), Some("www.cloudflare.com"));
        assert_eq!(hello.alpn(), vec!["h3".to_string()]);
        assert_eq!(hello.x25519_key_share(), Some(eph.public_bytes()));
        assert_eq!(intercepted(classify(&hello, &table(), NOW)), Some(42));
    }

    #[test]
    fn psk_parsing_rejects_anything_but_32_bytes() {
        assert!(parse_psk(&"11".repeat(32)).is_some());
        assert!(parse_psk("abcd").is_none());
        assert!(parse_psk("zz").is_none());
    }
}
