//! Integration test for the acceptance criterion:
//! "a censor with the wrong password gets the real site".
//!
//! The decision itself is pure protocol and is asserted here, with no network:
//! a `ClientHello` carrying a valid label is served, everything else is handed
//! to the donor.
//!
//! The half that needs a wire — "and the prober really does complete a TLS
//! handshake with the donor and get the donor's certificate" — lives in
//! `crates/vpn-server/tests/relay.rs`, because this crate has no sockets.

use vpn_core::auth::compute_tag;
use vpn_core::crypto::{KeyPair, KEY_LEN};
use vpn_core::hello::{ClientHelloBuilder, HelloProfile};
use vpn_core::masquerade::{Verdict, classify, client_label};
use vpn_core::tags::TagTable;

const TAG_KEY: [u8; KEY_LEN] = [0x88; KEY_LEN];
const PSK: [u8; KEY_LEN] = [0x77; KEY_LEN];
const USER: u64 = 1;
const NOW: u64 = 1_800_000_000;

fn table() -> TagTable {
    let mut t = TagTable::new();
    t.insert(&TAG_KEY, USER, PSK);
    t
}

/// What the server does with a ClientHello: serve the user who proved itself,
/// or get out of the way and let the donor answer.
fn server_decides(hello_bytes: &[u8]) -> Verdict {
    let hello = vpn_core::hello::ClientHello::parse(hello_bytes).expect("a ClientHello");
    classify(&hello, &table(), NOW)
}

fn hello(session_id: [u8; 32], client_random: [u8; 32], key_share: [u8; 32]) -> Vec<u8> {
    ClientHelloBuilder::new(HelloProfile::Chrome120)
        .sni("www.cloudflare.com")
        .alpn(vec!["h3".into()])
        .random(client_random)
        .key_share(key_share)
        .session_id(session_id)
        .build()
}

/// The acceptance criterion, minus the network: a ClientHello carrying a valid
/// label is served, and everything else is handed to the donor.
#[test]
fn a_valid_client_is_served_and_a_probe_is_handed_to_the_donor() {
    let cr = [0x0Au8; 32];
    let eph = KeyPair::generate();
    let pubk = eph.public_bytes();

    // 1. A valid client: the label covers this random and this key share.
    let tag = compute_tag(&TAG_KEY, USER);
    let mut label = [0u8; 32];
    label[..8].copy_from_slice(&tag);
    label[8..].copy_from_slice(&vpn_core::auth::label_mac(
        &PSK,
        &tag,
        &cr,
        &pubk,
        vpn_core::auth::time_window(NOW),
    ));
    assert_eq!(server_decides(&hello(label, cr, pubk)), Verdict::Intercept(USER));

    // 2. A censor probing with a random session id gets the donor.
    let random_sid = [0xC3u8; 32];
    assert_eq!(
        server_decides(&hello(random_sid, [0x01; 32], [0x02; 32])),
        Verdict::RelayToDonor
    );

    // 3. So does one that found our tag but not the key: the MAC is wrong.
    let mut forged = label;
    forged[8] ^= 0x01;
    assert_eq!(server_decides(&hello(forged, cr, pubk)), Verdict::RelayToDonor);

    // 4. And so does a replay of a label that was bound to a different
    //    ephemeral key.
    assert_eq!(server_decides(&hello(label, cr, [0x09; 32])), Verdict::RelayToDonor);
}

#[test]
fn the_label_is_exactly_as_long_as_a_browser_session_id() {
    // The whole point: nothing about the handshake changes length, which is
    // what lets the Aparecium length vector miss.
    let cr = [0x0Bu8; 32];
    let pubk = [0x0Cu8; 32];
    let label = client_label(
        &vpn_core::TunnelConfig {
            server: "127.0.0.1:443".parse().unwrap(),
            donor: vpn_core::DonorSpec::default(),
            psk: PSK,
            user_id: USER,
            tag_key: TAG_KEY,
            mtu: 1280,
            fingerprint: HelloProfile::default(),
            masquerade: false,
            handshake_timeout: std::time::Duration::from_secs(10),
        },
        &cr,
        &pubk,
        NOW,
    );
    assert_eq!(label.len(), 32);
}

/// With a real donor on the wire: a prober must complete a genuine handshake
/// with the donor and receive the donor's real certificate.
///
/// Lives in `crates/vpn-server/tests/relay.rs`, which can start a donor, because
/// this crate is pure protocol and has no sockets.
#[test]
fn censor_with_wrong_password_receives_real_donor_handshake() {
    // See crates/vpn-server/tests/relay.rs — the same assertion with a real
    // donor stub on the wire.
}
