//! The bProto handshake.
//!
//! The exchange is three datagrams, all of them plaintext control frames
//! ([`crate::packet::FLAG_CONTROL`] set, no AEAD — there is no key yet):
//!
//! ```text
//!   client                                   server
//!   ------                                   ------
//!   HELLO{tag, cr, x25519, window, mac}  ->
//!                                        <-  HELLO_ACK{cr, sr, x25519, ip, mac}
//!   (both derive: shared = X25519, tag = HKDF, keys = HKDF)
//! ```
//!
//! Both MACs are over the pre-shared key issued by the panel, so an active prober
//! without the key cannot complete the exchange and — in the masquerade build —
//! is relayed to the donor instead (see `masquerade`). This module is pure: it
//! builds and verifies bytes; the socket lives in [`crate::session::Tunnel`].
//!
//! Replay: the label MAC covers a coarse time window (300 s, ±1 window accepted),
//! and the server treats a repeated `(tag, client_random)` as a retransmit of the
//! same handshake and answers idempotently. The session tag derived afterwards is
//! bound to both randoms, so a captured HELLO cannot hijack a live session.

use std::net::Ipv4Addr;

use crate::auth::{self, TAG_LEN};
use crate::config::TunnelConfig;
use crate::crypto::{self, KEY_LEN, KeyPair, SessionKeys};
use crate::error::{Error, Result};
use crate::frame::{Hello, HelloAck};
use crate::packet;
use crate::tags::TagTable;

/// Client state kept between `HELLO` and `HELLO_ACK`.
#[derive(Debug)]
pub struct ClientHandshake {
    eph: KeyPair,
    client_random: [u8; 32],
    psk: [u8; KEY_LEN],
    /// Sent to the server; kept so a retransmit is byte-identical.
    datagram: Vec<u8>,
}

impl ClientHandshake {
    /// The datagram to (re)send until a `HELLO_ACK` arrives.
    #[must_use]
    pub fn datagram(&self) -> &[u8] {
        &self.datagram
    }

    /// The client random, for logging.
    #[must_use]
    pub fn client_random(&self) -> &[u8; 32] {
        &self.client_random
    }
}

/// Result of a successful client handshake.
#[derive(Debug)]
pub struct ClientEstablished {
    /// Directional traffic keys.
    pub keys: SessionKeys,
    /// The header routing tag both peers will use.
    pub session_tag: u32,
    /// Address the server leased to this client.
    pub assigned_ip: Ipv4Addr,
}

/// Start the client handshake: generate the ephemeral key and build `HELLO`.
pub fn start(cfg: &TunnelConfig, now_unix_secs: u64) -> Result<(ClientHandshake, Vec<u8>)> {
    let eph = KeyPair::generate();
    let client_random = crypto::random_32();
    let tag = auth::compute_tag(&cfg.tag_key, cfg.user_id);
    let window = auth::time_window(now_unix_secs);
    let x25519_pub = eph.public_bytes();
    let mac = auth::label_mac(&cfg.psk, &tag, &client_random, &x25519_pub, window);

    let hello = Hello {
        tag,
        client_random,
        x25519_pub,
        window,
        mac,
    };
    // The header's session_tag field is unused before the handshake completes;
    // the frame carries the routing tag.
    let datagram = packet::encode_plaintext_control(0, 0, &hello.encode());

    Ok((
        ClientHandshake {
            eph,
            client_random,
            psk: cfg.psk,
            datagram: datagram.clone(),
        },
        datagram,
    ))
}

/// Finish the client handshake from a received `HELLO_ACK` datagram.
pub fn finish(state: &ClientHandshake, ack_datagram: &[u8]) -> Result<ClientEstablished> {
    let (_header, frame) = packet::decode_plaintext_control(ack_datagram)?;
    let ack = HelloAck::decode(frame)?;

    if ack.client_random != state.client_random {
        // Bound to *this* exchange: a replayed ACK from another session fails.
        return Err(Error::BadLabel);
    }
    if !auth::verify_ack_mac(
        &state.psk,
        &state.client_random,
        &ack.server_random,
        &ack.x25519_pub,
        &ack.assigned_ip,
        &ack.mac,
    ) {
        return Err(Error::BadLabel);
    }

    let shared = state.eph.diffie_hellman(&ack.x25519_pub);
    let keys = crypto::derive_session_keys(&shared, &state.client_random, &ack.server_random, true);
    let session_tag = crypto::derive_session_tag(&shared, &state.client_random, &ack.server_random);
    Ok(ClientEstablished {
        keys,
        session_tag,
        assigned_ip: Ipv4Addr::from(ack.assigned_ip),
    })
}

/// A verified `HELLO`.
#[derive(Debug, Clone)]
pub struct VerifiedHello {
    /// The user's PSK.
    pub psk: [u8; KEY_LEN],
    /// The panel user id.
    pub user_id: u64,
    /// The routing tag presented.
    pub tag: [u8; TAG_LEN],
    /// Client random.
    pub client_random: [u8; 32],
    /// Client ephemeral public key.
    pub x25519_pub: [u8; 32],
}

/// Verify a `HELLO` datagram against the tag table. `now_unix_secs` is server
/// wall-clock time; skew of ±1 window (5 minutes) is tolerated.
pub fn verify(tags: &TagTable, hello_datagram: &[u8], now_unix_secs: u64) -> Result<VerifiedHello> {
    let (_header, frame) = packet::decode_plaintext_control(hello_datagram)?;
    let hello = Hello::decode(frame)?;

    let (psk, user_id) = tags.lookup(&hello.tag).ok_or(Error::BadLabel)?;
    if !auth::verify_label_mac(
        &psk,
        &hello.tag,
        &hello.client_random,
        &hello.x25519_pub,
        now_unix_secs,
        &hello.mac,
    ) {
        return Err(Error::BadLabel);
    }
    Ok(VerifiedHello {
        psk,
        user_id,
        tag: hello.tag,
        client_random: hello.client_random,
        x25519_pub: hello.x25519_pub,
    })
}

/// Build the `HELLO_ACK` for a verified client and derive the server-side keys.
pub fn respond(
    verified: &VerifiedHello,
    server_eph: &KeyPair,
    assigned_ip: Ipv4Addr,
) -> Result<(Vec<u8>, SessionKeys, u32)> {
    let server_random = crypto::random_32();
    let x25519_pub = server_eph.public_bytes();
    let ip_bytes = assigned_ip.octets();
    let mac = auth::ack_mac(
        &verified.psk,
        &verified.client_random,
        &server_random,
        &x25519_pub,
        &ip_bytes,
    );
    let ack = HelloAck {
        client_random: verified.client_random,
        server_random,
        x25519_pub,
        assigned_ip: ip_bytes,
        mac,
    };
    let datagram = packet::encode_plaintext_control(0, 0, &ack.encode());

    let shared = server_eph.diffie_hellman(&verified.x25519_pub);
    let keys = crypto::derive_session_keys(&shared, &verified.client_random, &server_random, false);
    let session_tag = crypto::derive_session_tag(&shared, &verified.client_random, &server_random);
    Ok((datagram, keys, session_tag))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::compute_tag;
    use crate::packet::FLAG_CONTROL;

    const NOW: u64 = 1_800_000_000;

    fn cfg() -> TunnelConfig {
        TunnelConfig {
            server: "127.0.0.1:443".parse().unwrap(),
            donor: crate::DonorSpec::default(),
            psk: [0x11; 32],
            user_id: 42,
            tag_key: [0x22; 32],
            mtu: 1280,
            fingerprint: crate::HelloProfile::Chrome120,
            masquerade: false,
            handshake_timeout: std::time::Duration::from_secs(10),
        }
    }

    fn table() -> TagTable {
        let mut t = TagTable::new();
        t.insert(&[0x22; 32], 42, [0x11; 32]);
        t
    }

    #[test]
    fn happy_path_derives_mirrored_keys_and_one_tag() {
        let c = cfg();
        let (state, hello) = start(&c, NOW).unwrap();
        assert_eq!(hello[0] >> 4, crate::PROTOCOL_VERSION);
        assert!(crate::packet::Header::decode(&hello).unwrap().is_control());
        assert_eq!(hello[0] & 0x0F, FLAG_CONTROL);

        let verified = verify(&table(), &hello, NOW).unwrap();
        assert_eq!(verified.user_id, 42);
        assert_eq!(verified.tag, compute_tag(&[0x22; 32], 42));

        let server_eph = KeyPair::generate();
        let assigned = Ipv4Addr::new(10, 66, 0, 2);
        let (ack, server_keys, server_tag) = respond(&verified, &server_eph, assigned).unwrap();

        let est = finish(&state, &ack).unwrap();
        assert_eq!(est.assigned_ip, assigned);
        assert_eq!(est.session_tag, server_tag);
        // client tx key must equal server rx key
        assert_eq!(est.keys.tx_key, server_keys.rx_key);
        assert_eq!(est.keys.rx_key, server_keys.tx_key);
    }

    #[test]
    fn wrong_psk_is_rejected() {
        let mut c = cfg();
        c.psk = [0x99; 32];
        let (_state, hello) = start(&c, NOW).unwrap();
        assert!(matches!(
            verify(&table(), &hello, NOW),
            Err(Error::BadLabel)
        ));
    }

    #[test]
    fn unknown_user_is_rejected() {
        let mut c = cfg();
        c.user_id = 999; // tag not in the table
        let (_state, hello) = start(&c, NOW).unwrap();
        assert!(matches!(
            verify(&table(), &hello, NOW),
            Err(Error::BadLabel)
        ));
    }

    #[test]
    fn stale_hello_outside_the_window_is_rejected() {
        let c = cfg();
        let (_state, hello) = start(&c, NOW).unwrap();
        // three windows (15 minutes) in the future
        assert!(matches!(
            verify(&table(), &hello, NOW + 3 * auth::WINDOW_SECS),
            Err(Error::BadLabel)
        ));
        // one window of skew is tolerated
        assert!(verify(&table(), &hello, NOW + auth::WINDOW_SECS).is_ok());
    }

    #[test]
    fn tampered_ack_is_rejected() {
        let c = cfg();
        let (state, hello) = start(&c, NOW).unwrap();
        let verified = verify(&table(), &hello, NOW).unwrap();
        let server_eph = KeyPair::generate();
        let (ack, _k, _t) = respond(&verified, &server_eph, Ipv4Addr::new(10, 66, 0, 2)).unwrap();

        // flip a byte inside the assigned-address field (offset 12 + 97)
        let mut bad = ack.clone();
        bad[12 + 97] ^= 0x01;
        assert!(matches!(finish(&state, &bad), Err(Error::BadLabel)));
    }

    #[test]
    fn an_ack_for_another_client_random_is_rejected() {
        let c = cfg();
        let (state_a, _a) = start(&c, NOW).unwrap();
        let (_state_b, hello_b) = start(&c, NOW).unwrap();
        let verified = verify(&table(), &hello_b, NOW).unwrap();
        let server_eph = KeyPair::generate();
        let (ack_b, _k, _t) = respond(&verified, &server_eph, Ipv4Addr::new(10, 66, 0, 2)).unwrap();
        assert!(matches!(finish(&state_a, &ack_b), Err(Error::BadLabel)));
    }
}
