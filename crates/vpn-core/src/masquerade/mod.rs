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
pub mod initial;
pub mod relay;
pub mod tls;

/// Everything the server learns from the client's first UDP datagrams.
///
/// Produced by [`inspect_client_hello`]; the caller then verifies the
/// `session_id` label through [`crate::auth::verify_session_id`] (tag lookup
/// via [`crate::tags::TagTable`]) and decides: tunnel — or splice the client
/// through to the donor as an ordinary site visitor.
#[derive(Debug, Clone, PartialEq)]
pub struct InspectedClientHello {
    /// Requested connection ID (drives Initial key derivation).
    pub dcid: Vec<u8>,
    /// Client's chosen connection ID.
    pub scid: Vec<u8>,
    /// Client's stateless-retry bearer token (empty without a retry).
    pub token: Vec<u8>,
    /// Requested donor site (SNI).
    pub sni: Option<String>,
    /// The 32-byte authentication label carried as `legacy_session_id`.
    pub session_id: Option<[u8; crate::auth::SESSION_ID_LEN]>,
    /// Label MAC input: the handshake `random`.
    pub client_random: Option<[u8; 32]>,
    /// Label MAC input: the offered X25519 `key_share`, if present.
    pub x25519_share: Option<[u8; 32]>,
}

/// Decrypt the client's Initial packets and lift the masquerade label out of
/// the CRYPTO stream.
///
/// Errors: [`Error::Decrypt`] if the first packet fails AEAD (forged data);
/// [`Error::Handshake`] if the packets do not (yet) contain a parseable
/// ClientHello. Note that a straggling client may still be building its hello
/// across datagrams — the caller should retry with more datagrams rather than
/// treat [`Error::Handshake`] as fatal.
pub fn inspect_client_hello(dgram: &[u8]) -> Result<InspectedClientHello> {
    let flight = initial::inspect_datagram(dgram)?;
    let stream = flight
        .crypto_stream()
        .ok_or(Error::Handshake("CRYPTO stream has a hole"))?;
    let hello = tls::parse_handshake(&stream)
        .client_hello
        .ok_or(Error::Handshake("no ClientHello in the CRYPTO stream"))?;
    let session_id = if hello.session_id.len() == crate::auth::SESSION_ID_LEN {
        let mut sid = [0u8; crate::auth::SESSION_ID_LEN];
        sid.copy_from_slice(&hello.session_id);
        Some(sid)
    } else {
        None
    };
    Ok(InspectedClientHello {
        dcid: flight
            .packets
            .first()
            .map(|p| p.dcid.clone())
            .unwrap_or_default(),
        scid: flight
            .packets
            .first()
            .map(|p| p.scid.clone())
            .unwrap_or_default(),
        token: flight
            .packets
            .first()
            .map(|p| p.token.clone())
            .unwrap_or_default(),
        sni: hello.sni,
        session_id,
        client_random: Some(hello.random),
        x25519_share: hello.x25519_share,
    })
}

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
    /// The 32-byte client random (also carried in the native HELLO).
    pub client_random: [u8; 32],
    /// The client's ephemeral X25519 public key (also carried in the HELLO).
    pub x25519_pub: [u8; 32],
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
/// Stage 2: the ClientHello is hand-crafted in the Chrome uTLS shape
/// ([`hello::build`]) with the 32-byte auth label in `session_id`; the QUIC
/// Initial wrapper lives in [`craft_initial_flight`]. `craftls` vendoring
/// (`crates/craftls/PATCH.md`) remains the plan for a full per-version parrot.
pub fn craft_client_hello(params: &HelloParams) -> Result<CraftedHello> {
    let handshake = hello::build(params)?;
    Ok(CraftedHello {
        handshake,
        client_random: params.client_random,
        x25519_pub: params.x25519_pub,
    })
}

/// Build the client's opening flight: a real, decryptable QUIC v1 Initial
/// carrying the labeled ClientHello, padded to `initial_size` bytes.
///
/// The server classifies it via [`inspect_client_hello`] + `interceptor` and
/// lets the native handshake follow; a passive observer sees a genuine browser
/// QUIC Initial. Errors: [`Error::Config`] when `initial_size` cannot fit the
/// ClientHello.
pub fn craft_initial_flight(params: &HelloParams, initial_size: usize) -> Result<Vec<u8>> {
    let handshake = hello::build(params)?;
    let mut dcid = [0u8; 8];
    crate::crypto::fill_random(&mut dcid);
    let frame = initial::crypto_frame(0, &handshake);
    initial::craft_flight(&dcid, &[], &[], 0, 4, &frame, initial_size)
}

#[cfg(test)]
mod tests {
    use super::Error;
    use super::HelloParams;
    use super::craft_initial_flight;
    use super::inspect_client_hello;
    use crate::auth::{compute_tag, extract_tag, verify_session_id};
    use crate::crypto::KEY_LEN;
    use crate::masquerade::hello::ClientSecrets;
    use crate::masquerade::initial::testkit;
    use crate::masquerade::tls::testkit as tlstk;
    use crate::masquerade::tls::testkit::HelloMaterial;
    use crate::unix_now_secs;

    /// Whole-stack acceptance: a sealed QUIC Initial carrying a real
    /// ClientHello with a genuine session_id label parses out to exactly the
    /// fields the label MAC needs. This is the data the server feeds
    /// `verify_session_id` — and the shape the interceptor exercises.
    #[test]
    fn labeled_initial_survives_the_stack() {
        let (psk, tag_key, user) = ([0x22u8; KEY_LEN], [0x11u8; KEY_LEN], 7);
        let secrets = ClientSecrets::generate();
        let tag = compute_tag(&tag_key, user);
        let now = unix_now_secs();
        let session_id = secrets.session_id(&psk, &tag, now);

        let hello = tlstk::hello_message(&HelloMaterial {
            random: &secrets.client_random,
            session_id: &session_id,
            x25519: &secrets.ephemeral.public_bytes(),
            sni: "connector.cloudflare.com",
        });
        let dgram = testkit::seal_and_protect(
            &[0x42u8; 8],
            &[0x43u8; 4],
            &[],
            0,
            4,
            &testkit::crypto_frame(&hello),
        );

        let inspected = inspect_client_hello(&dgram).expect("stack parses");
        assert_eq!(inspected.dcid, vec![0x42u8; 8]);
        assert_eq!(inspected.scid, vec![0x43u8; 4]);
        assert_eq!(inspected.sni.as_deref(), Some("connector.cloudflare.com"));
        assert_eq!(inspected.session_id, Some(session_id));
        assert_eq!(inspected.client_random, Some(secrets.client_random));
        assert_eq!(
            inspected.x25519_share,
            Some(secrets.ephemeral.public_bytes())
        );

        // The label verifies — the same call `interceptor::classify` makes.
        let tag2 = extract_tag(&session_id).expect("tag");
        assert_eq!(tag2, tag);
        assert!(verify_session_id(
            &psk,
            &session_id,
            &secrets.client_random,
            &secrets.ephemeral.public_bytes(),
            now
        ));
    }

    #[test]
    fn uninhabited_hello_fails_cleanly() {
        // A labeled flight's crypto that is not a TLS message yields the
        // handshake error, not a phantom labele.
        let dgram = testkit::seal_and_protect(
            &[0x42u8; 8],
            &[],
            &[],
            5,
            4,
            &testkit::crypto_frame(&[0xEE; 8]),
        );
        match inspect_client_hello(&dgram) {
            Err(Error::Handshake(_)) => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    /// The production craft path: `craft_initial_flight` produces a datagram
    /// that is a genuine QUIC v1 Initial, decryptable by the server-side
    /// inspector, whose ClientHello label verifies against the tag table —
    /// with a *browser-shaped* hello (Chrome cipher/extension order, GREASE).
    #[test]
    fn crafted_initial_is_a_real_labeled_flight() {
        use crate::auth::{extract_tag, verify_session_id};
        use crate::crypto::KEY_LEN;

        let (psk, tag_key, user) = ([0x22u8; KEY_LEN], [0x11u8; KEY_LEN], 7);
        let tag = compute_tag(&tag_key, user);
        let now = unix_now_secs();
        let client_random = crate::crypto::random_32();
        let eph = crate::crypto::KeyPair::generate();
        let x25519 = eph.public_bytes();

        let params = HelloParams {
            sni: "tesla.com".into(),
            alpn: vec!["h3".into()],
            fingerprint: crate::config::Fingerprint::Chrome112,
            session_id: crate::auth::derive_session_id(&psk, &tag, &client_random, &x25519, now),
            client_random,
            x25519_pub: x25519,
        };
        let dgram = craft_initial_flight(&params, 1252).expect("craft");

        // Chrome sizes its Initial datagrams to 1252 B with PADDING.
        assert_eq!(dgram.len(), 1252);
        // Long header, version 1, zero-length source CID (Chrome shape).
        assert_eq!(dgram[0] & 0xC0, 0xC0);
        assert_eq!(&dgram[1..5], &1u32.to_be_bytes());

        let inspected = inspect_client_hello(&dgram).expect("server parses the flight");
        assert_eq!(inspected.sni.as_deref(), Some("tesla.com"));
        assert_eq!(inspected.client_random, Some(client_random));
        assert_eq!(inspected.x25519_share, Some(x25519));
        let sid = inspected.session_id.expect("label present");
        assert_eq!(extract_tag(&sid).expect("tag"), tag);
        assert!(verify_session_id(&psk, &sid, &client_random, &x25519, now));

        // The hello is also browser-shaped at the TLS layer: GREASE cipher
        // suite first, ALPN h3, padded ClientHello ≥ 500 B of extensions.
        assert!(inspected.scid.is_empty(), "Chrome sends a zero-length SCID");
    }
}
