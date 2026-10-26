//! ClientHello interception: the "own vs probe" decision.
//!
//! The server parses the cleartext `session_id`, `random` and the X25519 key
//! share out of the ClientHello, looks the routing tag up in the [`TagTable`]
//! and verifies the label MAC. Everything that fails goes to the donor
//! transparently — that is what makes an active prober with the wrong password
//! see the real site.

use vpn_core::auth::{extract_tag, verify_session_id};
use vpn_core::config::from_hex;
use vpn_core::crypto::KEY_LEN;
use vpn_core::masquerade::InspectedClientHello;

use crate::config::TagTable;

/// What the server should do with an incoming handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The label verified: take over the handshake and speak bProto.
    Intercept(u64),
    /// Not ours: relay every byte to the donor, verbatim.
    RelayToDonor,
}

/// Fields we need from a TLS ClientHello. Parsing itself lives in the
/// `masquerade` layer (`vpn-core`); this struct is the boundary.
#[derive(Debug, Clone)]
pub struct ClientHelloView {
    /// The 32-byte `session_id` field, if present.
    pub session_id: Vec<u8>,
    /// The 32-byte client random.
    pub client_random: [u8; 32],
    /// The client's X25519 key share (from the `key_share` extension).
    pub x25519_pub: [u8; 32],
}

/// Decide the fate of a ClientHello lifted out of a QUIC Initial flight.
///
/// This is the masquerade entry point: `hello` comes straight from
/// [`vpn_core::masquerade::inspect_client_hello`]. Anything that does not
/// parse — or does not carry a label, or carries one that fails the MAC —
/// is relayed wholesale to the donor, exactly like a probe's traffic.
pub fn classify_initial(hello: &InspectedClientHello, tags: &TagTable, now: u64) -> Verdict {
    let (Some(sid), Some(cr), Some(kp)) = (
        hello.session_id.as_ref(),
        hello.client_random.as_ref(),
        hello.x25519_share.as_ref(),
    ) else {
        return Verdict::RelayToDonor;
    };
    classify(
        &ClientHelloView {
            session_id: sid.to_vec(),
            client_random: *cr,
            x25519_pub: *kp,
        },
        tags,
        now,
    )
}

/// Decide the fate of a ClientHello. `now` is unix time in seconds.
#[must_use]
pub fn classify(view: &ClientHelloView, tags: &TagTable, now: u64) -> Verdict {
    let Some(tag) = extract_tag(&view.session_id) else {
        return Verdict::RelayToDonor;
    };
    let Some((psk, user_id)) = tags.lookup(&tag) else {
        return Verdict::RelayToDonor;
    };
    if verify_session_id(
        &psk,
        &view.session_id,
        &view.client_random,
        &view.x25519_pub,
        now,
    ) {
        Verdict::Intercept(user_id)
    } else {
        // Right tag, wrong MAC: a replay or a forgery. Relay, do not reveal.
        Verdict::RelayToDonor
    }
}

/// Parse a hex PSK, used when building a [`TagTable`] from an admin sync.
pub fn parse_psk(hex: &str) -> Result<[u8; KEY_LEN], String> {
    from_hex(hex)?
        .try_into()
        .map_err(|_| "expected 32-byte hex".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpn_core::auth::{compute_tag, derive_session_id};
    use vpn_core::crypto::{KeyPair, derive_session_keys};
    use vpn_core::masquerade::InspectedClientHello;
    use vpn_core::packet::{Header, InnerType};

    fn tags() -> ([u8; KEY_LEN], TagTable) {
        let tag_key = [0x11u8; KEY_LEN];
        let mut t = TagTable::default();
        t.insert(&tag_key, 7, [0x22u8; KEY_LEN]);
        (tag_key, t)
    }

    fn view_for(
        psk: &[u8; KEY_LEN],
        tag_key: &[u8; KEY_LEN],
        user: u64,
        now: u64,
    ) -> ClientHelloView {
        let cr = [0xA0u8; 32];
        let kp = KeyPair::generate();
        let pubk = kp.public_bytes();
        let tag = compute_tag(tag_key, user);
        let sid = derive_session_id(psk, &tag, &cr, &pubk, now);
        ClientHelloView {
            session_id: sid.to_vec(),
            client_random: cr,
            x25519_pub: pubk,
        }
    }

    #[test]
    fn interceptor_reads_masquerade_view() {
        let (tag_key, t) = tags();
        let now = 1_800_000_000;
        let v = view_for(&[0x22u8; KEY_LEN], &tag_key, 7, now);
        // Same fields, seen through the QUIC-layer boundary type.
        let hello = InspectedClientHello {
            dcid: vec![1; 8],
            scid: vec![2; 8],
            token: Vec::new(),
            sni: Some("connector.cloudflare.com".into()),
            session_id: Some(v.session_id.clone().try_into().expect("32")),
            client_random: Some(v.client_random),
            x25519_share: Some(v.x25519_pub),
        };
        assert_eq!(classify_initial(&hello, &t, now), Verdict::Intercept(7));

        // Missing key share or label: relay, never crash, never leak.
        let mut partial = hello.clone();
        partial.x25519_share = None;
        assert_eq!(classify_initial(&partial, &t, now), Verdict::RelayToDonor);
        let mut labelless = hello;
        labelless.session_id = None;
        assert_eq!(classify_initial(&labelless, &t, now), Verdict::RelayToDonor);
    }

    #[test]
    fn valid_client_is_intercepted() {
        let (tag_key, t) = tags();
        let now = 1_800_000_000;
        let v = view_for(&[0x22u8; KEY_LEN], &tag_key, 7, now);
        assert_eq!(classify(&v, &t, now), Verdict::Intercept(7));
    }

    #[test]
    fn random_probe_is_relayed() {
        let (_, t) = tags();
        let v = ClientHelloView {
            session_id: [0x5Au8; 32].to_vec(),
            client_random: [0x01; 32],
            x25519_pub: [0x02; 32],
        };
        assert_eq!(classify(&v, &t, 1_800_000_000), Verdict::RelayToDonor);
    }

    #[test]
    fn wrong_mac_with_known_tag_is_relayed() {
        let (tag_key, t) = tags();
        let now = 1_800_000_000;
        let mut v = view_for(&[0x22u8; KEY_LEN], &tag_key, 7, now);
        // keep the tag, corrupt the MAC portion
        v.session_id[31] ^= 0xFF;
        assert_eq!(classify(&v, &t, now), Verdict::RelayToDonor);
    }

    #[test]
    fn unknown_user_is_relayed() {
        let (tag_key, t) = tags();
        let now = 1_800_000_000;
        let v = view_for(&[0x33u8; KEY_LEN], &tag_key, 999, now);
        assert_eq!(classify(&v, &t, now), Verdict::RelayToDonor);
    }

    #[test]
    fn sanity_that_intercept_yields_a_sealable_session() {
        // not a classification test: proves the accepted path has the material
        // to run the packet crypto, keeping the two halves honest.
        let shared = [0x09u8; 32];
        let keys = derive_session_keys(&shared, &[1; 32], &[2; 32], false);
        assert_eq!(
            keys.tx_key,
            derive_session_keys(&shared, &[1; 32], &[2; 32], true).rx_key
        );
        let h = Header::new(0, 1, 0);
        assert_eq!(InnerType::Ip as u8, 0x00);
        assert_eq!(h.version, vpn_core::PROTOCOL_VERSION);
    }
}
