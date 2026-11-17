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

/// Build the ClientHello for a session.
///
/// This is a hand-serialized Chrome-parrot ClientHello (uTLS-style template):
/// Chrome's cipher-suite and extension ordering with GREASE values, X25519
/// key share, `h2`/`h3`-era ALPN and TLS 1.3 supported_versions. The 32-byte
/// authentication label rides in `legacy_session_id` — exactly where browsers
/// carry 32 random bytes, so the length and position of every field matches a
/// real browser hello. The QUIC datagram is padded with PADDING frames
/// elsewhere (`initial::craft_flight`), matching BoringSSL's datagram padding.
///
/// The template is verified against this crate's independent
/// [`super::tls::parse_handshake`] in tests, and against the full-stack
/// `inspect_client_hello` path.
pub fn build(params: &HelloParams) -> Result<Vec<u8>> {
    if params.sni.is_empty() {
        return Err(Error::Config("masquerade sni is empty".into()));
    }
    let alpn: Vec<&str> = if params.alpn.is_empty() {
        vec!["h3"]
    } else {
        params.alpn.iter().map(String::as_str).collect()
    };

    // --- extensions, in Chrome order -----------------------------------
    let mut exts = Vec::new();

    // GREASE extension (0x0a0a), one GREASE byte.
    exts.push(ext(0x0a0a, &[0x00]));
    // server_name (0x0000).
    let name = params.sni.as_bytes();
    let mut sni_list = vec![0x00u8]; // host_name type
    sni_list.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_list.extend_from_slice(name);
    exts.push(ext(0x0000, &vec16(&sni_list)));
    // extended_master_secret (0x0017), empty.
    exts.push(ext(0x0017, &[]));
    // renegotiation_info (0xff01), empty list.
    exts.push(ext(0xff01, &[0x00]));
    // supported_groups (0x000a): GREASE, X25519MLKEM768, X25519, P-256, P-384.
    let groups: [u16; 5] = [0x0a0a, 0x11ec, 0x001d, 0x0017, 0x0018];
    let mut group_list = Vec::with_capacity(groups.len() * 2);
    for g in groups {
        group_list.extend_from_slice(&g.to_be_bytes());
    }
    exts.push(ext(0x000a, &group_list));
    // ec_point_formats (0x000b): uncompressed, ansix962 prime, primep.
    exts.push(ext(0x000b, &[0x03, 0x00, 0x01, 0x02]));
    // session_ticket (0x0023), empty.
    exts.push(ext(0x0023, &[]));
    // ALPN (0x0010).
    let mut alpn_list = Vec::new();
    for proto in &alpn {
        alpn_list.push(proto.len().min(255) as u8);
        alpn_list.extend_from_slice(proto.as_bytes());
    }
    exts.push(ext(0x0010, &vec16(&alpn_list)));
    // status_request (0x0005), empty.
    exts.push(ext(0x0005, &[]));
    // signature_algorithms (0x000d), Chrome order.
    let sig_algs: [u16; 10] = [
        0x0403, 0x0503, 0x0603, 0x0807, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
    ];
    let mut sig_list = Vec::with_capacity(sig_algs.len() * 2);
    for s in sig_algs {
        sig_list.extend_from_slice(&s.to_be_bytes());
    }
    exts.push(ext(0x000d, &sig_list));
    // signed_cert_timestamp (0x0012), empty.
    exts.push(ext(0x0012, &[]));
    // key_share (0x0033): GREASE entry, then X25519.
    let mut shares = Vec::new();
    // GREASE entry: group 0x0a0a, a 1-byte key.
    shares.extend_from_slice(&0x0a0au16.to_be_bytes());
    shares.extend_from_slice(&1u16.to_be_bytes());
    shares.push(0x00);
    shares.extend_from_slice(&0x001du16.to_be_bytes());
    shares.extend_from_slice(&(32u16).to_be_bytes());
    shares.extend_from_slice(&params.x25519_pub);
    exts.push(ext(0x0033, &vec16(&shares)));
    // psk_key_exchange_modes (0x002d): psk_dhe_ke.
    exts.push(ext(0x002d, &[0x01]));
    // supported_versions (0x002b): GREASE, TLS 1.3, TLS 1.2.
    exts.push(ext(0x002b, &[0x0a, 0x0a, 0x03, 0x04, 0x03, 0x03]));
    // compress_certificate (0x001d): brotli.
    exts.push(ext(0x001d, &[0x02, 0x01, 0x72]));
    // application_settings / ALPS (0x4469): "h2".
    if alpn.contains(&"h2") {
        exts.push(ext(0x4469, &[0x02, b'h', b'2']));
    }

    // --- assemble the handshake message ---------------------------------
    let mut body = vec![0x03, 0x03]; // legacy_version
    body.extend_from_slice(&params.client_random);
    // legacy_session_id: the 32-byte auth label (browser middlebox shape).
    body.push(crate::auth::SESSION_ID_LEN as u8);
    body.extend_from_slice(&params.session_id);
    // cipher_suites: GREASE first, then Chrome's list.
    let suites: [u16; 18] = [
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0xc009, 0xc00a, 0x009c, 0x009d, 0x002f, 0x0035,
    ];
    let mut suite_list = Vec::with_capacity(suites.len() * 2);
    for s in suites {
        suite_list.extend_from_slice(&s.to_be_bytes());
    }
    body.extend(vec16(&suite_list));
    body.extend(vec8(&[0x00])); // null compression
    body.extend(vec16(&exts.iter().flatten().copied().collect::<Vec<u8>>()));

    let mut msg = Vec::with_capacity(body.len() + 4);
    msg.push(HELLO_TYPE);
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    msg.extend_from_slice(&body);
    Ok(msg)
}

const HELLO_TYPE: u8 = 0x01;

fn vec8(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 1);
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
    out
}

fn vec16(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 2);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn ext(ty: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend(vec16(payload));
    out
}
