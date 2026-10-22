//! Key material: PSK generation, the routing tag, and the client config URI.
//!
//! The tag algorithm here MUST stay byte-identical to
//! `vpn_core::auth::compute_tag`. That invariant is enforced by
//! `tag_matches_vpn_core_vector` below, which pins a vector produced by the
//! protocol crate.

use std::net::SocketAddr;

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Generate a fresh 32-byte pre-shared key.
#[must_use]
pub fn generate_psk() -> [u8; 32] {
    let mut psk = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut psk);
    psk
}

/// Routing tag: `HMAC-SHA256(K_tag, "bproto-tag" ‖ user_id_be)[0..8]`.
///
/// Mirrors `vpn_core::auth::compute_tag`.
#[must_use]
pub fn compute_tag(tag_key: &[u8; 32], user_id: u64) -> [u8; 8] {
    let mut mac = HmacSha256::new_from_slice(tag_key).expect("HMAC accepts any key length");
    mac.update(b"bproto-tag");
    mac.update(&user_id.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&out[..8]);
    tag
}

/// Everything that goes into a client configuration.
#[derive(Debug, Clone)]
pub struct ConfigParts {
    /// Server endpoint.
    pub server: SocketAddr,
    /// Donor SNI.
    pub donor_sni: String,
    /// Numeric user id.
    pub user_id: u64,
    /// Pre-shared key.
    pub psk: [u8; 32],
    /// Routing tag key (shared by the whole deployment).
    pub tag_key: [u8; 32],
    /// ClientHello fingerprint name.
    pub fingerprint: String,
    /// Human label for the device.
    pub label: String,
}

/// Build the `bproto://import/<base64url(json)>` URI that clients import, and
/// that the panel renders as a QR code.
#[must_use]
pub fn config_uri(parts: &ConfigParts) -> String {
    let json = serde_json::json!({
        "v": 1,
        "server": parts.server.to_string(),
        "sni": parts.donor_sni,
        "uid": parts.user_id,
        "psk": hex::encode(parts.psk),
        "tag_key": hex::encode(parts.tag_key),
        "fp": parts.fingerprint,
        "label": parts.label,
    });
    let payload = json.to_string();
    format!("bproto://import/{}", base64url(payload.as_bytes()))
}

/// Render a QR code as an SVG string.
pub fn qr_svg(text: &str) -> anyhow::Result<String> {
    let code = qrcode::QrCode::new(text.as_bytes())?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(240, 240)
        .build())
}

/// Standard base64 without padding, URL-safe alphabet. Small local
/// implementation to avoid another dependency on the panel's security boundary.
#[must_use]
pub fn base64url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0u8) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0u8) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 63) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference bytes for `compute_tag(&[0x22; 32], 1)`, matching
    /// `vpn_core::auth::compute_tag`.
    const TAG_VECTOR: [u8; 8] = [0x33, 0x5c, 0xf2, 0xe0, 0x5f, 0x97, 0xe9, 0xc6];

    #[test]
    fn tag_matches_vpn_core_vector() {
        // Pin produced by `vpn_core::auth::compute_tag(&[0x22; 32], 1)`.
        // If vpn-core changes the tag derivation, this test must be updated in
        // lockstep, which is the point.
        let tag = compute_tag(&[0x22u8; 32], 1);
        let expected = TAG_VECTOR;
        assert_eq!(tag, expected);
    }

    #[test]
    fn psk_is_random() {
        assert_ne!(generate_psk(), generate_psk());
    }

    #[test]
    fn base64url_known_values() {
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(base64url(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn config_uri_is_importable_shape() {
        let uri = config_uri(&ConfigParts {
            server: "203.0.113.10:443".parse().unwrap(),
            donor_sni: "www.cloudflare.com".into(),
            user_id: 7,
            psk: [0x11; 32],
            tag_key: [0x22; 32],
            fingerprint: "chrome112".into(),
            label: "Pixel".into(),
        });
        assert!(uri.starts_with("bproto://import/"));
        assert!(uri.len() > 80);
    }

    #[test]
    fn qr_renders_svg() {
        let svg = qr_svg("bproto://import/test").unwrap();
        assert!(svg.contains("<svg"));
    }
}
