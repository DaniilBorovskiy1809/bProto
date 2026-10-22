//! Configuration handed by the embedder to the client (see `vpn-client`).

use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::crypto::KEY_LEN;
use crate::error::{Error, Result};
use crate::hello::HelloProfile;
use crate::packet::MAX_DATAGRAM;

/// The donor site whose certificate and QUIC/TLS behaviour we borrow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DonorSpec {
    /// SNI / hostname of the donor, e.g. `www.cloudflare.com`.
    pub sni: String,
    /// ALPN list offered to the donor. For QUIC masquerade: `["h3"]`.
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
    /// Optional explicit address, to survive DNS poisoning.
    #[serde(default)]
    pub addr_override: Option<SocketAddr>,
}

fn default_alpn() -> Vec<String> {
    vec!["h3".to_string()]
}

impl Default for DonorSpec {
    fn default() -> Self {
        Self {
            sni: "www.cloudflare.com".to_string(),
            alpn: default_alpn(),
            addr_override: None,
        }
    }
}

/// Everything the core needs to set up one tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Server UDP endpoint.
    pub server: SocketAddr,
    /// Donor whose identity we borrow.
    pub donor: DonorSpec,
    /// Pre-shared key (hex, 32 bytes) issued by the panel.
    #[serde(with = "hex_key")]
    pub psk: [u8; KEY_LEN],
    /// Numeric user id (matches the panel's `users.id`).
    pub user_id: u64,
    /// Routing tag key `K_tag` (hex, 32 bytes). Shared by all clients of a
    /// deployment; lets the client pick its own tag without an extra round trip.
    #[serde(with = "hex_key")]
    pub tag_key: [u8; KEY_LEN],
    /// Tunnel MTU. Capped at [`MAX_DATAGRAM`] minus framing overhead.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// `ClientHello` fingerprint to imitate on the masquerade port.
    #[serde(default)]
    pub fingerprint: HelloProfile,
    /// Run the masquerade layer: browser-shaped `ClientHello` on the donor's
    /// port, with unknown handshakes relayed to the donor. Off means the plain
    /// bProto datapath only, which is honest but not disguised.
    #[serde(default)]
    pub masquerade: bool,
    /// Handshake timeout.
    #[serde(default = "default_handshake_timeout", with = "humantime_serde_compat")]
    pub handshake_timeout: Duration,
}

fn default_mtu() -> u16 {
    1280
}

fn default_handshake_timeout() -> Duration {
    Duration::from_secs(10)
}

impl TunnelConfig {
    /// Effective tunnel MTU, capped by the framing overhead.
    #[must_use]
    pub fn effective_mtu(&self) -> usize {
        (self.mtu as usize).min(crate::packet::TUNNEL_MTU)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> crate::Result<()> {
        if self.donor.sni.is_empty() {
            return Err(crate::Error::Config("donor.sni is empty".into()));
        }
        if !(576..=MAX_DATAGRAM).contains(&(self.mtu as usize)) {
            return Err(crate::Error::Config(format!(
                "mtu {} out of range 576..={MAX_DATAGRAM}",
                self.mtu
            )));
        }
        Ok(())
    }
}

/// Minimal hex codec so the config does not pull an extra dependency.
mod hex_key {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::config::to_hex(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = crate::config::from_hex(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32-byte hex key"))
    }
}

/// Minimal humantime-compatible duration codec (seconds or `10s`/`500ms`).
mod humantime_serde_compat {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_millis() as u64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Millis(u64),
            Text(String),
        }
        match Repr::deserialize(d)? {
            Repr::Millis(ms) => Ok(Duration::from_millis(ms)),
            Repr::Text(t) => parse_duration(&t).map_err(serde::de::Error::custom),
        }
    }

    fn parse_duration(t: &str) -> Result<Duration, String> {
        let t = t.trim();
        let (num, unit) = t.split_at(
            t.find(|c: char| !c.is_ascii_digit())
                .ok_or_else(|| format!("bad duration {t:?}"))?,
        );
        let n: u64 = num.parse().map_err(|_| format!("bad duration {t:?}"))?;
        match unit.trim() {
            "ms" => Ok(Duration::from_millis(n)),
            "s" | "" => Ok(Duration::from_secs(n)),
            "m" => Ok(Duration::from_secs(n * 60)),
            other => Err(format!("unknown duration unit {other:?}")),
        }
    }
}

/// Lowercase hex encoding helper.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Hex decoding helper.
pub fn from_hex(s: &str) -> core::result::Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("hex string has odd length".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char)
            .to_digit(16)
            .ok_or_else(|| format!("bad hex digit at {i}"))?;
        let lo = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("bad hex digit at {}", i + 1))?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

/// The URI scheme the control panel emits and clients import.
pub const IMPORT_SCHEME: &str = "bproto://import/";

/// Body of a `bproto://import/<base64url(json)>` payload.
///
/// Field names match `panel/backend/src/keys.rs::config_uri`; `sni` and
/// `donor_sni` are both accepted so hand-written configs are forgiving.
#[derive(Debug, Deserialize)]
struct ImportBody {
    #[serde(default)]
    v: u32,
    server: SocketAddr,
    #[serde(alias = "donor_sni")]
    sni: String,
    uid: u64,
    psk: String,
    tag_key: String,
    /// Fingerprint name, e.g. `chrome120`.
    #[serde(default)]
    fp: Option<String>,
    #[serde(default)]
    mtu: Option<u16>,
    /// Human label for the device; informational only.
    #[serde(default)]
    label: Option<String>,
}

/// Parse a `bproto://import/...` URI into a [`TunnelConfig`].
///
/// This is the handoff between the control panel (`GET /api/keys/{id}/config`,
/// which returns the URI and a QR code) and a client. Both the CLI and the FFI
/// entry points accept a URI, so a scanned key works without any file.
pub fn from_import_uri(uri: &str) -> Result<TunnelConfig> {
    from_import_uri_with_label(uri).map(|(cfg, _)| cfg)
}

/// As [`from_import_uri`], but also returns the human device label.
pub fn from_import_uri_with_label(uri: &str) -> Result<(TunnelConfig, Option<String>)> {
    let body = uri
        .trim()
        .strip_prefix(IMPORT_SCHEME)
        .ok_or_else(|| Error::Config(format!("expected a {IMPORT_SCHEME} URI")))?;
    let raw = base64url_decode(body).map_err(Error::Config)?;
    let parsed: ImportBody = serde_json::from_slice(&raw)
        .map_err(|e| Error::Config(format!("import payload is not valid JSON: {e}")))?;

    if parsed.v > 1 {
        return Err(Error::Config(format!(
            "import payload version {} is newer than this client understands",
            parsed.v
        )));
    }

    let psk = parse_key(&parsed.psk).map_err(|e| Error::Config(format!("import psk: {e}")))?;
    let tag_key =
        parse_key(&parsed.tag_key).map_err(|e| Error::Config(format!("import tag_key: {e}")))?;

    let fingerprint = match parsed.fp.as_deref() {
        None => HelloProfile::default(),
        Some(name) => serde_json::from_value(serde_json::Value::String(name.to_string()))
            .map_err(|_| Error::Config(format!("import fp {name:?} is not a known fingerprint")))?,
    };

    if parsed.sni.trim().is_empty() {
        return Err(Error::Config("import sni is empty".to_string()));
    }

    let cfg = TunnelConfig {
        server: parsed.server,
        donor: DonorSpec {
            sni: parsed.sni,
            ..DonorSpec::default()
        },
        psk,
        user_id: parsed.uid,
        tag_key,
        mtu: parsed.mtu.unwrap_or_else(default_mtu),
        fingerprint,
        masquerade: false,
        handshake_timeout: default_handshake_timeout(),
    };
    cfg.validate()?;
    Ok((cfg, parsed.label))
}

/// Build a `bproto://import/...` URI. Used by tests and by the CLI's `export`.
#[must_use]
pub fn to_import_uri(cfg: &TunnelConfig, label: &str) -> String {
    let json = serde_json::json!({
        "v": 1,
        "server": cfg.server.to_string(),
        "sni": cfg.donor.sni,
        "uid": cfg.user_id,
        "psk": to_hex(&cfg.psk),
        "tag_key": to_hex(&cfg.tag_key),
        "fp": cfg.fingerprint.as_str(),
        "label": label,
    });
    format!(
        "{IMPORT_SCHEME}{}",
        base64url_encode(json.to_string().as_bytes())
    )
}

fn parse_key(hex: &str) -> core::result::Result<[u8; KEY_LEN], String> {
    from_hex(hex)?
        .try_into()
        .map_err(|_| "expected 32-byte hex".to_string())
}

/// URL-safe base64 without padding (RFC 4648 §5).
#[must_use]
pub fn base64url_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
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

/// Inverse of [`base64url_encode`]. Rejects invalid characters and non-zero
/// trailing bits, so a mangled URI fails rather than silently truncating.
pub fn base64url_decode(input: &str) -> core::result::Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for (i, c) in input.bytes().enumerate() {
        if c == b'=' {
            break;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(format!("invalid base64url character {c:?} at {i}")),
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return Err("base64url padding bits are not zero".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let k = [0xABu8; 32];
        assert_eq!(from_hex(&to_hex(&k)).unwrap(), k.to_vec());
        assert!(from_hex("abc").is_err());
    }

    #[test]
    fn config_toml_roundtrip() {
        let toml = r#"
            server = "1.2.3.4:443"
            user_id = 7
            psk = "00000000000000000000000000000000000000000000000000000000000000ff"
            tag_key = "1111111111111111111111111111111111111111111111111111111111111111"
            [donor]
            sni = "example.org"
        "#;
        let cfg: TunnelConfig = toml::from_str(toml).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.user_id, 7);
        assert_eq!(cfg.donor.alpn, vec!["h3"]);
        assert_eq!(cfg.psk[31], 0xff);
        assert_eq!(cfg.handshake_timeout, Duration::from_secs(10));
    }

    #[test]
    fn base64url_matches_the_panel_vectors() {
        for (raw, encoded) in [
            (&b"f"[..], "Zg"),
            (&b"fo"[..], "Zm8"),
            (&b"foo"[..], "Zm9v"),
            (&b"foob"[..], "Zm9vYg"),
            (&b"fooba"[..], "Zm9vYmE"),
            (&b"foobar"[..], "Zm9vYmFy"),
        ] {
            assert_eq!(base64url_encode(raw), encoded);
            assert_eq!(base64url_decode(encoded).unwrap(), raw);
        }
    }

    #[test]
    fn base64url_rejects_a_mangled_uri() {
        assert!(base64url_decode("Zm9v!").is_err());
        // trailing bits that are not zero
        assert!(base64url_decode("Zh").is_err());
    }

    /// The exact JSON the panel's `keys::config_uri` produces.
    #[test]
    fn import_uri_roundtrip() {
        let cfg = TunnelConfig {
            server: "203.0.113.10:443".parse().unwrap(),
            donor: DonorSpec {
                sni: "www.cloudflare.com".into(),
                ..DonorSpec::default()
            },
            psk: [0x11; 32],
            user_id: 7,
            tag_key: [0x22; 32],
            mtu: 1280,
            fingerprint: HelloProfile::Safari17,
            masquerade: false,
            handshake_timeout: Duration::from_secs(10),
        };
        let uri = to_import_uri(&cfg, "Pixel");
        assert!(uri.starts_with(IMPORT_SCHEME));

        let back = from_import_uri(&uri).unwrap();
        assert_eq!(back.server, cfg.server);
        assert_eq!(back.donor.sni, "www.cloudflare.com");
        assert_eq!(back.user_id, 7);
        assert_eq!(back.psk, [0x11; 32]);
        assert_eq!(back.tag_key, [0x22; 32]);
        assert_eq!(back.fingerprint, HelloProfile::Safari17);

        // The panel's tag derivation must agree with the core's.
        assert_eq!(
            crate::auth::compute_tag(&back.tag_key, back.user_id),
            crate::auth::compute_tag(&cfg.tag_key, cfg.user_id)
        );
    }

    #[test]
    fn import_uri_from_a_hand_written_payload() {
        let json = r#"{"v":1,"server":"1.2.3.4:443","donor_sni":"example.org","uid":9,
                       "psk":"2222222222222222222222222222222222222222222222222222222222222222",
                       "tag_key":"3333333333333333333333333333333333333333333333333333333333333333"}"#;
        let uri = format!("{IMPORT_SCHEME}{}", base64url_encode(json.as_bytes()));
        let cfg = from_import_uri(&uri).unwrap();
        assert_eq!(cfg.user_id, 9);
        assert_eq!(cfg.donor.sni, "example.org");
        assert_eq!(cfg.fingerprint, HelloProfile::Chrome120);
        assert_eq!(cfg.mtu, 1280);
    }

    #[test]
    fn import_uri_rejects_bad_input() {
        assert!(from_import_uri("https://example.org").is_err());
        assert!(from_import_uri("bproto://import/!!!!").is_err());
        let bad_json = format!("{IMPORT_SCHEME}{}", base64url_encode(b"{ not json }"));
        assert!(from_import_uri(&bad_json).is_err());
        // short psk
        let short = r#"{"server":"1.2.3.4:443","sni":"a.org","uid":1,
                        "psk":"22","tag_key":"3333333333333333333333333333333333333333333333333333333333333333"}"#;
        let uri = format!("{IMPORT_SCHEME}{}", base64url_encode(short.as_bytes()));
        assert!(from_import_uri(&uri).is_err());
    }
}
