//! TLS 1.3 `ClientHello` codec: the carrier for the authentication label.
//!
//! The masquerade story rests on one claim — a real browser sends 32 random
//! bytes in the `ClientHello.session_id` field (middlebox compatibility mode),
//! so we can put 32 bytes of *verifiable* data there instead **without changing
//! the length of a single handshake message**. Keeping the length is what makes
//! the Aparecium length vector miss: it catches ShadowTLS v3 precisely because
//! that protocol appends an HMAC to every handshake frame.
//!
//! This module therefore does two things and nothing else:
//!
//! * [`ClientHello::parse`] – read the fields the server needs out of a real
//!   (browser- or `quinn`-produced) `ClientHello`, including one that is not
//!   ours;
//! * [`ClientHelloBuilder`] – emit a `ClientHello` that matches a named browser
//!   profile (cipher order, extension order, GREASE) with our label in
//!   `session_id`.
//!
//! It is deliberately *not* a TLS implementation. Nothing here completes a
//! handshake; the handshake is the donor's, relayed verbatim.

use crate::error::{Error, Result};

/// TLS record content type: handshake.
pub const RECORD_HANDSHAKE: u8 = 0x16;
/// Handshake message type: `client_hello`.
pub const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// `session_id` length a browser sends in middlebox compatibility mode, and the
/// exact length of our authentication label. Never change one without the other.
pub const BROWSER_SESSION_ID_LEN: usize = 32;

/// RFC 8701 GREASE values. Real browsers sprinkle these through every list so
/// servers cannot ossify on a fixed set.
pub const GREASE: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

// Extension type numbers we care about.
pub const EXT_SERVER_NAME: u16 = 0x0000;
pub const EXT_STATUS_REQUEST: u16 = 0x0005;
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
pub const EXT_EC_POINT_FORMATS: u16 = 0x000b;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
pub const EXT_ALPN: u16 = 0x0010;
pub const EXT_PADDING: u16 = 0x0015;
pub const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
pub const EXT_SIGNED_CERT_TIMESTAMP: u16 = 0x0012;
pub const EXT_RECORD_SIZE_LIMIT: u16 = 0x001c;
pub const EXT_SESSION_TICKET: u16 = 0x0023;
pub const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
pub const EXT_DELEGATED_CREDENTIALS: u16 = 0x0022;
pub const EXT_KEY_SHARE: u16 = 0x0033;
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
pub const EXT_APPLICATION_SETTINGS: u16 = 0x44cd;
pub const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// Named `ClientHello` fingerprint. The shape (cipher order, extension order,
/// GREASE positions) is what a passive fingerprinting DPI sees.
///
/// This is the *only* fingerprint type in the tree: the control panel stores
/// these names in subscription payloads, the client config carries one, and the
/// `ClientHello` builder consumes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HelloProfile {
    /// Chrome 120 on Windows, HTTP/3.
    #[default]
    #[serde(alias = "chrome112", alias = "chrome108")]
    Chrome120,
    /// Firefox 121.
    #[serde(alias = "firefox105")]
    Firefox121,
    /// Safari 17 on macOS.
    #[serde(alias = "safari171", alias = "safari17_1")]
    Safari17,
}

impl HelloProfile {
    /// The name stored in configs and in the panel's import payload.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chrome120 => "chrome120",
            Self::Firefox121 => "firefox121",
            Self::Safari17 => "safari17",
        }
    }
}

impl std::fmt::Display for HelloProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One parsed TLS extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// Extension type.
    pub ty: u16,
    /// Raw extension body (`extension_data`).
    pub data: Vec<u8>,
}

/// A parsed `ClientHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// `legacy_version`; always `0x0303` for a TLS 1.3-capable client.
    pub legacy_version: u16,
    /// The 32-byte client random.
    pub random: [u8; 32],
    /// `session_id`, verbatim. 32 bytes for anything that looks like a browser,
    /// and 32 bytes for us; the label is `tag ‖ mac` (see [`crate::auth`]).
    pub session_id: Vec<u8>,
    /// Offered cipher suites, in order, GREASE included.
    pub cipher_suites: Vec<u16>,
    /// Offered compression methods.
    pub compression_methods: Vec<u8>,
    /// Extensions in the order they appeared on the wire.
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    /// Parse from either a bare `ClientHello` handshake message or a full TLS
    /// record wrapping one.
    ///
    /// Anything that is not structurally a `ClientHello` is rejected; a caller
    /// that wants to relay unknowns to the donor must treat a parse error as
    /// "not ours" and forward the bytes untouched.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut cur = Reader::new(bytes);

        // Optional TLS record header.
        if cur.peek_u8()? == RECORD_HANDSHAKE {
            let _version = cur.u16()?;
            let len = cur.u16()? as usize;
            if cur.remaining() < len {
                return Err(Error::ShortDatagram {
                    got: cur.remaining(),
                    need: len,
                });
            }
            cur = Reader::new(&bytes[5..5 + len]);
        }

        let handshake_type = cur.u8()?;
        if handshake_type != HANDSHAKE_CLIENT_HELLO {
            return Err(Error::BadFrameType(handshake_type));
        }
        let body_len = cur.u24()? as usize;
        if cur.remaining() < body_len {
            return Err(Error::ShortDatagram {
                got: cur.remaining(),
                need: body_len,
            });
        }
        let mut cur = Reader::new(&cur.as_slice()[..body_len]);

        let legacy_version = cur.u16()?;
        let mut random = [0u8; 32];
        cur.copy(&mut random)?;

        let sid_len = cur.u8()? as usize;
        let mut session_id = vec![0u8; sid_len];
        cur.copy(&mut session_id)?;

        let cs_len = cur.u16()? as usize;
        if !cs_len.is_multiple_of(2) {
            return Err(Error::BadFrameType(0));
        }
        let mut cipher_suites = Vec::with_capacity(cs_len / 2);
        for _ in 0..cs_len / 2 {
            cipher_suites.push(cur.u16()?);
        }

        let comp_len = cur.u8()? as usize;
        let mut compression_methods = vec![0u8; comp_len];
        cur.copy(&mut compression_methods)?;

        let mut extensions = Vec::new();
        if cur.remaining() >= 2 {
            let ext_block_len = cur.u16()? as usize;
            let mut ext = Reader::new(&cur.as_slice()[..ext_block_len.min(cur.remaining())]);
            while ext.remaining() >= 4 {
                let ty = ext.u16()?;
                let len = ext.u16()? as usize;
                let mut data = vec![0u8; len];
                ext.copy(&mut data)?;
                extensions.push(Extension { ty, data });
            }
        }

        Ok(Self {
            legacy_version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    /// The first extension body of this type, if present.
    #[must_use]
    pub fn extension(&self, ty: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|e| e.ty == ty)
            .map(|e| e.data.as_slice())
    }

    /// SNI hostname, if the `server_name` extension carries a `host_name`.
    #[must_use]
    pub fn sni(&self) -> Option<&str> {
        let mut r = Reader::new(self.extension(EXT_SERVER_NAME)?);
        let _list_len = r.u16().ok()?;
        loop {
            if r.remaining() < 3 {
                return None;
            }
            let name_type = r.u8().ok()?;
            let len = r.u16().ok()? as usize;
            if r.remaining() < len {
                return None;
            }
            let host = r.take(len).ok()?;
            if name_type == 0 {
                return std::str::from_utf8(host).ok();
            }
        }
    }

    /// ALPN protocol names, in order.
    #[must_use]
    pub fn alpn(&self) -> Vec<String> {
        let Some(data) = self.extension(EXT_ALPN) else {
            return Vec::new();
        };
        let mut r = Reader::new(data);
        let mut out = Vec::new();
        let _list_len = r.u16().ok();
        while let Ok(len) = r.u8() {
            let Ok(proto) = r.take(len as usize) else {
                break;
            };
            out.push(String::from_utf8_lossy(proto).into_owned());
        }
        out
    }

    /// Offered TLS versions from `supported_versions`.
    #[must_use]
    pub fn supported_versions(&self) -> Vec<u16> {
        let Some(data) = self.extension(EXT_SUPPORTED_VERSIONS) else {
            return Vec::new();
        };
        let mut r = Reader::new(data);
        let Ok(len) = r.u8() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for _ in 0..len / 2 {
            match r.u16() {
                Ok(v) => out.push(v),
                Err(_) => break,
            }
        }
        out
    }

    /// Named groups present in `key_share`.
    #[must_use]
    pub fn key_share_groups(&self) -> Vec<u16> {
        let Some(data) = self.extension(EXT_KEY_SHARE) else {
            return Vec::new();
        };
        let mut r = Reader::new(data);
        let Ok(mut len) = r.u16() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        while len >= 4 {
            let Ok(group) = r.u16() else { break };
            let Ok(klen) = r.u16() else { break };
            if r.take(klen as usize).is_err() {
                break;
            }
            out.push(group);
            len = len.saturating_sub(4 + klen);
        }
        out
    }

    /// The `session_id` exactly as a label: 32 bytes.
    ///
    /// Anything else is not one of ours and must be relayed untouched.
    #[must_use]
    pub fn session_id_label(&self) -> Option<[u8; BROWSER_SESSION_ID_LEN]> {
        self.session_id.as_slice().try_into().ok()
    }

    /// The X25519 public key from `key_share`, if one is offered.
    ///
    /// Group `0x001d` (X25519) is mandatory for both TLS 1.3 and QUIC, so a
    /// ClientHello without one is not a modern client at all. The key is part of
    /// what the authentication label covers, which is why the server has to read
    /// it back out of the hello rather than trusting anything the client says
    /// elsewhere.
    #[must_use]
    pub fn x25519_key_share(&self) -> Option<[u8; 32]> {
        let data = self.extension(EXT_KEY_SHARE)?;
        let mut r = Reader::new(data);
        let Ok(mut remaining) = r.u16() else {
            return None;
        };
        while remaining >= 4 {
            let Ok(group) = r.u16() else { return None };
            let Ok(klen) = r.u16() else { return None };
            let Ok(key) = r.take(klen as usize) else {
                return None;
            };
            if group == 0x001d {
                return key.try_into().ok();
            }
            remaining = remaining.saturating_sub(4 + klen);
        }
        None
    }
}

/// Builds a `ClientHello` matching a browser profile.
#[derive(Debug, Clone)]
pub struct ClientHelloBuilder {
    profile: HelloProfile,
    sni: String,
    alpn: Vec<String>,
    /// The 32-byte label. `None` emits 32 random bytes, exactly like a browser.
    session_id: Option<[u8; BROWSER_SESSION_ID_LEN]>,
    random: [u8; 32],
    /// X25519 key share to offer.
    key_share: Option<[u8; 32]>,
    /// Padding extension length; Chrome pads the ClientHello to ~512 bytes.
    padding: usize,
}

impl Default for ClientHelloBuilder {
    fn default() -> Self {
        Self {
            profile: HelloProfile::default(),
            sni: String::new(),
            alpn: vec!["h3".to_string()],
            session_id: None,
            random: [0u8; 32],
            key_share: None,
            padding: 0,
        }
    }
}

impl ClientHelloBuilder {
    /// A builder for this profile.
    #[must_use]
    pub fn new(profile: HelloProfile) -> Self {
        Self {
            profile,
            ..Self::default()
        }
    }

    /// The browser profile to imitate.
    #[must_use]
    pub fn profile(mut self, profile: HelloProfile) -> Self {
        self.profile = profile;
        self
    }

    /// SNI hostname to send.
    #[must_use]
    pub fn sni(mut self, sni: impl Into<String>) -> Self {
        self.sni = sni.into();
        self
    }

    /// ALPN protocols to offer.
    #[must_use]
    pub fn alpn(mut self, alpn: Vec<String>) -> Self {
        self.alpn = alpn;
        self
    }

    /// The 32-byte `session_id` label to place in the ClientHello.
    #[must_use]
    pub fn session_id(mut self, id: [u8; BROWSER_SESSION_ID_LEN]) -> Self {
        self.session_id = Some(id);
        self
    }

    /// Client random.
    #[must_use]
    pub fn random(mut self, random: [u8; 32]) -> Self {
        self.random = random;
        self
    }

    /// X25519 public key to offer in `key_share`.
    #[must_use]
    pub fn key_share(mut self, pubkey: [u8; 32]) -> Self {
        self.key_share = Some(pubkey);
        self
    }

    /// Length of the `padding` extension.
    #[must_use]
    pub fn padding(mut self, bytes: usize) -> Self {
        self.padding = bytes;
        self
    }

    /// Emit the `ClientHello` as a complete TLS record (`0x16 0x03 0x01 …`).
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let body = self.build_handshake_body();
        let mut handshake = Vec::with_capacity(4 + body.len());
        handshake.push(HANDSHAKE_CLIENT_HELLO);
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut out = Vec::with_capacity(5 + handshake.len());
        out.push(RECORD_HANDSHAKE);
        out.extend_from_slice(&0x0301u16.to_be_bytes());
        out.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        out.extend_from_slice(&handshake);
        out
    }

    /// Emit the bare `ClientHello` handshake body (no record header).
    #[must_use]
    pub fn build_handshake_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
        out.extend_from_slice(&self.random);

        let sid = self.session_id.unwrap_or_else(random_32);
        out.push(BROWSER_SESSION_ID_LEN as u8);
        out.extend_from_slice(&sid);

        let suites = self.cipher_suites();
        out.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
        for s in suites {
            out.extend_from_slice(&s.to_be_bytes());
        }

        out.push(1); // compression_methods: [null]
        out.push(0);

        let exts = self.build_extensions();
        out.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        out.extend_from_slice(&exts);
        out
    }

    fn cipher_suites(&self) -> Vec<u16> {
        let mut v = match self.profile {
            HelloProfile::Chrome120 => vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            HelloProfile::Firefox121 => vec![
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a,
                0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            HelloProfile::Safari17 => vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
            ],
        };
        // GREASE first, as every real browser does.
        v.insert(0, GREASE[0]);
        v
    }

    /// Extensions in the exact order this browser emits them. Order is the
    /// single most fingerprinted property of a ClientHello, so it is worth the
    /// verbosity.
    fn build_extensions(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        let mut grease_i = 0usize;
        let mut next_grease = || {
            let g = GREASE[(grease_i + 3) % GREASE.len()];
            grease_i += 1;
            g
        };

        let push = |out: &mut Vec<u8>, ty: u16, data: &[u8]| {
            out.extend_from_slice(&ty.to_be_bytes());
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        };

        // Leading GREASE extension.
        push(&mut out, next_grease(), &[]);

        // server_name
        if !self.sni.is_empty() {
            let host = self.sni.as_bytes();
            let mut d = Vec::new();
            d.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
            d.push(0); // host_name
            d.extend_from_slice(&(host.len() as u16).to_be_bytes());
            d.extend_from_slice(host);
            push(&mut out, EXT_SERVER_NAME, &d);
        }

        push(&mut out, EXT_EXTENDED_MASTER_SECRET, &[]);
        push(&mut out, EXT_RENEGOTIATION_INFO, &[0x00]);

        // supported_groups: x25519 first, which is all that matters for QUIC.
        let mut groups = vec![0x001d_u16, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101];
        groups.insert(0, GREASE[1]);
        let mut d = Vec::new();
        d.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
        for g in groups {
            d.extend_from_slice(&g.to_be_bytes());
        }
        push(&mut out, EXT_SUPPORTED_GROUPS, &d);

        push(&mut out, EXT_EC_POINT_FORMATS, &[0x01, 0x00]);
        push(&mut out, EXT_SESSION_TICKET, &[]);

        // ALPN
        if !self.alpn.is_empty() {
            let mut d = Vec::new();
            let body: Vec<u8> = self
                .alpn
                .iter()
                .flat_map(|p| {
                    let mut v = vec![p.len() as u8];
                    v.extend_from_slice(p.as_bytes());
                    v
                })
                .collect();
            d.extend_from_slice(&(body.len() as u16).to_be_bytes());
            d.extend_from_slice(&body);
            push(&mut out, EXT_ALPN, &d);
        }

        push(&mut out, EXT_STATUS_REQUEST, &[0x01, 0, 0, 0, 0]);

        match self.profile {
            HelloProfile::Firefox121 => {
                push(&mut out, EXT_DELEGATED_CREDENTIALS, &{
                    let mut d = vec![];
                    d.extend_from_slice(&0x0403u16.to_be_bytes());
                    d.extend_from_slice(&0x0503u16.to_be_bytes());
                    d.extend_from_slice(&0x0603u16.to_be_bytes());
                    d.extend_from_slice(&0x0804u16.to_be_bytes());
                    d
                });
            }
            HelloProfile::Chrome120 => {
                // Chrome sends signature_algorithms before key_share.
                push(&mut out, EXT_SIGNATURE_ALGORITHMS, &sig_algs());
                push(&mut out, EXT_SIGNED_CERT_TIMESTAMP, &[]);
            }
            HelloProfile::Safari17 => {
                push(&mut out, EXT_SIGNATURE_ALGORITHMS, &sig_algs());
            }
        }

        // key_share: X25519 with our ephemeral public key.
        if let Some(pk) = self.key_share {
            let mut share = Vec::new();
            share.extend_from_slice(&0x001du16.to_be_bytes());
            share.extend_from_slice(&(pk.len() as u16).to_be_bytes());
            share.extend_from_slice(&pk);
            let mut d = Vec::new();
            d.extend_from_slice(&(share.len() as u16).to_be_bytes());
            d.extend_from_slice(&share);
            push(&mut out, EXT_KEY_SHARE, &d);
        }

        if matches!(self.profile, HelloProfile::Firefox121) {
            push(&mut out, EXT_SIGNATURE_ALGORITHMS, &sig_algs());
            push(&mut out, EXT_RECORD_SIZE_LIMIT, &16385u16.to_be_bytes());
        }

        // supported_versions: TLS 1.3 then 1.2.
        push(
            &mut out,
            EXT_SUPPORTED_VERSIONS,
            &[0x04, 0x03, 0x04, 0x03, 0x03],
        );

        // psk_key_exchange_modes: psk_dhe_ke
        push(&mut out, EXT_PSK_KEY_EXCHANGE_MODES, &[0x01, 0x01]);

        if matches!(self.profile, HelloProfile::Chrome120) {
            push(&mut out, EXT_COMPRESS_CERTIFICATE, &[0x02, 0x00, 0x02]);
            let mut d = Vec::new();
            let alps = b"h2";
            d.extend_from_slice(&((alps.len() + 2) as u16).to_be_bytes());
            d.extend_from_slice(&(alps.len() as u16).to_be_bytes());
            d.extend_from_slice(alps);
            push(&mut out, EXT_APPLICATION_SETTINGS, &d);
        }

        // Trailing GREASE, then padding last (padding must be last).
        push(&mut out, next_grease(), &[]);
        if self.padding > 0 {
            push(&mut out, EXT_PADDING, &vec![0u8; self.padding]);
        }
        out
    }
}

fn sig_algs() -> Vec<u8> {
    let algs = [
        0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201, 0x0203,
    ];
    let mut d = Vec::new();
    d.extend_from_slice(&((algs.len() * 2) as u16).to_be_bytes());
    for a in algs {
        d.extend_from_slice(&a.to_be_bytes());
    }
    d
}

fn random_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS CSPRNG unavailable");
    b
}

// ---------------------------------------------------------------------------
// Byte reader
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn as_slice(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn peek_u8(&self) -> Result<u8> {
        self.buf.get(self.pos).copied().ok_or(Error::ShortDatagram {
            got: self.remaining(),
            need: 1,
        })
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::ShortDatagram {
                got: self.remaining(),
                need: n,
            });
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn copy(&mut self, dst: &mut [u8]) -> Result<()> {
        let src = self.take(dst.len())?;
        dst.copy_from_slice(src);
        Ok(())
    }

    fn u8(&mut self) -> Result<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Result<u32> {
        let b = self.take(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builder() -> ClientHelloBuilder {
        ClientHelloBuilder::new(HelloProfile::Chrome120)
            .sni("www.cloudflare.com")
            .alpn(vec!["h3".into()])
            .random([0x11; 32])
            .key_share([0x22; 32])
            .session_id([0x33; BROWSER_SESSION_ID_LEN])
    }

    #[test]
    fn every_profile_roundtrips_through_parse() {
        for profile in [
            HelloProfile::Chrome120,
            HelloProfile::Firefox121,
            HelloProfile::Safari17,
        ] {
            let bytes = builder().profile(profile).build();
            let hello = ClientHello::parse(&bytes).unwrap_or_else(|e| panic!("{profile:?}: {e}"));

            assert_eq!(hello.legacy_version, 0x0303);
            assert_eq!(hello.random, [0x11; 32]);
            assert_eq!(hello.session_id, vec![0x33u8; BROWSER_SESSION_ID_LEN]);
            assert_eq!(hello.sni(), Some("www.cloudflare.com"));
            assert_eq!(hello.alpn(), vec!["h3".to_string()]);
            assert_eq!(hello.supported_versions(), vec![0x0304, 0x0303]);
            assert_eq!(hello.key_share_groups(), vec![0x001d]);
        }
    }

    #[test]
    fn the_record_header_is_well_formed() {
        let bytes = builder().build();
        assert_eq!(bytes[0], RECORD_HANDSHAKE);
        assert_eq!(&bytes[1..3], &[0x03, 0x01]);
        let len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        assert_eq!(len, bytes.len() - 5, "record length must match the body");
        assert_eq!(bytes[5], HANDSHAKE_CLIENT_HELLO);
    }

    #[test]
    fn the_label_does_not_change_the_length_of_the_client_hello() {
        // The Aparecium length vector: if swapping the label in changed the size
        // of the handshake, a censor could detect us by measuring it.
        let with_label = builder().session_id([0x33; 32]).build();
        let browser_like = builder().session_id([0x9f; 32]).build();
        assert_eq!(with_label.len(), browser_like.len());

        let a = builder().session_id([0x00; 32]).build();
        let b = builder().session_id([0xff; 32]).build();
        assert_eq!(a.len(), b.len());
        assert_ne!(a, b, "the label must actually be on the wire");
    }

    #[test]
    fn a_bare_handshake_message_parses_too() {
        let body = builder().build_handshake_body();
        let mut msg = vec![HANDSHAKE_CLIENT_HELLO];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        assert_eq!(ClientHello::parse(&msg).unwrap().sni(), Some("www.cloudflare.com"));
    }

    #[test]
    fn each_profile_has_a_distinct_fingerprint() {
        let shapes: Vec<Vec<u16>> = [
            HelloProfile::Chrome120,
            HelloProfile::Firefox121,
            HelloProfile::Safari17,
        ]
        .iter()
        .map(|p| {
            let bytes = builder().profile(*p).build();
            ClientHello::parse(&bytes)
                .unwrap()
                .extensions
                .iter()
                .map(|e| e.ty)
                .collect()
        })
        .collect();
        assert_ne!(shapes[0], shapes[1]);
        assert_ne!(shapes[1], shapes[2]);
        assert_ne!(shapes[0], shapes[2]);
    }

    #[test]
    fn a_realistic_foreign_client_hello_parses() {
        // Hand-built TLS 1.3 ClientHello with no session_id label and two ALPN
        // entries: the shape a real browser or another VPN would send, and what
        // the server must be able to read before deciding to relay.
        let mut bytes = vec![RECORD_HANDSHAKE, 0x03, 0x01];
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x5a; 32]);
        body.push(0); // no session_id
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.extend_from_slice(&0x1302u16.to_be_bytes());
        body.push(1);
        body.push(0);

        let mut ext = Vec::new();
        // server_name = example.org
        let host = b"example.org";
        ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        ext.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        ext.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        ext.extend_from_slice(host);
        // ALPN = h2, http/1.1
        let alpn_body: Vec<u8> = [&b"\x02h2"[..], &b"\x08http/1.1"[..]].concat();
        ext.extend_from_slice(&EXT_ALPN.to_be_bytes());
        ext.extend_from_slice(&(alpn_body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&alpn_body);

        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        bytes.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&handshake);

        let hello = ClientHello::parse(&bytes).unwrap();
        assert_eq!(hello.sni(), Some("example.org"));
        assert_eq!(hello.alpn(), vec!["h2".to_string(), "http/1.1".to_string()]);
        assert!(hello.session_id.is_empty());
        assert!(hello.session_id_label().is_none());
    }

    #[test]
    fn malformed_input_is_rejected_not_guessed_at() {
        assert!(ClientHello::parse(&[]).is_err());
        assert!(ClientHello::parse(&[0x16, 0x03, 0x01, 0x00, 0x10, 0x01]).is_err());
        // Record header claiming more bytes than are present.
        assert!(ClientHello::parse(&[0x16, 0x03, 0x01, 0x00, 0x40, 0x01, 0x00]).is_err());
        // Not a ClientHello at all.
        assert!(ClientHello::parse(&[0x02, 0x00, 0x00, 0x00]).is_err());
    }
}
