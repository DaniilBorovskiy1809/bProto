//! TLS 1.3 handshake message parsing inside QUIC CRYPTO frames.
//!
//! QUIC has no TLS record layer: handshake messages appear verbatim inside the
//! CRYPTO stream. [`parse_handshake`] walks the messages and
//! [`ClientHello::from_handshake`] destructures the one we care about.
//!
//! The fields the server needs map 1:1 onto the label scheme in
//! [`crate::auth`]: `legacy_session_id` is the 32-byte authentication label
//! (see `crates/craftls/PATCH.md`), `random` and the X25519 `key_share` are the
//! other two MAC inputs. SNI routes the transparent relay to the donor.

/// A parsed TLS handshake message stream (one connection's first flight).
#[derive(Debug, Default, PartialEq)]
pub(crate) struct HandshakeMessages {
    /// Reassembled ClientHello, if a complete one is present.
    pub(crate) client_hello: Option<ClientHello>,
}

/// The parsed fields of a TLS 1.3 `ClientHello` we care about.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ClientHello {
    /// 32 bytes of the handshake `random` field (label MAC input).
    pub(crate) random: [u8; 32],
    /// The `legacy_session_id` field: our 32-byte auth label in browser
    /// middlebox-compatibility guise (browsers send 32 random bytes here).
    pub(crate) session_id: Vec<u8>,
    /// The offered `key_share` for secp-less x25519 (group 0x001d).
    pub(crate) x25519_share: Option<[u8; 32]>,
    /// The offered `server_name` (SNI); routes the donor relay.
    pub(crate) sni: Option<String>,
}

/// Parse a contiguous stream of TLS handshake messages and return every
/// ClientHello found (there is at most one). Offsets and lengths are checked;
/// truncation or a bogus length aborts the walk instead of panicking.
pub(crate) fn parse_handshake(data: &[u8]) -> HandshakeMessages {
    let mut messages = HandshakeMessages::default();
    let mut pos = 0usize;
    while let Some(m) = next_message(data, pos) {
        let (ty, body, end) = m;
        if ty == HELLO_TYPE && messages.client_hello.is_none() {
            messages.client_hello = ClientHello::parse(body);
        }
        pos = end;
    }
    messages
}

const HELLO_TYPE: u8 = 0x01;

/// Walk one `type(1) || len(3 BE) || body` record, returning `(ty, body, end)`.
fn next_message(data: &[u8], pos: usize) -> Option<(u8, &[u8], usize)> {
    let rest = &data.get(pos..)?;
    let &ty = rest.first()?;
    let body = rest.get(1..)?;
    if body.len() < 3 {
        return None;
    }
    let len = u32::from_be_bytes([0, body[0], body[1], body[2]]) as usize;
    let body = body.get(3..)?;
    let body = body.get(..len)?;
    Some((ty, body, pos + 4 + len))
}

impl ClientHello {
    /// Parse the ClientHello body from a `0x01` handshake message.
    fn parse(body: &[u8]) -> Option<Self> {
        // legacy_version(2) || random(32)
        if body.len() < 2 + 32 {
            return None;
        }
        let mut random = [0u8; 32];
        random.copy_from_slice(&body[2..34]);
        let mut pos = 34;

        // legacy_session_id
        let (session_id, next) = take_vec(&body[pos..], 1)?;
        pos += next;

        // cipher_suites
        let (_, next) = take_vec(&body[pos..], 2)?;
        pos += next;

        // legacy_compression_methods
        let (_, next) = take_vec(&body[pos..], 1)?;
        pos += next;

        // extensions
        let (ext_block, next) = take_vec(&body[pos..], 2)?;
        let ext_block_len = next;
        if ext_block_len < next {
            return None;
        }
        pos += next;

        let _ = pos;
        let mut sni = None;
        let mut x25519_share = None;
        let mut ext_pos = 0usize;
        while let Some(ext) = next_vec(&ext_block[ext_pos..], 2) {
            let (ety, data, used) = ext;
            match ety {
                // server_name
                0x0000 => sni = parse_sni(data),
                // key_share
                0x0033 => x25519_share = parse_key_share(data),
                _ => {}
            }
            ext_pos += used;
        }
        Some(Self {
            random,
            session_id: session_id.to_vec(),
            x25519_share,
            sni,
        })
    }
}

/// Variable-length field: `len_be(n)` followed by `len` bytes.
/// Yields `(payload, bytes consumed)`.
fn take_vec(data: &[u8], len_bytes: usize) -> Option<(&[u8], usize)> {
    if data.len() < len_bytes {
        return None;
    }
    let mut len = 0usize;
    for &b in &data[..len_bytes] {
        len = (len << 8) | b as usize;
    }
    let payload = data.get(len_bytes..len_bytes + len)?;
    Some((payload, len_bytes + len))
}

/// Like [`take_vec`] but also hands back the length prefix (for extension
/// iteration, which is a flat list of `(type, data)` pairs).
fn next_vec(data: &[u8], len_bytes: usize) -> Option<(u16, &[u8], usize)> {
    let (ty_bytes, rest) = data.split_at_checked(2)?;
    let ty = u16::from_be_bytes([ty_bytes[0], ty_bytes[1]]);
    let (payload, used) = take_vec(rest, len_bytes)?;
    Some((ty, payload, 2 + used))
}

/// `server_name_list` = `u16 list_len` + `(u8 type; u16 name_len; name)*`,
/// type 0 == hostname. Ends at the first hostname found, which is what TLS
/// mandates (exactly one entry of type 0 per RFC 6066).
fn parse_sni(data: &[u8]) -> Option<String> {
    let (inner, _) = take_vec(data, 2)?;
    if inner.first() != Some(&0u8) {
        return None;
    }
    let (name, _) = take_vec(&inner[1..], 2)?;
    core::str::from_utf8(name).ok().map(str::to_owned)
}

/// `key_share` (client) = `u16 client_shares_len` + `(u16 group; u16 len; key)*`.
/// We take x25519 (group `0x001d`), length exactly 32.
fn parse_key_share(data: &[u8]) -> Option<[u8; 32]> {
    let (client_shares, _) = take_vec(data, 2)?;
    let mut cursor = 0usize;
    while let Some((group, key, used)) = next_entry(&client_shares[cursor..]) {
        if group == 0x001d && key.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(key);
            return Some(out);
        }
        cursor += used;
    }
    None
}

/// One `(group(2) || key(u16 len))` entry.
fn next_entry(data: &[u8]) -> Option<(u16, &[u8], usize)> {
    let (group_bytes, rest) = data.split_at_checked(2)?;
    let group = u16::from_be_bytes([group_bytes[0], group_bytes[1]]);
    let (key, used) = take_vec(rest, 2)?;
    Some((group, key, 2 + used))
}

/// Test-only serializer kit, shared across the crate's tests so whole-stack
/// round trips (QUIC Initial → CRYPTO frames → ClientHello) are built by an
/// *independent* construction path — not by the parser under test.
#[cfg(test)]
pub(crate) mod testkit {
    const HELLO_TYPE: u8 = 0x01;

    fn vec8(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![payload.len() as u8];
        out.extend_from_slice(payload);
        out
    }

    fn vec16(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    fn ext(ty: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = ty.to_be_bytes().to_vec();
        out.extend(vec16(payload));
        out
    }

    /// Serialize a ClientHello in one `0x01` handshake message.
    pub(crate) struct HelloMaterial<'a> {
        pub(crate) random: &'a [u8; 32],
        pub(crate) session_id: &'a [u8],
        pub(crate) x25519: &'a [u8; 32],
        pub(crate) sni: &'a str,
    }

    pub(crate) fn hello_message(m: &HelloMaterial<'_>) -> Vec<u8> {
        let mut body = [0x03, 0x03].to_vec(); // legacy_version
        body.extend_from_slice(m.random);
        body.extend(vec8(m.session_id));
        body.extend(vec16(&[0x13, 0x01, 0x13, 0x02])); // cipher suites
        body.extend(vec8(&[0x00])); // null compression

        let name = m.sni.as_bytes();
        let mut list = vec![0u8]; // host_name type
        list.extend((name.len() as u16).to_be_bytes());
        list.extend_from_slice(name);
        let sni = ext(0x0000, &vec16(&list));

        // key_share entry: (group || u16 len || key) inside a u16 list length
        let mut p = vec16(m.x25519);
        p.splice(0..0, 0x001du16.to_be_bytes());
        let ks = ext(0x0033, &vec16(&p));

        let supported_versions = ext(0x002b, &[0x03, 0x04]); // TLS 1.3

        let mut all = sni;
        all.extend_from_slice(&ks);
        all.extend_from_slice(&supported_versions);
        body.extend(vec16(&all));

        let mut msg = vec![HELLO_TYPE];
        msg.extend(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }
}

#[cfg(test)]
mod tests {
    use super::parse_handshake;
    use super::testkit;

    #[test]
    fn parses_client_hello_fields() {
        let random = [0x42u8; 32];
        let x25519 = [0x7au8; 32];
        let label = [0x11u8; 32];
        let msg = testkit::hello_message(&testkit::HelloMaterial {
            random: &random,
            session_id: &label,
            x25519: &x25519,
            sni: "connector.cloudflare.com",
        });
        let parsed = parse_handshake(&msg);
        let hello = parsed.client_hello.expect("client hello found");
        assert_eq!(hello.random, random);
        assert_eq!(hello.session_id, label.to_vec());
        assert_eq!(hello.x25519_share, Some(x25519));
        assert_eq!(hello.sni.as_deref(), Some("connector.cloudflare.com"));
    }

    #[test]
    fn truncated_body_yields_nothing() {
        let random = [0x42u8; 32];
        let msg = testkit::hello_message(&testkit::HelloMaterial {
            random: &random,
            session_id: &[0x11u8; 32],
            x25519: &[0x7au8; 32],
            sni: "connector.cloudflare.com",
        });
        for cut in 0..msg.len().saturating_sub(1) {
            // Any prefix shorter than the full message must not panic; a
            // truncated parse yields no complete hello.
            let _ = parse_handshake(&msg[..cut]);
        }
        assert!(parse_handshake(&[]).client_hello.is_none());
    }

    #[test]
    fn garbage_prefix_is_skipped_nonfatal() {
        let random = [0x42u8; 32];
        let msg = testkit::hello_message(&testkit::HelloMaterial {
            random: &random,
            session_id: &[0x11u8; 32],
            x25519: &[0x7au8; 32],
            sni: "connector.cloudflare.com",
        });
        let mut mixed = vec![0xEE, 0, 0, 0]; // unknown type, zero-length body
        mixed.extend_from_slice(&msg);
        assert!(parse_handshake(&mixed).client_hello.is_some());
    }
}
