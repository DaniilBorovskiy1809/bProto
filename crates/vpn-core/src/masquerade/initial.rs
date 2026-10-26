//! QUIC Initial packet inspection (RFC 9000 §17.2 / RFC 9001 §5).
//!
//! This is the masquerade's entry point on the server: the client's first UDP
//! datagrams are Version 1 QUIC Initial packets whose CRYPTO stream carries a
//! TLS ClientHello. Initial keys are *public* — they derive exclusively from
//! the destination connection ID and a constant salt (RFC 9001 §5.2) — so the
//! server can decrypt these packets passively, read the `session_id`
//! authentication label (see `crates/craftls/PATCH.md`), and decide between
//! the tunnel and the transparent donor splice **without producing or altering
//! a single handshake byte**.
//!
//! Only what the masquerade needs is implemented: Version 1 long headers,
//! Initial packets, and a frame walk for `PADDING`/`PING`/`CRYPTO` (bailing
//! out on anything else is acceptable because a genuine ClientHello flight
//! never contains other frames). Coalesced packets are walked sequentially.
//!
//! Test strategy: the derivation and unmask code mirrors quinn (0.11.19) +
//! rustls (0.23) + ring — the battle-tested reference chain — while the
//! round-trip tests build protected packets through an *independent* encrypt
//! path in the test module. RFC 9001 Appendix A vectors should be pinned
//! during the first live interop run with a real h3 client.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use hmac::Mac;
use sha2::Sha256;

use crate::error::{Error, Result};

/// RFC 9001 §5.2 — the Initial salt for QUIC Version 1.
const VERSION_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0x1f, 0x55, 0x93, 0x4b, 0x51, 0x61, //
    0xe4, 0x8f, 0x0e, 0x21, 0x7a, 0x35, 0x5d, 0x94, 0x38, 0x32,
];

/// The only QUIC version this layer understands.
const QUIC_V1: u32 = 1;
/// Maximum connection ID length (RFC 9000 §16).
const MAX_CID_LEN: usize = 20;

/// Which side's keys to derive (RFC 9001 §5.2 labels differ per side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Keys used by the client's flight — the interesting one for us.
    Client,
    /// Keys used by the server's flight.
    Server,
}

/// The three keys derived for one Initial flight (RFC 9001 §5.2).
#[derive(Debug, Clone)]
pub struct InitialKeys {
    /// 16-byte AEAD key (`quic key`).
    pub key: [u8; 16],
    /// 12-byte IV (`quic iv`).
    pub iv: [u8; 12],
    /// 16-byte header protection key (`quic hp`).
    pub hp: [u8; 16],
}

/// HKDF-Expand-Label (RFC 8446 §7.1):
/// info = Length(2 BE) ‖ "tls13 "‖label (u8-prefixed) ‖ 0x00 (empty context).
fn hkdf_expand_label(prk: &[u8; 32], label: &str, len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full.len() + 1);
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0x00);

    let h = Hkdf::<Sha256>::from_prk(prk).expect("32-byte prk is a valid PRK");
    let mut out = vec![0u8; len];
    h.expand(&info, &mut out)
        .expect("okm length produces a valid expansion");
    out
}

/// Derive the Initial keys from a DCID (RFC 9001 §5.2).
#[must_use]
pub fn initial_keys(dcid: &[u8], side: Side) -> InitialKeys {
    // HKDF-Extract: HMAC-SHA256(salt, DCID).
    let mut mac =
        <hmac::Hmac<Sha256> as Mac>::new_from_slice(&VERSION_V1_SALT).expect("any key length");
    mac.update(dcid);
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&mac.finalize().into_bytes());

    let in_label = match side {
        Side::Client => "client in",
        Side::Server => "server in",
    };
    let secret = hkdf_expand_label(&prk, in_label, 32);
    let mut secret32 = [0u8; 32];
    secret32.copy_from_slice(&secret);

    let key = hkdf_expand_label(&secret32, "quic key", 16);
    let iv = hkdf_expand_label(&secret32, "quic iv", 12);
    let hp = hkdf_expand_label(&secret32, "quic hp", 16);
    InitialKeys {
        key: key[..16].try_into().expect("16"),
        iv: iv[..12].try_into().expect("12"),
        hp: hp[..16].try_into().expect("16"),
    }
}

/// The AEAD nonce for a packet number: IV ⊕ pn in the low bytes.
fn nonce_for(iv: &[u8; 12], pn: u64) -> [u8; 12] {
    let pn_bytes = pn.to_be_bytes();
    let mut nonce = *iv;
    for (i, &b) in pn_bytes.iter().enumerate() {
        nonce[11 - i] ^= b;
    }
    nonce
}

/// One decrypted CRYPTO frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoFrame {
    /// Stream offset.
    pub offset: u64,
    /// Crypto data at that offset.
    pub data: Vec<u8>,
}

/// A decrypted QUIC Initial packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialPacket {
    /// 4-byte BE version (always 1 here; unsupported versions are rejected).
    pub version: u32,
    /// Destination connection ID (drives key derivation).
    pub dcid: Vec<u8>,
    /// Source connection ID.
    pub scid: Vec<u8>,
    /// Client's stateless-retry bearer token (empty if no retry happened).
    pub token: Vec<u8>,
    /// Decoded packet number.
    pub packet_number: u64,
    /// CRYPTO frames in the order encountered.
    pub crypto: Vec<CryptoFrame>,
}

/// A datagram-level result: possibly several coalesced packets.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InitialFlight {
    /// Every Initial packet successfully decrypted from this datagram.
    pub packets: Vec<InitialPacket>,
}

impl InitialFlight {
    /// Reassemble the CRYPTO stream — the TLS handshake bytes.
    ///
    /// Returns `None` while a hole exists (a coalesced partner packet failed
    /// to decrypt or the flight is still spread over further datagrams).
    #[must_use]
    pub fn crypto_stream(&self) -> Option<Vec<u8>> {
        // Frames whose offset + data cover a contiguous prefix form the
        // handshake stream seen by the TLS layer so far. Chrome sends the
        // ClientHello at offset 0 in the first packet. Frames are applied in
        // (offset, arrival) order; a frame later in the order that re-covers
        // the stream tail re-writes it. A hole truncates the stream there.
        let mut frames = self
            .packets
            .iter()
            .flat_map(|p| p.crypto.iter())
            .collect::<Vec<_>>();
        frames.sort_by_key(|f| f.offset);
        let mut out = Vec::new();
        let mut cursor = 0u64;
        for frame in frames {
            let end = frame.offset + frame.data.len() as u64;
            if end <= cursor {
                continue; // fully covered already
            }
            if frame.offset > cursor {
                break; // hole: unfinished stream
            }
            // The frame extends (or re-writes) the stream tail.
            let overlap = out.len().min((cursor - frame.offset) as usize);
            out.truncate(out.len() - overlap);
            out.extend_from_slice(&frame.data);
            cursor = end;
        }
        Some(out)
    }
}

/// QUIC variable-length integer (RFC 9000 §16). Returns `(value, bytes used)`.
fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let &head = buf.first()?;
    let len = 1usize << (head >> 6);
    if buf.len() < len {
        return None;
    }
    let mask = 0xffu64 >> len; // 2-bit length marker is dropped from the value
    let mut val = (head as u64) & mask;
    for &b in &buf[1..len] {
        val = (val << 8) | b as u64;
    }
    Some((val, len))
}

/// A scanned long-header boundary, before decryption.
#[derive(Debug)]
struct ScannedHeader {
    version: u32,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    token: Vec<u8>,
    /// Offset of the packet number within the datagram.
    pn_offset: usize,
    /// One past the packet: where the next coalesced packet would start.
    packet_end: usize,
}

/// Walk a long header (RFC 9000 §17.2) without decrypting anything.
fn scan_header(dgram: &[u8], pos: usize) -> Result<ScannedHeader> {
    let bad = |need: usize| Error::ShortDatagram {
        got: dgram.len(),
        need,
    };
    let mut idx = pos;
    let take = |n: usize, idx: &mut usize| -> Result<&[u8]> {
        let end = *idx + n;
        match dgram.get(*idx..end) {
            Some(s) => {
                *idx = end;
                Ok(s)
            }
            None => Err(bad(end)),
        }
    };

    if dgram.len() < idx + 5 {
        return Err(bad(idx + 5));
    }
    let first = dgram[idx];
    if first & 0x80 == 0 {
        // Short header: never the Initial(s) we are looking for.
        return Err(Error::Transport("not a long-header QUIC packet".into()));
    }
    let ty = (first & 0x30) >> 4;
    if ty != 0 {
        return Err(Error::Transport(
            "only Initial packets are inspected here".into(),
        ));
    }
    idx += 1;
    let version = u32::from_be_bytes(take(4, &mut idx)?.try_into().expect("4"));
    if version != QUIC_V1 {
        return Err(Error::Transport(format!("QUIC version {version}…")));
    }
    let dcid_len = *take(1, &mut idx)?.first().expect("len byte");
    if dcid_len as usize > MAX_CID_LEN {
        return Err(Error::Transport("DCID too long".into()));
    }
    let dcid = take(dcid_len as usize, &mut idx)?.to_vec();
    let scid_len = *take(1, &mut idx)?.first().expect("len byte");
    if scid_len as usize > MAX_CID_LEN {
        return Err(Error::Transport("SCID too long".into()));
    }
    let scid = take(scid_len as usize, &mut idx)?.to_vec();
    // Token length varint + token (empty when no retry happened).
    let (token_len, used) =
        decode_varint(dgram.get(idx..).ok_or_else(|| bad(idx + 1))?).ok_or_else(|| bad(idx + 1))?;
    let mut token_idx = idx + used;
    let token = take(token_len as usize, &mut token_idx)?.to_vec();
    idx = token_idx;
    // Length varint: packet number + protected payload (incl. 16-byte tag).
    let (length, used) =
        decode_varint(dgram.get(idx..).ok_or_else(|| bad(idx + 1))?).ok_or_else(|| bad(idx + 1))?;
    let pn_offset = idx + used;
    let packet_end = pn_offset
        .checked_add(length as usize)
        .filter(|e| *e <= dgram.len())
        .ok_or_else(|| bad(pn_offset + length as usize))?;
    Ok(ScannedHeader {
        version,
        dcid,
        scid,
        token,
        pn_offset,
        packet_end,
    })
}

/// Remove header protection in place (RFC 9001 §5.4), returning the true
/// packet-number length.
///
/// Sample placement mirrors quinn-proto's `decrypt_header` exactly: the AES
/// mask input is always the 16 bytes at `pn_offset + 4`, independent of the
/// still-unknown pn length. Client Initials carry the ClientHello (~1200 B),
/// so the sample is comfortably inside the packet's own payload; minimal
/// ACK-carrying server Initials are not a masquerade concern.
fn unprotect(packet: &mut [u8], pn_offset: usize, hp: &[u8; 16]) -> Result<usize> {
    if packet.len() < pn_offset + 20 {
        return Err(Error::ShortDatagram {
            got: packet.len(),
            need: pn_offset + 20,
        });
    }
    let cipher = Aes128::new(hp.into());
    let mut block = aes::Block::clone_from_slice(&packet[pn_offset + 4..pn_offset + 20]);
    cipher.encrypt_block(&mut block);
    let mask: [u8; 16] = block.into();

    let first = packet[0] ^ (mask[0] & 0x0f); // long header: 4 protected bits
    let pn_len = ((first & 0x03) as usize) + 1;
    packet[0] ^= mask[0] & 0x0f;
    for (i, dst) in packet[pn_offset..pn_offset + pn_len].iter_mut().enumerate() {
        *dst ^= mask[i + 1];
    }
    Ok(pn_len)
}

/// Truncated packet number → full pn (RFC 9000 §17.3).
fn decode_pn(expected: u64, truncated: &[u8]) -> u64 {
    let bits = truncated.len() as u64 * 8;
    let pn = truncated
        .iter()
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    let window = 1u64 << bits;
    let candidate = (expected + window - pn - 1) & !(window - 1);
    pn + candidate
}

/// Decrypt one packet's protected payload (ciphertext includes the 16-byte
/// GCM tag at the end).
fn decrypt_payload(
    packet: &[u8],
    pn_offset: usize,
    pn_len: usize,
    keys: &InitialKeys,
    pn: u64,
) -> Result<Vec<u8>> {
    let ct_start = pn_offset + pn_len;
    if packet.len() < ct_start + 16 {
        return Err(Error::ShortDatagram {
            got: packet.len(),
            need: ct_start + 16,
        });
    }
    // AEAD additional data = the header *including* the now-unprotected pn.
    let mut ct = packet.get(ct_start..).ok_or(Error::Decrypt)?.to_vec();
    let split = ct.len() - 16;
    let (body, tag) = ct.split_at_mut(split);
    Aes128Gcm::new(keys.key.as_ref().into())
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce_for(&keys.iv, pn)),
            packet.get(..ct_start).ok_or(Error::Decrypt)?,
            body,
            aes_gcm::Tag::from_slice(tag),
        )
        .map_err(|_| Error::Decrypt)
        .map(|_| body.to_vec())
}

/// Walk CRYPTO (0x06) frames out of a decrypted payload, tolerating
/// `PADDING` and `PING`.
fn extract_crypto(payload: &[u8]) -> Vec<CryptoFrame> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < payload.len() {
        match payload[pos] {
            0x00 | 0x01 => pos += 1, // PADDING, PING
            0x02 | 0x03 => break,    // ACK: not part of a client's first flight
            0x06 => {
                let Some((offset, used1)) = decode_varint(payload.get(pos + 1..).unwrap_or(&[]))
                else {
                    break;
                };
                let after1 = pos + 1 + used1;
                let Some((len, used2)) = decode_varint(payload.get(after1..).unwrap_or(&[])) else {
                    break;
                };
                let data_pos = after1 + used2;
                let Some(data) = payload
                    .get(data_pos..data_pos + len as usize)
                    .map(<[u8]>::to_vec)
                else {
                    break;
                };
                out.push(CryptoFrame { offset, data });
                pos = data_pos + len as usize;
            }
            _ => break,
        }
    }
    out
}

/// Inspect a datagram: decrypt every coalesced Initial packet it contains.
///
/// Decoding stops (without erroring) at the first non-Initial or undecryptable
/// packet — with one exception: AEAD failure on the *first* packet is surfaced
/// as [`Error::Decrypt`] so callers can tell "malicious garbage" from "just
/// stopped walking".
pub fn inspect_datagram(dgram: &[u8]) -> Result<InitialFlight> {
    // A long header needs at least: first byte, version, DCID len, SCID len.
    if dgram.len() < 7 {
        return Err(Error::ShortDatagram {
            got: dgram.len(),
            need: 7,
        });
    }
    let mut flight = InitialFlight::default();
    let mut pos = 0usize;
    let mut next_pn: u64 = 0;
    while pos < dgram.len() {
        let hdr = scan_header(dgram, pos)?;
        let keys = initial_keys(&hdr.dcid, Side::Client);
        let mut packet = dgram[pos..hdr.packet_end].to_vec();
        let pn_off = hdr.pn_offset - pos;
        let pn_len = unprotect(&mut packet, pn_off, &keys.hp)?;
        let pn = decode_pn(next_pn, &packet[pn_off..pn_off + pn_len]);
        let payload = decrypt_payload(&packet, pn_off, pn_len, &keys, pn)?;
        let crypto = extract_crypto(&payload);
        flight.packets.push(InitialPacket {
            version: hdr.version,
            dcid: hdr.dcid,
            scid: hdr.scid,
            token: hdr.token,
            packet_number: pn,
            crypto,
        });
        // Coalesced packets are laid out back to back.
        pos = hdr.packet_end;
        next_pn = pn + 1;
    }
    Ok(flight)
}

/// Test-only builder kit: an *independent* seal/protect path (raw aes-gcm +
/// XOR masking, no reuse of the production decrypt code) shared across the
/// crate's tests for whole-stack round trips.
#[cfg(test)]
pub(crate) mod testkit {
    use super::{QUIC_V1, Side, initial_keys};
    use aes::Aes128;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes_gcm::aead::AeadInPlace;
    use aes_gcm::{Aes128Gcm, Nonce};

    trait Varint {
        fn varint(self) -> Vec<u8>;
    }
    impl Varint for u64 {
        fn varint(self) -> Vec<u8> {
            // 2-byte form for the small values used here.
            vec![0x40 | (self >> 8) as u8, (self & 0xff) as u8]
        }
    }
    pub(super) fn varint(v: u64) -> Vec<u8> {
        v.varint()
    }

    /// Wrap payload bytes in a CRYPTO (0x06) frame, 2-byte forms.
    pub(crate) fn crypto_frame_at(offset: u64, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x06u8];
        out.extend(offset.varint());
        out.extend((data.len() as u64).varint());
        out.extend_from_slice(data);
        out
    }

    /// Wrap payload bytes in a CRYPTO frame at offset 0.
    pub(crate) fn crypto_frame(data: &[u8]) -> Vec<u8> {
        crypto_frame_at(0, data)
    }

    /// Build a valid, protected client Initial datagram.
    pub(crate) fn seal_and_protect(
        dcid: &[u8],
        scid: &[u8],
        token: &[u8],
        pn: u64,
        pn_len: usize,
        crypto: &[u8],
    ) -> Vec<u8> {
        let keys = initial_keys(dcid, Side::Client);
        // First byte: long header | fixed bit | Initial type 00 | pn_len-1.
        let mut header = vec![0xC0 | ((pn_len - 1) as u8)];
        header.extend_from_slice(&QUIC_V1.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(scid.len() as u8);
        header.extend_from_slice(scid);
        header.extend((token.len() as u64).varint());
        // Length varint (packet number + protected payload incl. tag), then
        // the truncated pn itself.
        let length = pn_len + crypto.len() + 16;
        header.push(0x40 | (length >> 8) as u8);
        header.push((length & 0xff) as u8);
        let pn_offset = header.len();
        let pnb = pn.to_be_bytes();
        header.extend_from_slice(&pnb[8 - pn_len..]);

        // Seal: nonce = iv ⊕ pn, aad = header with the still-unprotected pn,
        // ciphertext + 16-byte tag.
        let mut nonce = keys.iv;
        for (i, &b) in pnb.iter().enumerate() {
            nonce[11 - i] ^= b;
        }
        let mut pt = crypto.to_vec();
        let tag = Aes128Gcm::new(keys.key.as_ref().into())
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &header, pt.as_mut_slice())
            .expect("seal");
        pt.extend_from_slice(tag.as_slice());
        let mut packet = header;
        packet.extend_from_slice(&pt);

        // Protect header(+pn) with the AES-ECB mask (long header: 4 bits).
        let cipher = Aes128::new(keys.hp.as_ref().into());
        let mut block = aes::Block::clone_from_slice(&packet[pn_offset + 4..pn_offset + 20]);
        cipher.encrypt_block(&mut block);
        let mask: [u8; 16] = block.into();
        packet[0] ^= mask[0] & 0x0f;
        for (i, dst) in packet[pn_offset..pn_offset + pn_len].iter_mut().enumerate() {
            *dst ^= mask[i + 1];
        }
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::testkit;
    use super::{
        CryptoFrame, Error, Side, decode_varint, hkdf_expand_label, initial_keys, inspect_datagram,
    };

    #[test]
    fn keys_differ_per_dcid_and_side() {
        let a = initial_keys(&[1, 2, 3], Side::Client);
        let b = initial_keys(&[1, 2, 4], Side::Client);
        let c = initial_keys(&[1, 2, 3], Side::Server);
        assert_ne!(a.key, b.key);
        assert_ne!(a.key, c.key);
        assert_ne!(a.iv, c.iv);
        assert_ne!(a.hp, c.hp);
    }

    #[test]
    fn hkdf_expand_label_shapes() {
        // RFC 8446 §7.1 sanity: the derived values are stable and sized.
        let prk = [0x11u8; 32];
        assert_eq!(hkdf_expand_label(&prk, "quic key", 16).len(), 16);
        assert_eq!(hkdf_expand_label(&prk, "quic iv", 12).len(), 12);
        assert_eq!(hkdf_expand_label(&prk, "client in", 32).len(), 32);
    }

    #[test]
    fn short_dgram_rejected() {
        assert!(inspect_datagram(&[]).is_err());
        assert!(inspect_datagram(&[0xC0, 0, 0, 0, 1]).is_err());
    }

    #[test]
    fn non_long_header_rejected() {
        assert!(inspect_datagram(&[0x40, 0, 0, 0, 1, 0]).is_err());
    }

    #[test]
    fn roundtrip_single_packet() {
        let dcid = [0x42u8; 8];
        let crypto = testkit::crypto_frame(&[0xAA]);
        let dgram = testkit::seal_and_protect(&dcid, &[], &[], 7, 4, &crypto);
        let flight = inspect_datagram(&dgram).expect("parses");
        assert_eq!(flight.packets.len(), 1);
        let packet = &flight.packets[0];
        assert_eq!(packet.version, 1);
        assert_eq!(packet.dcid, dcid.to_vec());
        assert_eq!(packet.scid, Vec::<u8>::new());
        assert_eq!(packet.token, Vec::<u8>::new());
        assert_eq!(packet.packet_number, 7);
        assert_eq!(
            packet.crypto,
            vec![CryptoFrame {
                offset: 0,
                data: vec![0xAA]
            }]
        );
        assert_eq!(flight.crypto_stream().as_deref(), Some(&[0xAA][..]));
    }

    #[test]
    fn partial_pn_and_crypto_split() {
        // 1-byte pn and two CRYPTO frames, the second carrying the tail.
        let dcid = [0x07u8; 16];
        let mut crypto = testkit::crypto_frame(&[0xDD; 4]);
        // A second CRYPTO frame at offset 4 carrying 8 more bytes.
        let mut second = vec![0x06u8, 0x04]; // type, offset = 4 (1-byte varint)
        second.extend(testkit::varint(8));
        second.extend_from_slice(&[0xEE; 8]);
        crypto.extend_from_slice(&second);
        let dgram = testkit::seal_and_protect(&dcid, &[], &[], 0, 1, &crypto);
        let flight = inspect_datagram(&dgram).expect("parses");
        assert_eq!(flight.packets.len(), 1);
        assert_eq!(flight.packets[0].packet_number, 0);
        let mut stream = vec![0xDD; 4];
        stream.extend_from_slice(&[0xEE; 8]);
        assert_eq!(flight.crypto_stream().unwrap(), stream);
    }

    #[test]
    fn coalesced_packets_are_walked() {
        let dcid = [0x33u8; 8];
        let a = testkit::seal_and_protect(&dcid, &[], &[], 0, 4, &testkit::crypto_frame(&[0x11]));
        let b =
            testkit::seal_and_protect(&dcid, &[], &[], 1, 4, &testkit::crypto_frame_at(1, &[0x22]));
        let mut dgram = a;
        dgram.extend_from_slice(&b);
        let flight = inspect_datagram(&dgram).expect("parses");
        assert_eq!(flight.packets.len(), 2);
        assert_eq!(flight.packets[1].packet_number, 1);
        // The coalesced partner continues the CRYPTO stream at offset 1.
        assert_eq!(flight.crypto_stream().as_deref(), Some(&[0x11, 0x22][..]));
    }

    #[test]
    fn tampered_dcid_fails_aead() {
        let dgram = testkit::seal_and_protect(&[0x42u8; 8], &[], &[], 7, 4, &[0xEE]);
        let mut broken = dgram.clone();
        // Same-length DCID rewrite: header protection unmask still succeeds
        // via the new keys, but the AEAD tag can't verify any more.
        let at = broken.iter().position(|b| *b == 0x42).expect("dcid byte");
        broken[at] = 0x99;
        let res = inspect_datagram(&broken);
        match res {
            Err(Error::Decrypt) => {}
            Ok(f) => assert!(f.crypto_stream().is_none(), "unexpected decrypt success"),
            other => panic!("unexpected result {other:?}"),
        }
    }

    #[test]
    fn varint_decoding() {
        assert_eq!(decode_varint(&[0x00]), Some((0, 1)));
        assert_eq!(decode_varint(&[0x3f]), Some((63, 1)));
        assert_eq!(decode_varint(&[0x41, 0xAA]), Some((426, 2)));
        assert_eq!(decode_varint(&[0x40, 0xAA]), Some((170, 2)));
        assert_eq!(decode_varint(&[0x41]), None);
    }
}
