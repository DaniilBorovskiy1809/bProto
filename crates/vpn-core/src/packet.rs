//! The 12-byte bProto datagram header and inner framing.
//!
//! ```text
//!  offset  size  field
//!  0       1     flags: ver[7:4] | flags[3:0]
//!  1       4     session_tag   u32 BE   (rotating truncated connection id)
//!  5       5     packet_number u40 BE   (monotonic, anti-replay)
//!  10      2     reserved      u16 BE   (MUST be zero in MVP; FEC params later)
//!  -----------------------------------------------------------------------
//!  12      ..    AEAD ciphertext: ChaCha20-Poly1305(key, nonce, aad=header)
//! ```
//!
//! The header is authenticated (it is the AEAD associated data) but not
//! encrypted, so it can be used for routing without a key. The plaintext is an
//! inner frame:
//!
//! ```text
//!  0   1  inner_type (0 = IP, 1 = control, 2 = keepalive)
//!  1   .. IP packet || zero padding
//! ```

use crate::PROTOCOL_VERSION;
use crate::error::{Error, Result};

/// Size of the cleartext header in bytes.
pub const HEADER_LEN: usize = 12;
/// ChaCha20-Poly1305 tag length.
pub const AEAD_TAG_LEN: usize = 16;
/// Inner frame type byte.
pub const INNER_HDR_LEN: usize = 1;
/// Largest datagram we ever emit (QUIC-ish MTU).
pub const MAX_DATAGRAM: usize = 1280;
/// Usable IP payload inside one datagram.
pub const TUNNEL_MTU: usize = MAX_DATAGRAM - HEADER_LEN - AEAD_TAG_LEN - INNER_HDR_LEN; // 1251

/// Firefox-shaped QUIC Initial flight size: the very first datagram of a
/// connection is 1252 B on the wire and is sent twice, ~0.2 ms apart.
/// (Measured from a real Firefox ↔ site HTTP/3 capture.)
pub const INITIAL_SIZE: usize = 1252;

// Header flag bits.
/// Reserved for FEC (stage 3). Always zero in MVP.
pub const FLAG_FEC_RESERVED: u8 = 1 << 0;
/// Key phase bit for key updates.
pub const FLAG_KEY_PHASE: u8 = 1 << 1;
/// Spin bit; pure obfuscation to mirror QUIC's spin bit behaviour.
pub const FLAG_SPIN: u8 = 1 << 2;
/// Set when the datagram is a **plaintext** control datagram (the handshake).
/// Encrypted in-session control frames travel as [`InnerType::Control`] inside
/// AEAD with this bit *clear*.
pub const FLAG_CONTROL: u8 = 1 << 3;

const FLAGS_MASK: u8 = 0x0F;
const PN_MASK: u64 = (1u64 << 40) - 1;

/// Parsed header of a bProto datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Protocol version (high nibble of byte 0).
    pub version: u8,
    /// Flag bits (low nibble of byte 0).
    pub flags: u8,
    /// Rotating truncated connection identifier.
    pub session_tag: u32,
    /// Monotonic packet number, 40 bits on the wire.
    pub packet_number: u64,
    /// Reserved, must be zero in MVP.
    pub reserved: u16,
}

impl Header {
    /// Build a header with the current protocol version.
    #[must_use]
    pub fn new(flags: u8, session_tag: u32, packet_number: u64) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            flags: flags & FLAGS_MASK,
            session_tag,
            packet_number: packet_number & PN_MASK,
            reserved: 0,
        }
    }

    /// True if the FEC-reserved flag is set.
    #[must_use]
    pub fn fec_reserved(&self) -> bool {
        self.flags & FLAG_FEC_RESERVED != 0
    }

    /// True if this datagram carries a control frame.
    #[must_use]
    pub fn is_control(&self) -> bool {
        self.flags & FLAG_CONTROL != 0
    }

    /// Serialize into exactly [`HEADER_LEN`] bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = (self.version << 4) | (self.flags & FLAGS_MASK);
        out[1..5].copy_from_slice(&self.session_tag.to_be_bytes());
        let pn = self.packet_number & PN_MASK;
        // store 40 bits big-endian in bytes 5..10
        out[5] = (pn >> 32) as u8;
        out[6] = (pn >> 24) as u8;
        out[7] = (pn >> 16) as u8;
        out[8] = (pn >> 8) as u8;
        out[9] = pn as u8;
        out[10..12].copy_from_slice(&self.reserved.to_be_bytes());
        out
    }

    /// Parse a header from the front of `buf`.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(Error::ShortDatagram {
                got: buf.len(),
                need: HEADER_LEN,
            });
        }
        let version = buf[0] >> 4;
        if version != PROTOCOL_VERSION {
            return Err(Error::BadVersion(version));
        }
        let packet_number = ((buf[5] as u64) << 32)
            | ((buf[6] as u64) << 24)
            | ((buf[7] as u64) << 16)
            | ((buf[8] as u64) << 8)
            | (buf[9] as u64);
        Ok(Self {
            version,
            flags: buf[0] & FLAGS_MASK,
            session_tag: u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]),
            packet_number,
            reserved: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }
}

/// Kind of payload carried inside the encrypted inner frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InnerType {
    /// A raw IP packet (v4 or v6).
    Ip = 0x00,
    /// A control frame for the session state machine.
    Control = 0x01,
    /// Keepalive / pure padding.
    Keepalive = 0x02,
}

impl TryFrom<u8> for InnerType {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0x00 => Ok(Self::Ip),
            0x01 => Ok(Self::Control),
            0x02 => Ok(Self::Keepalive),
            other => Err(Error::BadInnerType(other)),
        }
    }
}

/// Encode an inner frame. When `bucket` is set the result is zero-padded so the
/// resulting datagram length lands on a size bucket (traffic analysis defence).
#[must_use]
pub fn encode_inner(t: InnerType, payload: &[u8], bucket: Option<usize>) -> Vec<u8> {
    let mut out = Vec::with_capacity(INNER_HDR_LEN + payload.len() + 64);
    out.push(t as u8);
    out.extend_from_slice(payload);
    if let Some(b) = bucket
        && out.len() < b
    {
        out.resize(b, 0);
    }
    out
}

/// Split an inner frame into its type and payload slice.
pub fn decode_inner(buf: &[u8]) -> Result<(InnerType, &[u8])> {
    if buf.is_empty() {
        return Err(Error::ShortDatagram {
            got: 0,
            need: INNER_HDR_LEN,
        });
    }
    let t = InnerType::try_from(buf[0])?;
    Ok((t, &buf[1..]))
}

/// The plaintext size that yields a datagram of exactly `bucket` bytes.
#[must_use]
pub const fn bucket_plaintext(bucket: usize) -> usize {
    bucket.saturating_sub(HEADER_LEN + AEAD_TAG_LEN)
}

/// Frame a **plaintext** control datagram: `header ‖ control_frame`.
///
/// Used only for the handshake, before any key exists. The receiver sees
/// [`FLAG_CONTROL`] in the header and parses the body directly.
#[must_use]
pub fn encode_plaintext_control(session_tag: u32, packet_number: u64, frame: &[u8]) -> Vec<u8> {
    let header = Header::new(FLAG_CONTROL, session_tag, packet_number);
    let mut out = Vec::with_capacity(HEADER_LEN + frame.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(frame);
    out
}

/// Parse a plaintext control datagram. Errors if the control flag is absent, so
/// a caller cannot accidentally treat an encrypted datagram as cleartext.
pub fn decode_plaintext_control(datagram: &[u8]) -> Result<(Header, &[u8])> {
    let header = Header::decode(datagram)?;
    if !header.is_control() {
        return Err(Error::BadFrameType(datagram[0] & 0x0F));
    }
    Ok((header, &datagram[HEADER_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = Header::new(FLAG_SPIN | FLAG_CONTROL, 0xDEADBEEF, 0x00_AB_CD_EF_12);
        let enc = h.encode();
        assert_eq!(enc.len(), HEADER_LEN);
        assert_eq!(enc[0] >> 4, PROTOCOL_VERSION);
        let dec = Header::decode(&enc).unwrap();
        assert_eq!(h, dec);
        assert!(dec.is_control());
        assert!(!dec.fec_reserved());
    }

    #[test]
    fn packet_number_is_40_bits() {
        let h = Header::new(0, 1, u64::MAX);
        let dec = Header::decode(&h.encode()).unwrap();
        assert_eq!(dec.packet_number, PN_MASK);
    }

    #[test]
    fn rejects_short_and_bad_version() {
        assert!(matches!(
            Header::decode(&[0u8; 5]),
            Err(Error::ShortDatagram { .. })
        ));
        let mut bad = Header::new(0, 0, 0).encode();
        bad[0] = 0x90; // version 9
        assert!(matches!(Header::decode(&bad), Err(Error::BadVersion(9))));
    }

    #[test]
    fn inner_roundtrip_padded() {
        let frame = encode_inner(InnerType::Ip, &[0x45, 0x00, 0x00], Some(64));
        assert_eq!(frame.len(), 64);
        let (t, payload) = decode_inner(&frame).unwrap();
        assert_eq!(t, InnerType::Ip);
        assert_eq!(&payload[..3], &[0x45, 0x00, 0x00]);
    }

    #[test]
    fn plaintext_control_roundtrip_and_flag_check() {
        let dg = encode_plaintext_control(0x1234, 0, b"hello-frame");
        let (h, frame) = decode_plaintext_control(&dg).unwrap();
        assert!(h.is_control());
        assert_eq!(h.session_tag, 0x1234);
        assert_eq!(frame, b"hello-frame");

        // an encrypted datagram (flag clear) must be refused by the cleartext path
        let enc = Header::new(0, 7, 3).encode();
        assert!(decode_plaintext_control(&enc).is_err());
    }
}
