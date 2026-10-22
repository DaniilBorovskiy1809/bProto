//! Control frames.
//!
//! Two families share this codec:
//!
//! * **plaintext** handshake frames (`Hello`, `HelloAck`) that travel in a
//!   datagram with the `FLAG_CONTROL` header bit set and no AEAD;
//! * **encrypted** session frames (`Ack`, `Ping`, `Pong`, `Close`) that travel as
//!   an [`crate::packet::InnerType::Control`] inner frame inside AEAD.

use crate::auth::{MAC_LEN, TAG_LEN};
use crate::error::{Error, Result};

/// Control frame type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Client -> server handshake opening.
    Hello = 0x01,
    /// Server -> client handshake response.
    HelloAck = 0x02,
    /// Acknowledged packet-number ranges.
    Ack = 0x03,
    /// Keepalive probe.
    Ping = 0x04,
    /// Keepalive reply.
    Pong = 0x05,
    /// Graceful teardown.
    Close = 0x06,
}

impl TryFrom<u8> for FrameType {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::Hello),
            0x02 => Ok(Self::HelloAck),
            0x03 => Ok(Self::Ack),
            0x04 => Ok(Self::Ping),
            0x05 => Ok(Self::Pong),
            0x06 => Ok(Self::Close),
            other => Err(Error::BadFrameType(other)),
        }
    }
}

/// Client handshake opening. 104 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// Routing tag.
    pub tag: [u8; TAG_LEN],
    /// Client random.
    pub client_random: [u8; 32],
    /// Client ephemeral X25519 public key.
    pub x25519_pub: [u8; 32],
    /// Time window the MAC was computed for.
    pub window: u64,
    /// [`crate::auth::label_mac`] over the fields above.
    pub mac: [u8; MAC_LEN],
}

/// Server handshake response. 92 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAck {
    /// Echo of the client random, so the MAC is bound to this exchange.
    pub client_random: [u8; 32],
    /// Server random.
    pub server_random: [u8; 32],
    /// Server ephemeral X25519 public key.
    pub x25519_pub: [u8; 32],
    /// Tunnel address handed to the client.
    pub assigned_ip: [u8; 4],
    /// [`crate::auth::ack_mac`] over the fields above.
    pub mac: [u8; MAC_LEN],
}

impl Hello {
    /// Serialize to a control frame payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + TAG_LEN + 32 + 32 + 8 + MAC_LEN);
        out.push(FrameType::Hello as u8);
        out.extend_from_slice(&self.tag);
        out.extend_from_slice(&self.client_random);
        out.extend_from_slice(&self.x25519_pub);
        out.extend_from_slice(&self.window.to_be_bytes());
        out.extend_from_slice(&self.mac);
        out
    }

    /// Parse from a control frame payload.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        const LEN: usize = 1 + TAG_LEN + 32 + 32 + 8 + MAC_LEN;
        if buf.len() != LEN {
            return Err(Error::ShortDatagram {
                got: buf.len(),
                need: LEN,
            });
        }
        if FrameType::try_from(buf[0])? != FrameType::Hello {
            return Err(Error::BadFrameType(buf[0]));
        }
        let mut h = Hello {
            tag: [0; TAG_LEN],
            client_random: [0; 32],
            x25519_pub: [0; 32],
            window: 0,
            mac: [0; MAC_LEN],
        };
        h.tag.copy_from_slice(&buf[1..9]);
        h.client_random.copy_from_slice(&buf[9..41]);
        h.x25519_pub.copy_from_slice(&buf[41..73]);
        h.window = u64::from_be_bytes(buf[73..81].try_into().expect("8 bytes"));
        h.mac.copy_from_slice(&buf[81..105]);
        Ok(h)
    }
}

impl HelloAck {
    /// Serialize to a control frame payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 32 + 32 + 4 + MAC_LEN);
        out.push(FrameType::HelloAck as u8);
        out.extend_from_slice(&self.client_random);
        out.extend_from_slice(&self.server_random);
        out.extend_from_slice(&self.x25519_pub);
        out.extend_from_slice(&self.assigned_ip);
        out.extend_from_slice(&self.mac);
        out
    }

    /// Parse from a control frame payload.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        const LEN: usize = 1 + 32 + 32 + 32 + 4 + MAC_LEN;
        if buf.len() != LEN {
            return Err(Error::ShortDatagram {
                got: buf.len(),
                need: LEN,
            });
        }
        if FrameType::try_from(buf[0])? != FrameType::HelloAck {
            return Err(Error::BadFrameType(buf[0]));
        }
        let mut a = HelloAck {
            client_random: [0; 32],
            server_random: [0; 32],
            x25519_pub: [0; 32],
            assigned_ip: [0; 4],
            mac: [0; MAC_LEN],
        };
        a.client_random.copy_from_slice(&buf[1..33]);
        a.server_random.copy_from_slice(&buf[33..65]);
        a.x25519_pub.copy_from_slice(&buf[65..97]);
        a.assigned_ip.copy_from_slice(&buf[97..101]);
        a.mac.copy_from_slice(&buf[101..125]);
        Ok(a)
    }
}

/// Simple control frame with no payload.
#[must_use]
pub fn simple(t: FrameType) -> Vec<u8> {
    vec![t as u8]
}

/// Parse the frame type of an encrypted control payload.
pub fn peek_type(buf: &[u8]) -> Result<FrameType> {
    let first = *buf
        .first()
        .ok_or(Error::ShortDatagram { got: 0, need: 1 })?;
    FrameType::try_from(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrip() {
        let h = Hello {
            tag: [1, 2, 3, 4, 5, 6, 7, 8],
            client_random: [9; 32],
            x25519_pub: [10; 32],
            window: 12345,
            mac: [11; MAC_LEN],
        };
        let enc = h.encode();
        assert_eq!(enc.len(), 105);
        assert_eq!(Hello::decode(&enc).unwrap(), h);
        assert!(Hello::decode(&enc[..100]).is_err());
    }

    #[test]
    fn hello_ack_roundtrip() {
        let a = HelloAck {
            client_random: [1; 32],
            server_random: [2; 32],
            x25519_pub: [3; 32],
            assigned_ip: [10, 66, 0, 2],
            mac: [4; MAC_LEN],
        };
        let enc = a.encode();
        assert_eq!(enc.len(), 125);
        assert_eq!(HelloAck::decode(&enc).unwrap(), a);
    }

    #[test]
    fn simple_frames_and_types() {
        assert_eq!(
            peek_type(&simple(FrameType::Ping)).unwrap(),
            FrameType::Ping
        );
        assert!(matches!(peek_type(&[]), Err(Error::ShortDatagram { .. })));
        assert!(matches!(peek_type(&[0xFF]), Err(Error::BadFrameType(0xFF))));
    }
}
