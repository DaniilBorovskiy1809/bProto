//! Cryptography: X25519 key agreement, HKDF key schedule and the
//! ChaCha20-Poly1305 AEAD used for every datagram.
//!
//! No primitive here is hand-rolled. Everything comes from audited RustCrypto
//! crates. The only thing this module defines is *how* the primitives are
//! composed, which is documented in `docs/PROTOCOL.md`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// Symmetric key length.
pub const KEY_LEN: usize = 32;
/// AEAD nonce length.
pub const NONCE_LEN: usize = 12;
/// Per-direction nonce prefix length (the rest of the nonce is the packet number).
pub const NONCE_PREFIX_LEN: usize = 4;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;

/// HKDF info string; bump on any wire-format change.
const HKDF_INFO: &[u8] = b"bproto v1 session keys";

/// X25519 static/ephemeral keypair as raw bytes.
#[derive(Clone)]
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &hex_short(self.public.as_bytes()))
            .finish_non_exhaustive()
    }
}

impl KeyPair {
    /// Generate a fresh keypair from the OS CSPRNG.
    ///
    /// We read 32 bytes from the OS directly and build the secret from them,
    /// rather than going through `rand`, so this crate does not depend on
    /// `rand_core` feature flags matching across crates.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
        Self::from_secret_bytes(bytes)
    }

    /// Rebuild a keypair from raw secret bytes (used for pinned client keys).
    #[must_use]
    pub fn from_secret_bytes(bytes: [u8; KEY_LEN]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// The public key, 32 bytes.
    #[must_use]
    pub fn public_bytes(&self) -> [u8; KEY_LEN] {
        *self.public.as_bytes()
    }

    /// Raw secret bytes. Handle with care.
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; KEY_LEN] {
        self.secret.to_bytes()
    }

    /// Perform the Diffie-Hellman and return the raw 32-byte shared secret.
    #[must_use]
    pub fn diffie_hellman(&self, peer: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
        let peer = PublicKey::from(*peer);
        self.secret.diffie_hellman(&peer).to_bytes()
    }
}

/// Traffic keys and nonce prefixes for one session, one direction each.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// key used to seal packets we send
    pub tx_key: [u8; KEY_LEN],
    /// key used to open packets we receive
    pub rx_key: [u8; KEY_LEN],
    /// nonce prefix for outgoing packets
    pub tx_nonce_prefix: [u8; NONCE_PREFIX_LEN],
    /// nonce prefix for incoming packets
    pub rx_nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionKeys").finish_non_exhaustive()
    }
}

/// Derive the session key schedule from the X25519 shared secret.
///
/// The IKM is the raw DH output; the salt binds both randoms so a repeated
/// ephemeral key cannot produce the same keys twice.
#[must_use]
pub fn derive_session_keys(
    shared: &[u8; KEY_LEN],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    is_client: bool,
) -> SessionKeys {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(client_random);
    salt[32..].copy_from_slice(server_random);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    // c2s_key | s2c_key | c2s_prefix | s2c_prefix
    let mut okm = [0u8; KEY_LEN * 2 + NONCE_PREFIX_LEN * 2];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("HKDF output length is valid");

    let mut c2s_key = [0u8; KEY_LEN];
    let mut s2c_key = [0u8; KEY_LEN];
    let mut c2s_prefix = [0u8; NONCE_PREFIX_LEN];
    let mut s2c_prefix = [0u8; NONCE_PREFIX_LEN];
    c2s_key.copy_from_slice(&okm[0..32]);
    s2c_key.copy_from_slice(&okm[32..64]);
    c2s_prefix.copy_from_slice(&okm[64..68]);
    s2c_prefix.copy_from_slice(&okm[68..72]);
    okm.zeroize();

    if is_client {
        SessionKeys {
            tx_key: c2s_key,
            rx_key: s2c_key,
            tx_nonce_prefix: c2s_prefix,
            rx_nonce_prefix: s2c_prefix,
        }
    } else {
        SessionKeys {
            tx_key: s2c_key,
            rx_key: c2s_key,
            tx_nonce_prefix: s2c_prefix,
            rx_nonce_prefix: c2s_prefix,
        }
    }
}

/// Derive the 32-bit session tag both peers put in the datagram header.
///
/// It is bound to the handshake (both randoms) and the DH secret, so a passive
/// observer cannot link a tag to a user id, and an active prober cannot guess a
/// valid tag without the PSK. It is a *routing* identifier, not a secret: a
/// collision across sessions is handled by the server by replacing the older
/// session.
#[must_use]
pub fn derive_session_tag(
    shared: &[u8; KEY_LEN],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> u32 {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(client_random);
    salt[32..].copy_from_slice(server_random);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = [0u8; 4];
    hk.expand(b"bproto v1 session tag", &mut okm)
        .expect("HKDF output length is valid");
    u32::from_be_bytes(okm)
}

/// 32 bytes from the OS CSPRNG (handshake randoms).
#[must_use]
pub fn random_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS CSPRNG unavailable");
    b
}

/// Fill `buf` with OS CSPRNG bytes. Used for padding that must look like
/// ciphertext, never like zero fill.
pub fn fill_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

/// Build the 12-byte AEAD nonce from a direction prefix and the packet number.
#[must_use]
pub fn nonce(prefix: &[u8; NONCE_PREFIX_LEN], packet_number: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    n[NONCE_PREFIX_LEN..].copy_from_slice(&packet_number.to_be_bytes());
    n
}

/// Encrypt `plaintext` with the header as associated data. Returns
/// `ciphertext || tag`.
pub fn seal(
    key: &[u8; KEY_LEN],
    prefix: &[u8; NONCE_PREFIX_LEN],
    aad: &[u8],
    packet_number: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let n = nonce(prefix, packet_number);
    cipher
        .encrypt(
            Nonce::from_slice(&n),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

/// Decrypt `ciphertext` (with trailing tag) authenticating `aad`.
pub fn open(
    key: &[u8; KEY_LEN],
    prefix: &[u8; NONCE_PREFIX_LEN],
    aad: &[u8],
    packet_number: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let n = nonce(prefix, packet_number);
    cipher
        .decrypt(
            Nonce::from_slice(&n),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

fn hex_short(b: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{HEADER_LEN, Header};

    #[test]
    fn dh_is_symmetric() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let s1 = a.diffie_hellman(&b.public_bytes());
        let s2 = b.diffie_hellman(&a.public_bytes());
        assert_eq!(s1, s2);
    }

    #[test]
    fn key_schedule_is_mirrored() {
        let shared = [7u8; 32];
        let cr = [1u8; 32];
        let sr = [2u8; 32];
        let c = derive_session_keys(&shared, &cr, &sr, true);
        let s = derive_session_keys(&shared, &cr, &sr, false);
        assert_eq!(c.tx_key, s.rx_key);
        assert_eq!(c.rx_key, s.tx_key);
        assert_eq!(c.tx_nonce_prefix, s.rx_nonce_prefix);
    }

    #[test]
    fn seal_open_roundtrip_and_aad_binding() {
        let key = [9u8; 32];
        let prefix = [3u8; 4];
        let hdr = Header::new(0, 42, 7);
        let aad = hdr.encode();
        let ct = seal(&key, &prefix, &aad, 7, b"hello IP packet").unwrap();
        let pt = open(&key, &prefix, &aad, 7, &ct).unwrap();
        assert_eq!(pt, b"hello IP packet");

        // flipping a header byte must fail authentication
        let mut bad_aad = aad;
        bad_aad[HEADER_LEN - 1] ^= 0x01;
        assert!(open(&key, &prefix, &bad_aad, 7, &ct).is_err());
        // wrong packet number must fail (nonce mismatch)
        assert!(open(&key, &prefix, &aad, 8, &ct).is_err());
    }

    #[test]
    fn session_tag_is_symmetric_and_bound_to_the_randoms() {
        let shared = [0x42u8; 32];
        let cr = [1u8; 32];
        let sr = [2u8; 32];
        assert_eq!(
            derive_session_tag(&shared, &cr, &sr),
            derive_session_tag(&shared, &cr, &sr)
        );
        assert_ne!(
            derive_session_tag(&shared, &cr, &sr),
            derive_session_tag(&shared, &sr, &cr)
        );
    }

    #[test]
    fn random_32_is_not_constant() {
        assert_ne!(random_32(), random_32());
    }

    #[test]
    fn nonce_layout() {
        let n = nonce(&[0xAA, 0xBB, 0xCC, 0xDD], 0x0102_0304_0506_0708);
        assert_eq!(&n[..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(&n[4..], &0x0102_0304_0506_0708u64.to_be_bytes());
    }
}
