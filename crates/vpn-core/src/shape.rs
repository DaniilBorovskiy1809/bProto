//! Masquerade shape profiles.
//!
//! A profile controls every externally observable property of the tunnel's
//! opening flight and socket options — the knobs a DPI box can see before the
//! session is encrypted:
//!
//! * how large the first datagrams are (a real browser QUIC Initial is 1252 B),
//! * what fills the padding region (OS-random vs zeros),
//! * the IP socket shape (TTL, DF),
//! * pre-handshake "noise" datagrams (Xray `finalmask/noise` style): random
//!   fillers sent before the real flight, blurring the moment a flow starts.
//!
//! Presets mirror real clients; `profile = "custom"` plus explicit fields
//! builds any other shape. Overrides are allowed on presets too, so a
//! deployment can take `chrome-quic` and nudge a single knob.

use serde::{Deserialize, Serialize};

use crate::crypto;

/// How the padded region of an opening datagram is filled.
///
/// Browsers pad QUIC Initial datagrams with zero bytes (QUIC PADDING); our own
/// first flights use random filler so padding does not read as structural.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Filler {
    /// Cryptographically random filler (default for the native flights).
    #[default]
    Random,
    /// Zero bytes — authentic QUIC PADDING appearance.
    Zeros,
}

/// Pre-handshake noise datagrams (Xray `finalmask/noise` style).
///
/// `count` random datagrams of `min..=max` bytes go out just before the real
/// opening flight. The server drops them silently (they parse as neither
/// native nor QUIC datagrams), so the flow opens with traffic whose shape does
/// not announce "a tunnel handshake is starting".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoiseSpec {
    /// How many noise datagrams to send (0 disables noise).
    #[serde(default)]
    pub count: u32,
    /// Inclusive minimum noise datagram size.
    #[serde(default = "default_noise_min")]
    pub min: usize,
    /// Inclusive maximum noise datagram size.
    #[serde(default = "default_noise_max")]
    pub max: usize,
}

fn default_noise_min() -> usize {
    64
}

fn default_noise_max() -> usize {
    1400
}

impl Default for NoiseSpec {
    fn default() -> Self {
        Self {
            count: 0,
            min: default_noise_min(),
            max: default_noise_max(),
        }
    }
}

/// Config-facing shape section: a preset name plus optional overrides.
///
/// Overrides apply on top of any preset, including `chrome-quic`, so a
/// deployment can tune one knob without redefining the rest. With
/// `profile = "custom"` unset fields fall back to the Chrome values.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ShapeConfig {
    /// Preset name. Unknown names are a configuration error.
    #[serde(default)]
    pub profile: ShapePreset,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filler: Option<Filler>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub df: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noise: Option<NoiseSpec>,
    /// Wrap the opening flight in a real, decryptable QUIC v1 Initial whose
    /// ClientHello carries the auth label (`initial.rs`). The Chrome presets
    /// enable it; `webrtc` and bare `custom` leave it off unless set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_parrot: Option<bool>,
}

/// Shape presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShapePreset {
    /// Chrome HTTP/3 mimicry: 1252 B random-filler Initial, TTL 64, DF on,
    /// real QUIC Initial parrot on top. The default.
    #[default]
    #[serde(rename = "chrome-quic", alias = "chrome_quic")]
    ChromeQuic,
    /// The same shape plus noise datagrams before the flight (for paths where
    /// a single large opening datagram draws probing).
    #[serde(rename = "chrome-noise", alias = "chrome_noise")]
    ChromeNoise,
    /// WebRTC/STUN-ish small-datagram shape: tiny flights, no DF, no parrot.
    #[serde(rename = "webrtc", alias = "web_rtc")]
    WebRtc,
    /// Every field explicit (falls back to Chrome defaults when unset).
    Custom,
}

/// The resolved, concrete shape used by the protocol code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeProfile {
    /// Padded size of the client's first flight (the 1252 B QUIC Initial band).
    pub initial_size: usize,
    /// Padded size of the server's opening flight.
    pub ack_size: usize,
    /// Padding filler.
    pub filler: Filler,
    /// IP TTL on the tunnel socket.
    pub ttl: u8,
    /// DF bit on the tunnel socket (browser path-MTU shape).
    pub df: bool,
    /// Pre-flight noise datagrams.
    pub noise: NoiseSpec,
    /// Whether to wrap the opening flight in a real QUIC Initial.
    pub initial_parrot: bool,
}

impl Default for ShapeProfile {
    fn default() -> Self {
        Self::chrome_quic()
    }
}

impl ShapeProfile {
    /// Chrome HTTP/3 values (defaults).
    #[must_use]
    pub fn chrome_quic() -> Self {
        Self {
            initial_size: crate::packet::INITIAL_SIZE, // 1252
            ack_size: 1200,
            filler: Filler::Random,
            ttl: 64,
            df: true,
            noise: NoiseSpec::default(),
            initial_parrot: true,
        }
    }

    /// Resolve a config section to a concrete profile.
    ///
    /// Errors: [`crate::Error::Config`] if `initial_size`/`ack_size` are below
    /// the flight size they must pad (the padding cannot shrink a datagram).
    pub fn resolve(cfg: &ShapeConfig) -> crate::Result<Self> {
        let mut out = match cfg.profile {
            ShapePreset::ChromeQuic | ShapePreset::ChromeNoise | ShapePreset::Custom => {
                Self::chrome_quic()
            }
            ShapePreset::WebRtc => Self {
                initial_size: 240,
                ack_size: 240,
                filler: Filler::Random,
                ttl: 64,
                df: false,
                noise: NoiseSpec::default(),
                initial_parrot: false,
            },
        };
        if cfg.profile == ShapePreset::ChromeNoise {
            out.noise = NoiseSpec {
                count: 3,
                min: default_noise_min(),
                max: default_noise_max(),
            };
        }
        if let Some(v) = cfg.initial_size {
            out.initial_size = v;
        }
        if let Some(v) = cfg.ack_size {
            out.ack_size = v;
        }
        if let Some(v) = cfg.filler {
            out.filler = v;
        }
        if let Some(v) = cfg.ttl {
            out.ttl = v;
        }
        if let Some(v) = cfg.df {
            out.df = v;
        }
        if let Some(v) = cfg.noise {
            out.noise = v;
        }
        if let Some(v) = cfg.initial_parrot {
            out.initial_parrot = v;
        }
        if out.initial_size < out.min_flight_size() {
            return Err(crate::Error::Config(format!(
                "shape.initial_size {} is below the opening frame ({})",
                out.initial_size,
                out.min_flight_size()
            )));
        }
        if out.ack_size < out.min_ack_size() {
            return Err(crate::Error::Config(format!(
                "shape.ack_size {} is below the server frame ({})",
                out.ack_size,
                out.min_ack_size()
            )));
        }
        if out.noise.count > 0 && out.noise.min > out.noise.max {
            return Err(crate::Error::Config(
                "shape.noise.min must not exceed noise.max".into(),
            ));
        }
        Ok(out)
    }

    /// Smallest datagram the client's opening frame can fit in.
    #[must_use]
    pub fn min_flight_size(&self) -> usize {
        crate::frame::Hello::ENCODED_LEN + crate::packet::HEADER_LEN
    }

    /// Smallest datagram the server's opening frame can fit in.
    #[must_use]
    pub fn min_ack_size(&self) -> usize {
        crate::frame::HelloAck::ENCODED_LEN + crate::packet::HEADER_LEN
    }

    /// Fill a freshly encoded opening datagram up to `target` bytes.
    ///
    /// `Random` uses OS randomness; `Zeros` leaves the tail zeroed (authentic
    /// QUIC PADDING appearance). Errors if `target` cannot fit the frame.
    pub fn pad(&self, datagram: &mut Vec<u8>, target: usize) -> crate::Result<()> {
        if target < datagram.len() {
            return Err(crate::Error::Config(format!(
                "shape size {target} below frame size {}",
                datagram.len()
            )));
        }
        let old_len = datagram.len();
        datagram.resize(target, 0);
        if self.filler == Filler::Random {
            crypto::fill_random(&mut datagram[old_len..]);
        }
        Ok(())
    }

    /// Build one pre-flight noise datagram (first byte kept out of the
    /// `0x10..=0x1F` native band and the `0xC0..=0xFF` long-header band so the
    /// server drops it without opening a donor splice).
    #[must_use]
    pub fn noise_datagram(&self) -> Vec<u8> {
        let span = self.noise.max.saturating_sub(self.noise.min);
        let len = self.noise.min + (crypto::random_32()[0] as usize % (span + 1));
        let mut buf = vec![0u8; len.max(1)];
        crypto::fill_random(&mut buf);
        buf[0] = 0x80 | (crypto::random_32()[0] & 0x1f);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_quic_is_the_default_shape() {
        let p = ShapeProfile::resolve(&ShapeConfig::default()).unwrap();
        assert_eq!(p, ShapeProfile::chrome_quic());
        assert_eq!(p.initial_size, 1252);
        assert_eq!(p.ack_size, 1200);
        assert!(p.df);
        assert_eq!(p.ttl, 64);
        assert!(p.initial_parrot);
        assert_eq!(p.noise.count, 0);
    }

    #[test]
    fn noise_preset_and_overrides_apply() {
        let cfg = ShapeConfig {
            profile: ShapePreset::ChromeNoise,
            ..ShapeConfig::default()
        };
        let p = ShapeProfile::resolve(&cfg).unwrap();
        assert_eq!(p.noise.count, 3);

        let cfg = ShapeConfig {
            profile: ShapePreset::ChromeQuic,
            ttl: Some(128),
            noise: Some(NoiseSpec {
                count: 2,
                min: 100,
                max: 200,
            }),
            ..ShapeConfig::default()
        };
        let p = ShapeProfile::resolve(&cfg).unwrap();
        assert_eq!(p.ttl, 128);
        assert_eq!(p.noise.count, 2);
        assert_eq!(p.initial_size, 1252); // untouched knob keeps the preset
    }

    #[test]
    fn webrtc_profile_is_small_and_parrot_free() {
        let cfg = ShapeConfig {
            profile: ShapePreset::WebRtc,
            ..ShapeConfig::default()
        };
        let p = ShapeProfile::resolve(&cfg).unwrap();
        assert_eq!(p.initial_size, 240);
        assert!(!p.df);
        assert!(!p.initial_parrot);
    }

    #[test]
    fn sizes_below_the_frame_are_rejected() {
        let cfg = ShapeConfig {
            profile: ShapePreset::Custom,
            initial_size: Some(8),
            ..ShapeConfig::default()
        };
        assert!(ShapeProfile::resolve(&cfg).is_err());
    }

    #[test]
    fn noise_datagrams_avoid_native_and_quic_bands() {
        let p = ShapeProfile {
            noise: NoiseSpec {
                count: 1,
                min: 100,
                max: 200,
            },
            ..ShapeProfile::chrome_quic()
        };
        for _ in 0..64 {
            let d = p.noise_datagram();
            assert!((p.noise.min..=p.noise.max).contains(&d.len()));
            assert_ne!(d[0] & 0xF0, 0x10, "must not look native");
            assert_ne!(d[0] & 0xC0, 0xC0, "must not look like a QUIC long header");
        }
    }

    #[test]
    fn pad_fills_with_the_right_filler() {
        let mut random_shape = ShapeProfile::chrome_quic();
        random_shape.filler = Filler::Random;
        let mut d = vec![1u8; 10];
        random_shape.pad(&mut d, 1252).unwrap();
        assert_eq!(d.len(), 1252);
        assert_eq!(&d[..10], &[1u8; 10]);
        assert!(d[10..].iter().any(|&b| b != 0));

        let mut zeros_shape = ShapeProfile::chrome_quic();
        zeros_shape.filler = Filler::Zeros;
        let mut d = vec![1u8; 10];
        zeros_shape.pad(&mut d, 100).unwrap();
        assert!(d[10..].iter().all(|&b| b == 0));

        assert!(zeros_shape.pad(&mut vec![0u8; 200], 100).is_err());
    }
}
