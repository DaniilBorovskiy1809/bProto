//! Acknowledgements, RTT estimation and loss detection (RFC 9002 style).
//!
//! This is what makes CUBIC usable: the congestion controller needs to know
//! which packets were delivered and how long they took. NACK is supported as an
//! extra fast-loss hint, but it is never the only signal.

use std::collections::BTreeMap;

/// A set of non-overlapping, descending packet-number ranges: `[lo, hi]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AckRanges {
    ranges: Vec<(u64, u64)>,
}

impl AckRanges {
    /// Empty.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a single packet number, merging into neighbours.
    pub fn insert(&mut self, pn: u64) {
        // Keep ranges sorted ascending and disjoint.
        let pos = self.ranges.partition_point(|&(lo, _)| lo <= pn);
        let mut merged = (pn, pn);
        let mut start = pos;
        let mut end = pos;

        if pos > 0 {
            let (lo, hi) = self.ranges[pos - 1];
            if pn <= hi.saturating_add(1) {
                merged = (lo, merged.1);
                start = pos - 1;
            }
        }
        while end < self.ranges.len() {
            let (lo, hi) = self.ranges[end];
            if lo <= merged.1.saturating_add(1) {
                merged.1 = merged.1.max(hi);
                end += 1;
            } else {
                break;
            }
        }
        self.ranges.splice(start..end, [merged]);
    }

    /// True if the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The ranges, ascending.
    pub fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.ranges.iter().copied()
    }

    /// Highest acknowledged packet number.
    #[must_use]
    pub fn largest(&self) -> Option<u64> {
        self.ranges.last().map(|&(_, hi)| hi)
    }

    /// Encode as `frame_type(1) ‖ count(u16) ‖ (lo u40, hi u40)*`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.ranges.len() * 10);
        out.push(crate::frame::FrameType::Ack as u8);
        out.extend_from_slice(&(self.ranges.len() as u16).to_be_bytes());
        for &(lo, hi) in &self.ranges {
            out.extend_from_slice(&u40(lo));
            out.extend_from_slice(&u40(hi));
        }
        out
    }

    /// Decode from a control payload (expects the leading frame type byte).
    pub fn decode(buf: &[u8]) -> crate::Result<Self> {
        if buf.len() < 3 || buf[0] != crate::frame::FrameType::Ack as u8 {
            return Err(crate::Error::BadFrameType(
                buf.first().copied().unwrap_or(0),
            ));
        }
        let count = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        if buf.len() < 3 + count * 10 {
            return Err(crate::Error::ShortDatagram {
                got: buf.len(),
                need: 3 + count * 10,
            });
        }
        let mut r = Self::new();
        for i in 0..count {
            let o = 3 + i * 10;
            let lo = u40_read(&buf[o..o + 5]);
            let hi = u40_read(&buf[o + 5..o + 10]);
            r.ranges.push((lo, hi));
        }
        Ok(r)
    }

    /// Iterate every packet number in the set (for RTT sampling).
    pub fn for_each(&self, mut f: impl FnMut(u64)) {
        for &(lo, hi) in &self.ranges {
            for pn in lo..=hi {
                f(pn);
            }
        }
    }
}

fn u40(v: u64) -> [u8; 5] {
    let b = v.to_be_bytes();
    [b[3], b[4], b[5], b[6], b[7]]
}

fn u40_read(b: &[u8]) -> u64 {
    ((b[0] as u64) << 32)
        | ((b[1] as u64) << 24)
        | ((b[2] as u64) << 16)
        | ((b[3] as u64) << 8)
        | (b[4] as u64)
}

/// Smoothed RTT in microseconds, RFC 9002 section 5.
#[derive(Debug, Clone)]
pub struct RttEstimator {
    latest_us: u64,
    smoothed_us: u64,
    rttvar_us: u64,
    initial_us: u64,
    samples: u64,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new(333_000)
    }
}

impl RttEstimator {
    /// Initial RTT defaults to 333 ms (RFC 9002).
    #[must_use]
    pub fn new(initial_us: u64) -> Self {
        Self {
            latest_us: initial_us,
            smoothed_us: initial_us,
            rttvar_us: initial_us / 2,
            initial_us,
            samples: 0,
        }
    }

    /// Feed a new RTT sample.
    pub fn update(&mut self, sample_us: u64) {
        self.latest_us = sample_us;
        if self.samples == 0 {
            self.smoothed_us = sample_us;
            self.rttvar_us = sample_us / 2;
        } else {
            let diff = sample_us.abs_diff(self.smoothed_us);
            self.rttvar_us = (3 * self.rttvar_us + diff) / 4;
            self.smoothed_us = (7 * self.smoothed_us + sample_us) / 8;
        }
        self.samples += 1;
    }

    /// Smoothed RTT.
    #[must_use]
    pub fn smoothed(&self) -> u64 {
        self.smoothed_us
    }

    /// The probe timeout: `srtt + max(4*rttvar, 1ms)`.
    #[must_use]
    pub fn pto(&self) -> u64 {
        self.smoothed_us + 4 * self.rttvar_us.max(1_000)
    }

    /// Whether any sample has been taken.
    #[must_use]
    pub fn has_samples(&self) -> bool {
        self.samples > 0
    }

    /// The configured initial RTT.
    #[must_use]
    pub fn initial(&self) -> u64 {
        self.initial_us
    }
}

/// Tracks in-flight packets to produce RTT samples, measure bytes in flight and
/// detect loss.
#[derive(Debug, Default)]
pub struct SentPackets {
    /// packet number -> (send time in us, wire bytes)
    inflight: BTreeMap<u64, (u64, u64)>,
}

impl SentPackets {
    /// Register a sent packet at time `now_us`.
    pub fn on_sent(&mut self, pn: u64, now_us: u64, bytes: u64) {
        self.inflight.insert(pn, (now_us, bytes));
    }

    /// Remove a packet, returning its `(send time, bytes)`.
    pub fn ack(&mut self, pn: u64) -> Option<(u64, u64)> {
        self.inflight.remove(&pn)
    }

    /// Packets currently in flight.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inflight.len()
    }

    /// True when nothing is in flight.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inflight.is_empty()
    }

    /// Wire bytes currently in flight.
    #[must_use]
    pub fn bytes_in_flight(&self) -> u64 {
        self.inflight.values().map(|&(_, b)| b).sum()
    }

    /// Packet numbers older than `pto` before `now_us`: candidates for loss.
    #[must_use]
    pub fn timed_out(&self, now_us: u64, pto_us: u64) -> Vec<u64> {
        self.inflight
            .iter()
            .filter(|&(_, &(t, _))| now_us.saturating_sub(t) > pto_us)
            .map(|(&pn, _)| pn)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_merge_and_encode() {
        let mut r = AckRanges::new();
        for pn in [1u64, 2, 3, 7, 8, 20, 4] {
            r.insert(pn);
        }
        // 1..=4 and 7..=8 and 20
        let got: Vec<_> = r.iter().collect();
        assert_eq!(got, vec![(1, 4), (7, 8), (20, 20)]);
        assert_eq!(r.largest(), Some(20));

        let enc = r.encode();
        let dec = AckRanges::decode(&enc).unwrap();
        assert_eq!(dec, r);
    }

    #[test]
    fn ranges_handle_u40_limit() {
        let mut r = AckRanges::new();
        let big = (1u64 << 40) - 1;
        r.insert(big - 1);
        r.insert(big);
        assert_eq!(r.iter().collect::<Vec<_>>(), vec![(big - 1, big)]);
        let dec = AckRanges::decode(&r.encode()).unwrap();
        assert_eq!(dec.largest(), Some(big));
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(AckRanges::decode(&[0x03]).is_err());
        assert!(AckRanges::decode(&[0x04, 0, 0]).is_err());
        // Trailing bytes past the declared ranges are tolerated: control
        // datagrams carry random shaping padding after the frame.
        let mut padded = AckRanges::new().encode();
        padded.push(0x5A);
        assert_eq!(AckRanges::decode(&padded).unwrap().ranges.len(), 0);
    }

    #[test]
    fn rtt_converges_and_pto_exceeds_srtt() {
        let mut r = RttEstimator::new(333_000);
        assert!(!r.has_samples());
        for _ in 0..50 {
            r.update(50_000);
        }
        assert!(r.has_samples());
        assert!(r.smoothed() < 60_000 && r.smoothed() > 40_000);
        assert!(r.pto() > r.smoothed());
    }

    #[test]
    fn in_flight_tracking_and_timeouts() {
        let mut s = SentPackets::default();
        s.on_sent(1, 1_000, 1200);
        s.on_sent(2, 2_000, 300);
        assert_eq!(s.len(), 2);
        assert_eq!(s.bytes_in_flight(), 1500);
        assert_eq!(s.ack(1), Some((1_000, 1200)));
        assert_eq!(s.ack(1), None);
        assert_eq!(s.bytes_in_flight(), 300);
        assert_eq!(s.timed_out(10_000, 5_000), vec![2]);
        assert!(s.timed_out(3_000, 5_000).is_empty());
    }
}
