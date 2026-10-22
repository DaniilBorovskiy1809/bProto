//! CUBIC congestion control, byte-based (RFC 8312 shaped).
//!
//! This controller exists so the datapath is not a fixed-rate firehose. It has
//! the three CUBIC parts:
//!
//! * **slow start** while `cwnd < ssthresh`,
//! * a **cubic growth function** `W(t) = C*(t-K)^3 + W_max` in congestion
//!   avoidance, floored by a TCP-friendly `+MSS`-per-RTT term so it never grows
//!   slower than Reno in the concave part of the curve,
//! * **multiplicative decrease** to `beta * cwnd` on loss, with fast
//!   convergence when a second loss hits an already-reduced window.
//!
//! It is deliberately *not* a byte-perfect RFC 8312 transcription: the RFC is
//! written in segments and per-ACK bookkeeping, and the extra machinery buys
//! nothing until the QUIC transport lands. `docs/PLAN.md` records that stage 2
//! replaces this with `quinn`'s CUBIC; the public surface here is kept small so
//! that swap is local.

/// CUBIC's cubic constant.
const C: f64 = 0.4;
/// Multiplicative decrease factor (`1 - beta` is the fraction removed).
const BETA: f64 = 0.7;
/// Floor of the congestion window, in MSS.
const MIN_CWND_MSS: f64 = 2.0;

/// Byte-based CUBIC controller.
#[derive(Debug, Clone)]
pub struct Cubic {
    mss: f64,
    cwnd: f64,
    ssthresh: f64,
    w_max: f64,
    epoch_start_us: u64,
    /// False until the first congestion-avoidance ACK after a loss/timeout.
    epoch_open: bool,
}

impl Cubic {
    /// Create a controller for a given maximum segment size in bytes.
    #[must_use]
    pub fn new(mss: u32) -> Self {
        let mss = f64::from(mss.max(1));
        Self {
            mss,
            cwnd: 10.0 * mss, // RFC 9002 initial window (10 * max_datagram_size)
            ssthresh: f64::INFINITY,
            w_max: 0.0,
            epoch_start_us: 0,
            epoch_open: false,
        }
    }

    /// Current congestion window, in bytes.
    #[must_use]
    pub fn cwnd(&self) -> u64 {
        self.cwnd.max(0.0) as u64
    }

    /// Current slow-start threshold, in bytes (`u64::MAX` while unknown).
    #[must_use]
    pub fn ssthresh(&self) -> u64 {
        if self.ssthresh.is_finite() {
            self.ssthresh.max(0.0) as u64
        } else {
            u64::MAX
        }
    }

    /// True while the window is still growing exponentially.
    #[must_use]
    pub fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// May we put more bytes on the wire?
    #[must_use]
    pub fn can_send(&self, bytes_in_flight: u64) -> bool {
        (bytes_in_flight as f64) < self.cwnd
    }

    fn min_cwnd(&self) -> f64 {
        MIN_CWND_MSS * self.mss
    }

    /// `K = cbrt(W_max * (1 - beta) / C)` — the time to reach `W_max` again.
    fn k(&self) -> f64 {
        ((self.w_max * (1.0 - BETA)) / C).cbrt()
    }

    /// The cubic target window at time `t_s` seconds into the current epoch.
    fn target(&self, t_s: f64) -> f64 {
        (self.w_max + C * (t_s - self.k()).powi(3)).max(self.min_cwnd())
    }

    /// Account for `acked` newly delivered bytes.
    pub fn on_ack(&mut self, acked: u64, now_us: u64, srtt_us: u64) {
        let acked = acked as f64;
        if acked <= 0.0 {
            return;
        }
        if self.cwnd < self.ssthresh {
            // slow start: one segment out for every segment acknowledged
            self.cwnd += acked;
            return;
        }
        if !self.epoch_open {
            self.epoch_start_us = now_us;
            self.epoch_open = true;
        }
        let elapsed = now_us.saturating_sub(self.epoch_start_us) as f64 / 1_000_000.0;
        let t = elapsed + srtt_us as f64 / 1_000_000.0;
        let target = self.target(t);
        // Cubic increment, floored by the TCP-friendly +MSS-per-RTT term.
        let cubic_inc = (target - self.cwnd) * acked / self.cwnd;
        let tcp_inc = self.mss * acked / self.cwnd;
        self.cwnd += cubic_inc.max(tcp_inc).max(0.0);
    }

    /// Account for a fast-loss / fast-retransmit signal.
    pub fn on_loss(&mut self, now_us: u64) {
        if self.cwnd < self.w_max {
            // fast convergence: a second loss means the path may have shrunk
            self.w_max = self.cwnd * (1.0 + BETA) / 2.0;
        } else {
            self.w_max = self.cwnd;
        }
        self.ssthresh = (self.cwnd * BETA).max(self.min_cwnd());
        self.cwnd = self.ssthresh;
        self.epoch_start_us = now_us;
        self.epoch_open = true;
    }

    /// Account for a retransmission timeout: collapse to the floor.
    pub fn on_timeout(&mut self) {
        self.w_max = self.cwnd;
        self.ssthresh = (self.cwnd * BETA).max(self.min_cwnd());
        self.cwnd = self.min_cwnd();
        // restart the epoch lazily on the next congestion-avoidance ACK
        self.epoch_open = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: u32 = 1200;
    const SRTT: u64 = 40_000; // 40 ms

    #[test]
    fn initial_window_is_ten_segments() {
        let cc = Cubic::new(MSS);
        assert_eq!(cc.cwnd(), 10 * u64::from(MSS));
        assert!(cc.in_slow_start());
        assert!(cc.can_send(0));
        assert!(!cc.can_send(10 * u64::from(MSS)));
    }

    #[test]
    fn slow_start_doubles_per_rtt() {
        let mut cc = Cubic::new(MSS);
        let start = cc.cwnd();
        // one RTT worth of acknowledged data
        cc.on_ack(start, 1_000_000, SRTT);
        assert_eq!(cc.cwnd(), start * 2);
        assert!(cc.in_slow_start());
    }

    #[test]
    fn loss_reduces_to_beta_and_sets_threshold() {
        let mut cc = Cubic::new(MSS);
        cc.on_ack(20 * u64::from(MSS), 1_000_000, SRTT);
        let before = cc.cwnd();
        cc.on_loss(1_100_000);
        assert!(!cc.in_slow_start());
        assert_eq!(cc.ssthresh(), (before as f64 * BETA) as u64);
        assert_eq!(cc.cwnd(), cc.ssthresh());
    }

    #[test]
    fn congestion_avoidance_grows_again_toward_wmax() {
        let mut cc = Cubic::new(MSS);
        cc.on_ack(30 * u64::from(MSS), 1_000_000, SRTT);
        cc.on_loss(2_000_000);
        let after_loss = cc.cwnd();
        let mut now = 2_000_000u64;
        for _ in 0..200 {
            now += SRTT;
            cc.on_ack(u64::from(MSS), now, SRTT);
        }
        assert!(
            cc.cwnd() > after_loss,
            "cwnd must recover after a loss: {} -> {}",
            after_loss,
            cc.cwnd()
        );
    }

    #[test]
    fn timeout_collapses_to_the_floor_and_restarts_slow_start() {
        let mut cc = Cubic::new(MSS);
        cc.on_ack(40 * u64::from(MSS), 1_000_000, SRTT);
        cc.on_timeout();
        assert_eq!(cc.cwnd(), 2 * u64::from(MSS));
        // ssthresh stays above the floor, so the next RTT slow-starts again
        assert!(cc.in_slow_start());
        cc.on_ack(2 * u64::from(MSS), 1_100_000, SRTT);
        assert_eq!(cc.cwnd(), 4 * u64::from(MSS));
    }

    #[test]
    fn fast_convergence_reduces_wmax_on_second_loss() {
        let mut cc = Cubic::new(MSS);
        cc.on_ack(100 * u64::from(MSS), 1_000_000, SRTT); // w_max target high
        cc.on_loss(2_000_000);
        let wmax_first = cc.w_max;
        // grow a little, then lose again without exceeding the first w_max
        cc.on_ack(u64::from(MSS), 2_100_000, SRTT);
        cc.on_loss(2_200_000);
        assert!(cc.w_max < wmax_first, "fast convergence must lower W_max");
    }

    #[test]
    fn zero_ack_is_a_no_op() {
        let mut cc = Cubic::new(MSS);
        let before = cc.cwnd();
        cc.on_ack(0, 1_000, SRTT);
        assert_eq!(cc.cwnd(), before);
    }
}
