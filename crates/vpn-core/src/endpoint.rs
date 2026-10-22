//! The one session state machine, shared by both peers.
//!
//! Everything a live bProto session does — sealing, opening, acknowledging,
//! estimating RTT, detecting loss, running CUBIC, keepalive, idle expiry — lives
//! here, and here only. The client and the server are the *same* machine with
//! different keys, so there is exactly one implementation to audit and test.
//!
//! This type performs no I/O. It never sees a socket, a clock or a TUN device:
//!
//! * the caller hands it bytes and a timestamp,
//! * it hands back bytes the caller must send, and payloads the caller must
//!   deliver.
//!
//! That is what lets the async runtime (`vpn-rt`) stay a thin, dumb pump, and it
//! is what makes the whole protocol testable synchronously.

use std::collections::VecDeque;
use std::time::Duration;

use crate::ack::{AckRanges, RttEstimator, SentPackets};
use crate::congestion::Cubic;
use crate::crypto::{self, SessionKeys};
use crate::error::{Error, Result};
use crate::frame::{self, FrameType};
use crate::packet::{self, Header, InnerType};
use crate::replay::ReplayWindow;

/// How many received packets trigger an immediate ACK.
pub const ACK_EVERY: u64 = 8;
/// Default inbound silence that triggers a keepalive probe.
pub const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(15);
/// Default inbound silence after which a session is declared dead.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(45);

/// Which half of the key schedule this endpoint holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// `tx` is the client-to-server direction.
    Client,
    /// `tx` is the server-to-client direction.
    Server,
}

/// Tunables for one endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointParams {
    /// Largest IP packet that may be sealed.
    pub mtu: usize,
    /// Send a keepalive probe after this much inbound silence.
    pub keepalive: Duration,
    /// Declare the session dead after this much inbound silence.
    pub idle_timeout: Duration,
}

impl Default for EndpointParams {
    fn default() -> Self {
        Self {
            mtu: packet::TUNNEL_MTU,
            keepalive: DEFAULT_KEEPALIVE,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

/// What the caller must do with a decrypted datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    /// One IP packet, to be written to the TUN.
    Ip(Vec<u8>),
    /// A keepalive with no payload.
    Keepalive,
    /// A control frame the protocol consumed itself (ACK, PING, PONG, CLOSE).
    /// The caller has nothing to deliver.
    Consumed,
    /// The peer asked to close the session.
    Closed,
}

/// Health snapshot for status displays and the control panel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EndpointStats {
    /// Smoothed RTT in microseconds; `0` until the first ACK arrives.
    pub rtt_us: u64,
    /// Congestion window in bytes.
    pub cwnd_bytes: u64,
    /// Bytes authenticated and decrypted.
    pub rx_bytes: u64,
    /// Bytes sealed.
    pub tx_bytes: u64,
    /// Datagrams dropped (authentication failure or replay).
    pub dropped: u64,
    /// Bytes currently in flight.
    pub in_flight: u64,
}

/// A live bProto session. Pure state, no I/O.
#[derive(Debug)]
pub struct Endpoint {
    role: Role,
    keys: SessionKeys,
    session_tag: u32,
    params: EndpointParams,

    tx_pn: u64,
    rx_replay: ReplayWindow,

    rx_bytes: u64,
    tx_bytes: u64,
    dropped: u64,

    ack_out: AckRanges,
    ack_pending: u64,

    sent: SentPackets,
    rtt: RttEstimator,
    cc: Cubic,

    /// Control datagrams the protocol produced and the caller must send.
    outbox: VecDeque<Vec<u8>>,

    last_rx_us: u64,
    last_ping_us: u64,
    closed: bool,
}

impl Endpoint {
    /// Build an endpoint from an already-negotiated key schedule.
    ///
    /// `now_us` is the caller's monotonic clock; it seeds the idle timer so a
    /// session created long after the process started is not instantly reaped.
    #[must_use]
    pub fn established(
        role: Role,
        keys: SessionKeys,
        session_tag: u32,
        params: EndpointParams,
        now_us: u64,
    ) -> Self {
        Self {
            role,
            keys,
            session_tag,
            params,
            tx_pn: 0,
            rx_replay: ReplayWindow::new(),
            rx_bytes: 0,
            tx_bytes: 0,
            dropped: 0,
            ack_out: AckRanges::new(),
            ack_pending: 0,
            sent: SentPackets::default(),
            rtt: RttEstimator::default(),
            cc: Cubic::new(params.mtu as u32),
            outbox: VecDeque::new(),
            last_rx_us: now_us,
            last_ping_us: now_us,
            closed: false,
        }
    }

    /// Which half of the key schedule this endpoint holds.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// The routing tag both peers put in the datagram header.
    #[must_use]
    pub fn session_tag(&self) -> u32 {
        self.session_tag
    }

    /// Largest IP packet that may be sealed.
    #[must_use]
    pub fn mtu(&self) -> usize {
        self.params.mtu
    }

    /// True once the peer sent CLOSE or this endpoint was closed locally.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Health snapshot.
    #[must_use]
    pub fn stats(&self) -> EndpointStats {
        EndpointStats {
            rtt_us: self.rtt.smoothed(),
            cwnd_bytes: self.cc.cwnd(),
            rx_bytes: self.rx_bytes,
            tx_bytes: self.tx_bytes,
            dropped: self.dropped,
            in_flight: self.sent.bytes_in_flight(),
        }
    }

    /// Whether the congestion window has room for another packet right now.
    #[must_use]
    pub fn can_send(&self) -> bool {
        self.cc.can_send(self.sent.bytes_in_flight())
    }

    // -----------------------------------------------------------------------
    // Sending
    // -----------------------------------------------------------------------

    /// Encrypt one IP packet and return the datagram to send.
    ///
    /// The packet is registered as in-flight so an ACK can later produce an RTT
    /// sample and release congestion window. This does *not* block when the
    /// window is full — call [`Self::can_send`] first if you care.
    pub fn seal_ip(&mut self, ip: &[u8], now_us: u64) -> Result<Vec<u8>> {
        if ip.len() > self.params.mtu {
            return Err(Error::PayloadTooLarge(ip.len(), self.params.mtu));
        }
        let dgram = self.seal_inner(InnerType::Ip, ip)?;
        self.tx_bytes += ip.len() as u64;
        self.sent
            .on_sent(self.tx_pn - 1, now_us, dgram.len() as u64);
        Ok(dgram)
    }

    /// Queue a graceful close for the peer. The datagram is sent with the next
    /// [`Self::take_outbox`] drain.
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.queue_control(&frame::simple(FrameType::Close));
    }

    /// Take every datagram the protocol wants to send on its own initiative:
    /// ACKs, PONG replies, keepalive probes, CLOSE.
    #[must_use]
    pub fn take_outbox(&mut self) -> Vec<Vec<u8>> {
        self.outbox.drain(..).collect()
    }

    fn queue_control(&mut self, frame: &[u8]) {
        match self.seal_inner(InnerType::Control, frame) {
            Ok(dgram) => self.outbox.push_back(dgram),
            Err(e) => tracing::debug!(error = %e, "could not seal a control frame"),
        }
    }

    fn seal_inner(&mut self, ty: InnerType, payload: &[u8]) -> Result<Vec<u8>> {
        let pn = self.tx_pn;
        if pn >= (1u64 << 40) {
            return Err(Error::Transport("packet number space exhausted".into()));
        }
        self.tx_pn = pn + 1;

        let header = Header::new(0, self.session_tag, pn);
        let aad = header.encode();
        let inner = packet::encode_inner(ty, payload, None);
        let ct = crypto::seal(
            &self.keys.tx_key,
            &self.keys.tx_nonce_prefix,
            &aad,
            pn,
            &inner,
        )?;

        let mut out = Vec::with_capacity(aad.len() + ct.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // Receiving
    // -----------------------------------------------------------------------

    /// Authenticate and decrypt one datagram.
    ///
    /// Control frames are handled entirely inside: an ACK advances the RTT
    /// estimate and the congestion window, a PING queues a PONG. Those replies
    /// land in the outbox and are returned by [`Self::take_outbox`].
    pub fn open(&mut self, datagram: &[u8], now_us: u64) -> Result<Opened> {
        let header = Header::decode(datagram)?;
        if header.reserved != 0 {
            return Err(Error::Config("non-zero reserved header field".into()));
        }
        let aad = &datagram[..packet::HEADER_LEN];
        let ct = &datagram[packet::HEADER_LEN..];

        // Authenticate first: an attacker must not be able to poison the replay
        // window with packet numbers of its choosing.
        let plaintext = crypto::open(
            &self.keys.rx_key,
            &self.keys.rx_nonce_prefix,
            aad,
            header.packet_number,
            ct,
        )
        .inspect_err(|_| self.dropped += 1)?;

        if self.rx_replay.check_and_mark(header.packet_number).is_err() {
            self.dropped += 1;
            return Err(Error::Replay(header.packet_number));
        }

        self.last_rx_us = now_us;
        let (ty, payload) = packet::decode_inner(&plaintext)?;
        match ty {
            InnerType::Ip => {
                self.rx_bytes += payload.len() as u64;
                self.record_received(header.packet_number);
                Ok(Opened::Ip(payload.to_vec()))
            }
            InnerType::Keepalive => {
                self.record_received(header.packet_number);
                Ok(Opened::Keepalive)
            }
            InnerType::Control => {
                self.record_received(header.packet_number);
                Ok(self.handle_control(payload, now_us))
            }
        }
    }

    fn record_received(&mut self, pn: u64) {
        self.ack_out.insert(pn);
        self.ack_pending += 1;
        if self.ack_pending >= ACK_EVERY {
            self.flush_ack();
        }
    }

    fn flush_ack(&mut self) {
        if self.ack_out.is_empty() {
            return;
        }
        let ranges = std::mem::take(&mut self.ack_out);
        self.ack_pending = 0;
        self.queue_control(&ranges.encode());
    }

    fn handle_control(&mut self, payload: &[u8], now_us: u64) -> Opened {
        match frame::peek_type(payload) {
            Ok(FrameType::Ack) => {
                let Ok(ranges) = AckRanges::decode(payload) else {
                    return Opened::Consumed;
                };
                let srtt = self.rtt.smoothed();
                let mut acked_bytes = 0u64;
                let mut newest: Option<(u64, u64)> = None;
                ranges.for_each(|pn| {
                    if let Some((sent_at, bytes)) = self.sent.ack(pn) {
                        acked_bytes += bytes;
                        let sample = now_us.saturating_sub(sent_at);
                        if newest.is_none_or(|(prev, _)| pn > prev) {
                            newest = Some((pn, sample));
                        }
                    }
                });
                if acked_bytes > 0 {
                    self.cc.on_ack(acked_bytes, now_us, srtt);
                }
                if let Some((_, sample)) = newest {
                    self.rtt.update(sample);
                }
                Opened::Consumed
            }
            Ok(FrameType::Ping) => {
                self.queue_control(&frame::simple(FrameType::Pong));
                Opened::Consumed
            }
            Ok(FrameType::Close) => {
                self.closed = true;
                Opened::Closed
            }
            // Pong, Hello, HelloAck and anything unknown: nothing to do. Our own
            // PONG is the only reply we ever owe.
            _ => Opened::Consumed,
        }
    }

    // -----------------------------------------------------------------------
    // Housekeeping
    // -----------------------------------------------------------------------

    /// Periodic maintenance. Call this on a timer (20 ms is plenty) and send
    /// whatever [`Self::take_outbox`] then returns.
    ///
    /// Returns `true` when the session has been idle past its idle timeout and
    /// the caller should tear it down.
    pub fn poll(&mut self, now_us: u64) -> bool {
        self.flush_ack();

        let keepalive_us = self.params.keepalive.as_micros() as u64;
        let idle_us = self.params.idle_timeout.as_micros() as u64;
        let idle = now_us.saturating_sub(self.last_rx_us);

        if idle >= idle_us {
            return true;
        }
        if idle >= keepalive_us && now_us.saturating_sub(self.last_ping_us) >= keepalive_us {
            self.last_ping_us = now_us;
            self.queue_control(&frame::simple(FrameType::Ping));
        }

        // Loss detected by timeout still has to back CUBIC off; there is no
        // other signal when the peer goes quiet mid-flight.
        let pto = self.rtt.pto();
        if !self.sent.timed_out(now_us, pto).is_empty() {
            self.cc.on_loss(now_us);
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;

    fn pair(mtu: usize) -> (Endpoint, Endpoint) {
        let shared = [7u8; 32];
        let params = EndpointParams {
            mtu,
            ..EndpointParams::default()
        };
        let client = Endpoint::established(
            Role::Client,
            crypto::derive_session_keys(&shared, &[1; 32], &[2; 32], true),
            0x1234,
            params,
            NOW,
        );
        let server = Endpoint::established(
            Role::Server,
            crypto::derive_session_keys(&shared, &[1; 32], &[2; 32], false),
            0x1234,
            params,
            NOW,
        );
        (client, server)
    }

    /// Drive `from`'s outbox into `to`, returning what `to` made of it.
    fn pump(from: &mut Endpoint, to: &mut Endpoint, now_us: u64) -> Vec<Opened> {
        let mut out = Vec::new();
        for dgram in from.take_outbox() {
            out.push(to.open(&dgram, now_us).expect("peer must accept"));
        }
        out
    }

    #[test]
    fn ip_traffic_roundtrips_and_is_counted() {
        let (mut c, mut s) = pair(packet::TUNNEL_MTU);
        let ip = vec![0x45u8; 60];
        let dgram = c.seal_ip(&ip, NOW).unwrap();
        assert_eq!(Header::decode(&dgram).unwrap().session_tag, 0x1234);
        assert_eq!(s.open(&dgram, NOW).unwrap(), Opened::Ip(ip));
        assert_eq!(s.stats().rx_bytes, 60);
        assert_eq!(c.stats().tx_bytes, 60);
    }

    #[test]
    fn oversized_payload_is_refused_before_encryption() {
        let (mut c, _s) = pair(packet::TUNNEL_MTU);
        assert!(matches!(
            c.seal_ip(&vec![0u8; packet::TUNNEL_MTU + 1], NOW),
            Err(Error::PayloadTooLarge(_, _))
        ));
        assert!(c.seal_ip(&vec![0u8; packet::TUNNEL_MTU], NOW).is_ok());
    }

    #[test]
    fn replay_and_forgery_are_rejected_and_counted() {
        let (mut c, mut s) = pair(packet::TUNNEL_MTU);

        let mut forged = c.seal_ip(&[0x45; 20], NOW).unwrap();
        let last = forged.len() - 1;
        forged[last] ^= 0x80;
        assert!(matches!(s.open(&forged, NOW), Err(Error::Decrypt)));

        let good = c.seal_ip(&[0x45; 20], NOW).unwrap();
        s.open(&good, NOW).unwrap();
        assert!(matches!(s.open(&good, NOW), Err(Error::Replay(_))));
        assert_eq!(s.stats().dropped, 2);
    }

    #[test]
    fn a_tampered_header_fails_authentication() {
        let (mut c, mut s) = pair(packet::TUNNEL_MTU);
        let mut dgram = c.seal_ip(&[0x45; 20], NOW).unwrap();
        dgram[10] ^= 0xFF; // the reserved field is covered by the AAD
        assert!(matches!(s.open(&dgram, NOW), Err(Error::Config(_))));
    }

    #[test]
    fn acks_are_flushed_every_eight_packets_and_feed_the_rtt() {
        let (mut c, mut s) = pair(packet::TUNNEL_MTU);
        for i in 0..ACK_EVERY {
            let dgram = c.seal_ip(&[0x45; 20], NOW + i).unwrap();
            s.open(&dgram, NOW + i).unwrap();
        }
        // The eighth packet triggers an immediate ACK, no timer needed.
        let acks = s.take_outbox();
        assert_eq!(acks.len(), 1, "an ACK must be queued on the eighth packet");
        assert_eq!(
            Header::decode(&acks[0]).unwrap().session_tag,
            0x1234,
            "the ACK must be sealed under the shared session tag"
        );

        // Feeding it back must release every in-flight byte and produce an RTT
        // sample, which is the whole point of acknowledging.
        assert!(
            c.stats().in_flight > 0,
            "bytes are in flight before the ACK"
        );
        assert_eq!(c.stats().rtt_us, c.rtt.initial(), "no sample yet");
        for dgram in &acks {
            c.open(dgram, NOW + 1_000).unwrap();
        }
        assert_eq!(c.stats().in_flight, 0, "ACKs release in-flight bytes");
        assert!(
            c.stats().rtt_us > 0 && c.stats().rtt_us <= 1_000,
            "an RTT sample must land: got {}",
            c.stats().rtt_us
        );
    }

    #[test]
    fn ping_is_answered_with_pong_without_caller_involvement() {
        let (mut c, mut s) = pair(packet::TUNNEL_MTU);
        c.queue_control(&frame::simple(FrameType::Ping));
        let opened = pump(&mut c, &mut s, NOW);
        assert_eq!(opened, vec![Opened::Consumed]);
        // The server queued a PONG; the client consumes it silently.
        let opened = pump(&mut s, &mut c, NOW);
        assert_eq!(opened, vec![Opened::Consumed]);
    }

    #[test]
    fn keepalive_fires_after_the_keepalive_interval_and_only_once() {
        let (mut c, _s) = pair(packet::TUNNEL_MTU);
        let idle = c.params.keepalive.as_micros() as u64;
        assert!(!c.poll(NOW + idle - 1));
        assert!(c.take_outbox().is_empty());

        assert!(!c.poll(NOW + idle));
        assert_eq!(c.take_outbox().len(), 1, "one keepalive probe");

        // Immediately again: still inside the ping interval, so no second probe.
        assert!(!c.poll(NOW + idle + 1));
        assert!(c.take_outbox().is_empty());
    }

    #[test]
    fn a_session_born_late_is_not_instantly_expired() {
        // Regression: seeding `last_rx_us` from 0 made every session created
        // more than `idle_timeout` after start-up get reaped on the first tick.
        let (_c, s) = pair(packet::TUNNEL_MTU);
        let born = 300_000_000u64;
        let mut late = s;
        late.last_rx_us = born;
        let idle_us = late.params.idle_timeout.as_micros() as u64;
        assert!(!late.poll(born + 1_000_000));
        assert!(late.poll(born + idle_us));
    }

    #[test]
    fn close_is_queued_once_and_the_peer_sees_it() {
        let (mut c, mut s) = pair(packet::TUNNEL_MTU);
        c.close();
        assert!(c.is_closed());
        let out = c.take_outbox();
        assert_eq!(out.len(), 1);
        c.close();
        assert!(c.take_outbox().is_empty(), "close must be sent once");

        assert_eq!(s.open(&out[0], NOW).unwrap(), Opened::Closed);
        assert!(s.is_closed());
    }

    #[test]
    fn congestion_window_gates_sending() {
        let (mut c, _s) = pair(packet::TUNNEL_MTU);
        assert!(c.can_send(), "an idle endpoint must have room");
        // Fill the window without ever being ACKed.
        let mut sent = 0;
        while c.can_send() && sent < 10_000 {
            c.seal_ip(&[0x45; packet::TUNNEL_MTU], NOW).unwrap();
            sent += 1;
        }
        assert!(!c.can_send(), "an unacked flood must eventually block");
        assert!(sent > 1, "the initial window holds more than one packet");
    }
}
