//! Anti-replay sliding window.
//!
//! Each session keeps one window per direction. A packet number strictly below
//! `highest - WINDOW_BITS` is rejected immediately; a number inside the window
//! is rejected if its bit is already set. Checking and marking happen in one
//! call so a caller cannot forget to mark.
//!
//! Hand-rolled bitmap (64 x u64 = 4096 bits, 512 bytes) rather than a bitvec
//! dependency: it is ~80 lines, trivially auditable, and has no shifting-API
//! surprises between crate versions.

use crate::error::{Error, Result};

/// Window size in bits (packets).
pub const WINDOW_BITS: usize = 4096;
const WORDS: usize = WINDOW_BITS / 64;

/// Sliding bitmap of recently accepted packet numbers.
#[derive(Debug)]
pub struct ReplayWindow {
    highest: u64,
    /// bit index `i` (0 = most recent, i.e. `highest`) is set when seen.
    seen: [u64; WORDS],
    initialized: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// Empty window that accepts everything.
    #[must_use]
    pub fn new() -> Self {
        Self {
            highest: 0,
            seen: [0u64; WORDS],
            initialized: false,
        }
    }

    fn get(&self, idx: usize) -> bool {
        self.seen[idx / 64] & (1u64 << (idx % 64)) != 0
    }

    fn set(&mut self, idx: usize) {
        self.seen[idx / 64] |= 1u64 << (idx % 64);
    }

    /// Shift every bit towards higher indices by `n` (i.e. age each entry).
    fn shift_up(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        if n >= WINDOW_BITS {
            self.seen = [0u64; WORDS];
            return;
        }
        let word_shift = n / 64;
        let bit_shift = n % 64;

        if word_shift > 0 {
            for i in (0..WORDS).rev() {
                self.seen[i] = if i >= word_shift {
                    self.seen[i - word_shift]
                } else {
                    0
                };
            }
        }
        if bit_shift > 0 {
            for i in (0..WORDS).rev() {
                let carry = if i > 0 {
                    self.seen[i - 1] >> (64 - bit_shift)
                } else {
                    0
                };
                self.seen[i] = (self.seen[i] << bit_shift) | carry;
            }
        }
    }

    /// Test a packet number and, if it is fresh, mark it as seen.
    ///
    /// Returns [`Error::Replay`] if the number is a duplicate or too old.
    pub fn check_and_mark(&mut self, pn: u64) -> Result<()> {
        if !self.initialized {
            self.initialized = true;
            self.highest = pn;
            self.seen = [0u64; WORDS];
            self.set(0);
            return Ok(());
        }

        if pn > self.highest {
            let shift = pn - self.highest;
            if shift >= WINDOW_BITS as u64 {
                self.seen = [0u64; WORDS];
            } else {
                self.shift_up(shift as usize);
            }
            self.highest = pn;
            self.set(0);
            return Ok(());
        }

        let age = (self.highest - pn) as usize;
        if age >= WINDOW_BITS {
            return Err(Error::Replay(pn));
        }
        if self.get(age) {
            return Err(Error::Replay(pn));
        }
        self.set(age);
        Ok(())
    }

    /// Highest packet number accepted so far.
    #[must_use]
    pub fn highest(&self) -> u64 {
        self.highest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_in_order_and_rejects_duplicates() {
        let mut w = ReplayWindow::new();
        for pn in 0..1000 {
            w.check_and_mark(pn).unwrap();
        }
        assert!(matches!(w.check_and_mark(999), Err(Error::Replay(999))));
        assert!(matches!(w.check_and_mark(0), Err(Error::Replay(0))));
    }

    #[test]
    fn tolerates_reordering_within_window() {
        let mut w = ReplayWindow::new();
        w.check_and_mark(100).unwrap();
        w.check_and_mark(50).unwrap(); // older but inside window
        assert!(matches!(w.check_and_mark(50), Err(Error::Replay(50))));
        w.check_and_mark(101).unwrap();
    }

    #[test]
    fn drops_packets_older_than_window() {
        let mut w = ReplayWindow::new();
        w.check_and_mark(0).unwrap();
        w.check_and_mark(WINDOW_BITS as u64 + 10).unwrap();
        assert!(matches!(w.check_and_mark(1), Err(Error::Replay(1))));
    }

    #[test]
    fn huge_jump_resets_window() {
        let mut w = ReplayWindow::new();
        w.check_and_mark(1).unwrap();
        let far = 10 * WINDOW_BITS as u64;
        w.check_and_mark(far).unwrap();
        assert!(matches!(w.check_and_mark(1), Err(Error::Replay(1))));
        assert!(w.check_and_mark(far + 1).is_ok());
    }

    #[test]
    fn bit_shift_boundaries() {
        let mut w = ReplayWindow::new();
        w.check_and_mark(1).unwrap();
        // shift by exactly 63 and 64 to exercise partial/full word carry
        w.check_and_mark(1 + 63).unwrap();
        let mut w2 = ReplayWindow::new();
        w2.check_and_mark(5).unwrap();
        w2.check_and_mark(5 + 64).unwrap();
        assert!(matches!(w2.check_and_mark(5), Err(Error::Replay(5))));
    }
}
