// SPDX-License-Identifier: 0BSD
//! Bounded anti-replay set over (nonce, freshness) within the acceptance window.

use std::collections::HashSet;

pub struct ReplayGuard {
    window: u32,
    seen: HashSet<([u8; 8], u32)>,
}

impl ReplayGuard {
    pub fn new(window_minutes: u32) -> Self {
        Self {
            window: window_minutes,
            seen: HashSet::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    pub fn check_and_record(&mut self, nonce: [u8; 8], freshness: u32, now: u32) -> bool {
        let cutoff = now.saturating_sub(self.window);
        self.seen.retain(|(_, f)| *f >= cutoff);
        self.seen.insert((nonce, freshness))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sighting_accepted() {
        let mut g = ReplayGuard::new(2);
        assert!(g.check_and_record([1u8; 8], 100, 100));
    }

    #[test]
    fn exact_replay_rejected() {
        let mut g = ReplayGuard::new(2);
        assert!(g.check_and_record([1u8; 8], 100, 100));
        assert!(!g.check_and_record([1u8; 8], 100, 100));
    }

    #[test]
    fn different_nonce_accepted() {
        let mut g = ReplayGuard::new(2);
        assert!(g.check_and_record([1u8; 8], 100, 100));
        assert!(g.check_and_record([2u8; 8], 100, 100));
    }

    #[test]
    fn expired_entries_purged() {
        let mut g = ReplayGuard::new(2);
        assert!(g.check_and_record([1u8; 8], 100, 100));
        // advance now well past window; old entry purged so memory bounded
        assert!(g.check_and_record([9u8; 8], 200, 200));
        assert_eq!(g.len(), 1);
    }
}
