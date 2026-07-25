// SPDX-License-Identifier: 0BSD
//! Coarse-timestamp freshness check for the DCID authenticator.

use std::time::{SystemTime, UNIX_EPOCH};

pub const WINDOW_MINUTES: u32 = 2;

pub fn now_minutes() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs / 60) as u32
}

pub fn is_fresh(freshness: u32, now: u32, window: u32) -> bool {
    let lo = now.saturating_sub(window);
    let hi = now.saturating_add(window);
    freshness >= lo && freshness <= hi
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_window_is_fresh() {
        assert!(is_fresh(100, 100, 2));
        assert!(is_fresh(98, 100, 2));
        assert!(is_fresh(102, 100, 2));
    }

    #[test]
    fn outside_window_is_stale() {
        assert!(!is_fresh(97, 100, 2));
        assert!(!is_fresh(103, 100, 2));
    }

    #[test]
    fn saturates_at_boundaries() {
        assert!(is_fresh(0, 1, 2)); // now-window would underflow
        assert!(is_fresh(u32::MAX, u32::MAX - 1, 2)); // now+window would overflow
    }
}
