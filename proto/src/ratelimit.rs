// SPDX-License-Identifier: 0BSD
//! Rate limiting for the unauthenticated pre-filter path.
//!
//! Every datagram whose DCID does not belong to an active connection runs the
//! silence pre-filter (selector parse, freshness check, PSK scan, replay
//! guard) BEFORE the server can tell whether the sender is legitimate. That
//! work is cheap per-packet but not free, so a flood of junk can still burn
//! CPU even though every packet is eventually dropped silently. [`RateLimiter`]
//! sits in front of the pre-filter and rejects packets — at near-zero cost —
//! once a source (or the server as a whole) is sending faster than the
//! configured budget.
//!
//! Rejected packets are dropped with the exact same silence contract as every
//! other pre-filter failure: no bytes emitted, `Endpoint::handle` never
//! called.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// A classic token bucket: `capacity` tokens max, refilling continuously at
/// `refill_per_sec` tokens/sec. Each accepted packet costs one token.
pub struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    tokens: f64,
    /// Lazily initialized on the first `try_take` call, to the `now` the
    /// caller passes in — NOT `Instant::now()` at construction time. `new`
    /// takes no `now` parameter, and calling `Instant::now()` inside it would
    /// create a tiny skew against whatever `now` a caller (e.g. a test using a
    /// fixed `t0`) later passes to `try_take`, causing sub-millisecond refill
    /// shortfalls. Deferring initialization to the first `try_take` avoids
    /// that entirely: the bucket never "loses" partial elapsed time to a clock
    /// read it didn't ask for.
    last_update: Option<Instant>,
}

impl TokenBucket {
    /// A bucket that starts full (so the very first burst up to `capacity` is
    /// never penalized) and refills at `refill_per_sec` tokens/sec.
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            tokens: capacity,
            last_update: None,
        }
    }

    /// Refill based on elapsed time, then try to take one token. Returns
    /// `true` (and debits a token) if one was available, `false` otherwise.
    pub fn try_take(&mut self, now: Instant) -> bool {
        match self.last_update {
            None => {
                self.last_update = Some(now);
            }
            Some(last) => {
                let elapsed = now.saturating_duration_since(last).as_secs_f64();
                if elapsed > 0.0 {
                    self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
                    self.last_update = Some(now);
                }
            }
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Default per-source bucket: allows a burst of 32 packets, then ~8/sec
/// sustained. Generous enough that a legitimate client's connection attempt
/// (plus any handshake retransmits) never trips it, while still bounding the
/// cost any single (possibly spoofed) source IP can inflict.
const DEFAULT_PER_SOURCE_CAPACITY: f64 = 32.0;
const DEFAULT_PER_SOURCE_REFILL: f64 = 8.0;

/// Default global bucket: allows a burst of 2048 packets, then ~512/sec
/// sustained across ALL sources. This is the real backstop — UDP source IPs
/// are trivially spoofable, so a flood spread across many fake source
/// addresses would evade a per-IP-only limit. The global bucket caps total
/// pre-filter work regardless of how the flood is distributed, while still
/// being generous enough for many legitimate clients connecting at once.
const DEFAULT_GLOBAL_CAPACITY: f64 = 2048.0;
const DEFAULT_GLOBAL_REFILL: f64 = 512.0;

/// Maximum number of distinct source IPs tracked at once. Bounds the map's
/// own memory so it cannot itself become an amplification vector: without a
/// cap, a spoofed-source flood using a fresh IP per packet would grow the map
/// without bound. When full, the least-recently-used entry is evicted to make
/// room for a new source.
const MAX_TRACKED_SOURCES: usize = 4096;

/// Rate limiter for the unauthenticated pre-filter path: a global bucket plus
/// a bounded set of per-source buckets keyed by [`IpAddr`].
///
/// UDP source addresses are spoofable, so per-source limiting alone can be
/// evaded by spraying junk from many forged IPs. The global bucket is the
/// real backstop: it caps total pre-filter work no matter how a flood is
/// distributed across source addresses. Per-source buckets exist to stop a
/// *single* noisy (non-spoofing) source from consuming the whole global
/// budget and starving other legitimate connecting clients.
pub struct RateLimiter {
    global: TokenBucket,
    per_source: HashMap<IpAddr, SourceEntry>,
    /// Intrusive doubly-linked LRU. Links live beside each bucket, making hits
    /// and evictions O(1) instead of scanning a vector under source churn.
    lru_head: Option<IpAddr>,
    lru_tail: Option<IpAddr>,
    per_source_capacity: f64,
    per_source_refill: f64,
    max_tracked: usize,
}

struct SourceEntry {
    bucket: TokenBucket,
    older: Option<IpAddr>,
    newer: Option<IpAddr>,
}

impl RateLimiter {
    /// A limiter with the documented defaults (see the module-level constants
    /// above): generous enough not to drop a legitimate client's connection
    /// burst, tight enough to bound flood cost.
    pub fn new() -> Self {
        Self::with_params(
            DEFAULT_GLOBAL_CAPACITY,
            DEFAULT_GLOBAL_REFILL,
            DEFAULT_PER_SOURCE_CAPACITY,
            DEFAULT_PER_SOURCE_REFILL,
            MAX_TRACKED_SOURCES,
        )
    }

    /// Fully parameterized constructor, mainly for tests that need tighter
    /// budgets to exercise saturation without sending huge flood volumes.
    pub fn with_params(
        global_capacity: f64,
        global_refill: f64,
        per_source_capacity: f64,
        per_source_refill: f64,
        max_tracked: usize,
    ) -> Self {
        Self {
            global: TokenBucket::new(global_capacity, global_refill),
            per_source: HashMap::new(),
            lru_head: None,
            lru_tail: None,
            per_source_capacity,
            per_source_refill,
            max_tracked,
        }
    }

    /// Check whether a packet from `src` may proceed to the pre-filter.
    /// Consults BOTH the per-source bucket and the global bucket; a packet is
    /// allowed only if both have a token available. Cheap: a hash-map lookup
    /// plus O(1) float arithmetic, so this is safe to call before any
    /// MAC/HKDF work.
    pub fn check(&mut self, src: IpAddr, now: Instant) -> bool {
        // Security invariant: the global bucket is checked FIRST and has no
        // per-source reset, so it caps total pre-filter work even when LRU
        // eviction hands a churning attacker a fresh per-source bucket. Do NOT
        // reorder: consulting the per-source bucket first would let IP-churn
        // evade the global cap — a flood spraying a fresh (spoofed) source IP
        // per packet would get a brand-new full per-source bucket each time and
        // sail past a per-source-only check, so the global bucket must be the
        // gate that fires before any per-source state is even consulted.
        //
        // Checking global first also means we don't touch (grow) the per-source
        // map under a global flood once the server-wide budget is exhausted.
        if !self.global.try_take(now) {
            return false;
        }
        self.touch_source(src).try_take(now)
    }

    /// Get (or create) the bucket for `src`, updating LRU order (moving `src`
    /// to most-recently-used), evicting the least-recently-used source first
    /// if the map is at capacity and `src` is new.
    fn touch_source(&mut self, src: IpAddr) -> &mut TokenBucket {
        if self.per_source.contains_key(&src) {
            self.detach(src);
        } else {
            if self.per_source.len() >= self.max_tracked.max(1) {
                if let Some(oldest) = self.lru_head {
                    self.detach(oldest);
                    self.per_source.remove(&oldest);
                }
            }
            self.per_source.insert(
                src,
                SourceEntry {
                    bucket: TokenBucket::new(self.per_source_capacity, self.per_source_refill),
                    older: None,
                    newer: None,
                },
            );
        }
        self.attach_newest(src);
        &mut self
            .per_source
            .get_mut(&src)
            .expect("source inserted")
            .bucket
    }

    fn detach(&mut self, src: IpAddr) {
        let (older, newer) = {
            let entry = self.per_source.get(&src).expect("LRU source exists");
            (entry.older, entry.newer)
        };
        match older {
            Some(ip) => {
                self.per_source
                    .get_mut(&ip)
                    .expect("older link exists")
                    .newer = newer
            }
            None => self.lru_head = newer,
        }
        match newer {
            Some(ip) => {
                self.per_source
                    .get_mut(&ip)
                    .expect("newer link exists")
                    .older = older
            }
            None => self.lru_tail = older,
        }
        let entry = self.per_source.get_mut(&src).expect("LRU source exists");
        entry.older = None;
        entry.newer = None;
    }

    fn attach_newest(&mut self, src: IpAddr) {
        let old_tail = self.lru_tail;
        {
            let entry = self.per_source.get_mut(&src).expect("LRU source exists");
            entry.older = old_tail;
            entry.newer = None;
        }
        if let Some(tail) = old_tail {
            self.per_source.get_mut(&tail).expect("tail exists").newer = Some(src);
        } else {
            self.lru_head = Some(src);
        }
        self.lru_tail = Some(src);
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn bucket_allows_up_to_capacity_then_blocks() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(3.0, 1.0);
        assert!(b.try_take(t0));
        assert!(b.try_take(t0));
        assert!(b.try_take(t0));
        assert!(!b.try_take(t0));
    }

    #[test]
    fn bucket_refills_over_time() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(1.0, 1.0);
        assert!(b.try_take(t0));
        assert!(!b.try_take(t0));
        assert!(b.try_take(t0 + Duration::from_secs(1)));
    }

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([127, 0, 0, n])
    }

    #[test]
    fn per_source_bucket_blocks_a_single_noisy_source() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::with_params(1000.0, 1000.0, 2.0, 1.0, 16);
        assert!(rl.check(ip(1), t0));
        assert!(rl.check(ip(1), t0));
        assert!(
            !rl.check(ip(1), t0),
            "third packet from same source in same instant must be blocked"
        );
    }

    #[test]
    fn distinct_sources_have_independent_budgets() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::with_params(1000.0, 1000.0, 1.0, 1.0, 16);
        assert!(rl.check(ip(1), t0));
        assert!(!rl.check(ip(1), t0));
        // A different source has its own bucket, unaffected by ip(1)'s usage.
        assert!(rl.check(ip(2), t0));
    }

    #[test]
    fn global_bucket_caps_total_work_across_many_spoofed_sources() {
        let t0 = Instant::now();
        // Tiny global budget, generous per-source budget: proves the global
        // bucket is the real backstop against a spoofed-source flood, since
        // per-source limiting alone can't help when every packet claims a
        // fresh source IP.
        let mut rl = RateLimiter::with_params(3.0, 0.0, 1000.0, 1000.0, 4096);
        assert!(rl.check(ip(1), t0));
        assert!(rl.check(ip(2), t0));
        assert!(rl.check(ip(3), t0));
        // Fourth packet, from a brand-new (never-seen) source: still blocked,
        // because the global budget — not the per-source one — is exhausted.
        assert!(!rl.check(ip(4), t0));
    }

    #[test]
    fn map_is_bounded_and_evicts_lru_source() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::with_params(1_000_000.0, 1_000_000.0, 5.0, 5.0, 2);
        assert!(rl.check(ip(1), t0));
        assert!(rl.check(ip(2), t0));
        assert_eq!(rl.per_source.len(), 2);
        // A third distinct source evicts the LRU entry (ip(1), never touched
        // again) rather than growing the map past `max_tracked`.
        assert!(rl.check(ip(3), t0));
        assert_eq!(
            rl.per_source.len(),
            2,
            "the per-source map must stay bounded even as new sources keep appearing"
        );
        assert!(
            !rl.per_source.contains_key(&ip(1)),
            "the least-recently-used source must be the one evicted"
        );
        assert!(rl.per_source.contains_key(&ip(2)));
        assert!(rl.per_source.contains_key(&ip(3)));
    }

    #[test]
    fn a_hit_moves_source_to_newest_in_constant_time_lru() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::with_params(1_000_000.0, 1_000_000.0, 5.0, 5.0, 2);
        assert!(rl.check(ip(1), t0));
        assert!(rl.check(ip(2), t0));
        assert!(rl.check(ip(1), t0), "touch ip(1), making ip(2) oldest");
        assert!(rl.check(ip(3), t0));
        assert!(rl.per_source.contains_key(&ip(1)));
        assert!(!rl.per_source.contains_key(&ip(2)));
        assert!(rl.per_source.contains_key(&ip(3)));
        assert_eq!(rl.lru_head, Some(ip(1)));
        assert_eq!(rl.lru_tail, Some(ip(3)));
    }

    #[test]
    fn liveness_recovers_after_refill() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::with_params(1.0, 1.0, 1.0, 1.0, 16);
        assert!(rl.check(ip(1), t0));
        assert!(!rl.check(ip(1), t0 + Duration::from_millis(10)));
        // After a full second, both global and per-source buckets have
        // refilled, so a legitimate retry succeeds — the limiter must not
        // permanently lock out a source.
        assert!(rl.check(ip(1), t0 + Duration::from_secs(2)));
    }
}
