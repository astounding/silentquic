// SPDX-License-Identifier: 0BSD
//! silentquic — a cloaked QUIC transport.
//!
//! A server built on this crate emits **zero bytes** in response to any
//! packet that doesn't prove possession of a valid pre-shared key, and its
//! traffic camouflages as ordinary QUIC v1. See `README.md`'s `Threat Model`
//! section (or `docs/superpowers/specs/2026-07-03-silentquic-design.md` §3)
//! for the full, honest threat model before deploying. In particular: this
//! defeats internet-wide scanning and casual DPI, but does NOT defeat global
//! passive traffic analysis, sophisticated DPI that actively attempts
//! `Initial` decryption on every flow, or a resource side-channel via a
//! co-located service. **Run it as the only service on its host.** See
//! `README.md`'s `Limitations` section for boundaries not yet
//! production-hardened (single-threaded driver, unbounded
//! `Stream::read_to_end`, compile-time rate limits, CID pruning only at
//! connection close).

// Protocol logic lives in the sans-IO core crate; re-exported here so
// `silentquic::selector::…` (and friends) keep resolving unchanged.
pub use silentquic_proto::{freshness, initial_keys, ratelimit, replay, selector, transport};

pub mod config;
pub mod conn;
pub mod server;
pub mod client;
