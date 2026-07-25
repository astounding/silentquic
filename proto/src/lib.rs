// SPDX-License-Identifier: 0BSD
//! Sans-IO core for silentquic.
//!
//! This crate performs no I/O, spawns no tasks, requires no async runtime, and
//! never blocks or parks. The caller owns the socket and the clock and drives
//! the state machine directly, which makes silentquic embeddable in a
//! hand-rolled event loop — including the classic Unix reactor that calls
//! `select()` with a zero timeout and has other work to do between passes.
//! See `examples/poll_loop.rs` for the reference shape.
//!
//! The [`silentquic`](https://docs.rs/silentquic) crate is a thin tokio wrapper
//! over this core; applications that want async/await should use that instead.
//!
//! # Threat model
//!
//! A server built on this core emits **zero bytes** in response to any packet
//! that does not prove possession of a valid pre-shared key. Stated precisely:
//!
//! > **A datagram that fails the cloaking pre-filter queues nothing to send.**
//!
//! That is structural rather than a property of the caller's control flow.
//! [`endpoint::Endpoint::handle_datagram`] runs the whole pre-filter — rate
//! limiter, long-header parse, selector length, PSK selector match, freshness,
//! anti-replay — and returns before a failing packet reaches quinn-proto at all,
//! so there is nothing for [`endpoint::Endpoint::poll_transmit`] to hand back
//! and an embedder cannot reply to an unauthorized peer even by mistake.
//!
//! Note what the invariant is *not* keyed on: it is not
//! "[`outcome::DatagramOutcome::Dropped`] implies nothing was queued". A peer
//! that has already proved PSK possession can be answered — the reachable case
//! is a Version Negotiation reply to an authorized peer asking for a QUIC
//! version we do not speak, which yields `Dropped` *and* a queued transmit. See
//! [`outcome::DatagramOutcome::Dropped`].
//!
//! See the repository's `README.md` (`Threat Model`) for the full, honest
//! boundaries — this defeats internet-wide scanning and casual DPI, but does
//! NOT defeat global passive traffic analysis, sophisticated DPI that actively
//! attempts `Initial` decryption on every flow, or a resource side-channel via
//! a co-located service.

pub mod config;
pub mod conn;
pub mod crypto;
pub mod endpoint;
pub mod freshness;
pub mod initial_keys;
pub mod outcome;
pub mod ratelimit;
pub mod replay;
pub mod selector;
pub mod testing;
pub mod transport;
