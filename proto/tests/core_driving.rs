// SPDX-License-Identifier: 0BSD
//! The two guarantees a caller's *loop* depends on, proved through the public
//! core API with no sockets, no runtime and no threads.
//!
//! Both exist because the core cannot wait for anything, so the obligations it
//! cannot discharge itself have to be either enforced or bounded:
//!
//! * **Nothing sleeps through unflushed work.** `stream_read`'s
//!   `Chunks::finalize` releases the peer's MAX_STREAM_DATA/MAX_DATA credit, and
//!   that credit only reaches the wire on the next `poll_transmit` drain. A
//!   caller whose loop drains transmits *before* doing stream work would leave
//!   it queued, the peer would stay flow-control blocked, nothing would arrive
//!   to wake the loop, and the connection would hang until the idle timeout. So
//!   `next_timeout()` reports an **already-elapsed** deadline while any
//!   connection is dirty.
//! * **Per-stream bookkeeping is releasable.** `finished_reads` remembers one
//!   `StreamId` per stream that reached clean end-of-stream so that a read after
//!   FIN keeps answering `Finished`. On a long-lived connection carrying an
//!   unbounded number of short-lived streams that must be releasable, and
//!   `forget_stream` is the release.

use quinn_proto::{Dir, Side};

use silentquic_proto::outcome::{ReadOutcome, WriteOutcome};
use silentquic_proto::testing::connected_pair;

// ---------------------------------------------------------------------------
// The dirty guarantee
// ---------------------------------------------------------------------------

/// A quiesced pair has nothing pending, so its deadline (if any) is in the
/// future — and a single `stream_write` pulls it into the past.
#[test]
fn a_write_forces_an_already_elapsed_deadline_until_the_next_pass() {
    let mut pair = connected_pair();
    let now = pair.now();

    assert!(
        pair.client().next_timeout().is_none_or(|t| t > now),
        "a quiesced connection must not claim a deadline has already passed, or \
         every caller would spin"
    );

    let id = pair.open_bi(Side::Client);
    assert!(matches!(
        pair.conn(Side::Client).stream_write(id, b"unflushed"),
        Ok(WriteOutcome::Wrote(_))
    ));

    assert!(
        pair.client().next_timeout().is_some_and(|t| t <= now),
        "with bytes accepted but not yet drained, next_timeout() MUST report an \
         already-elapsed deadline: a caller that sleeps on it has to come straight \
         back around the loop, not sleep through the stall"
    );

    // The servicing pass that flushes the work clears the flag.
    while pair.client().poll_transmit(now).is_some() {}
    assert!(
        pair.client().next_timeout().is_none_or(|t| t > now),
        "once the work is queued for the caller, the deadline is honest again"
    );
}

/// The motivating case: a **read** is a send-side event too, because it releases
/// flow-control credit the peer may be blocked on. `stream_read` therefore marks
/// the connection dirty even when it copies nothing.
#[test]
fn a_read_forces_an_already_elapsed_deadline_because_it_releases_credit() {
    let mut pair = connected_pair();

    let id = pair.open_bi(Side::Client);
    pair.write_all(Side::Client, id, b"credit-please");
    pair.drive();
    assert_eq!(pair.accept_bi(Side::Server), id);

    // Quiesce, then read: the read is the ONLY thing that happens afterwards.
    let now = pair.now();
    while pair.server().poll_transmit(now).is_some() {}
    assert!(
        pair.server().next_timeout().is_none_or(|t| t > now),
        "quiesced before the read"
    );

    let mut buf = [0u8; 64];
    assert!(matches!(
        pair.conn(Side::Server).stream_read(id, &mut buf),
        Ok(ReadOutcome::Read(_))
    ));

    assert!(
        pair.server().next_timeout().is_some_and(|t| t <= now),
        "the MAX_STREAM_DATA/MAX_DATA credit this read released is not on the wire \
         yet. A caller that drained transmits before reading and then slept on this \
         deadline would leave the peer flow-control blocked with nothing to wake it"
    );
}

/// The flag is per-connection state, not a global latch: servicing the endpoint
/// clears it, and an untouched endpoint never sets it.
#[test]
fn an_untouched_endpoint_reports_its_real_deadline() {
    let mut pair = connected_pair();
    let now = pair.now();
    while pair.server().poll_transmit(now).is_some() {}

    let real = pair.server().next_timeout();
    assert_eq!(
        pair.server().next_timeout(),
        real,
        "a query must not itself change the answer"
    );
    assert!(
        real.is_none_or(|t| t > now),
        "no stream work has been done, so there is nothing unflushed to report"
    );
}

// ---------------------------------------------------------------------------
// The `finished_reads` eviction contract
// ---------------------------------------------------------------------------

/// `Finished` stays idempotent for as long as the caller cares about the stream,
/// and `forget_stream` is what ends that. Without a release, one entry per
/// stream accumulates forever on a connection that multiplexes short-lived
/// streams — the `squicusock` shape.
#[test]
fn forget_stream_releases_the_end_of_stream_bookkeeping() {
    let mut pair = connected_pair();

    let id = pair.open_bi(Side::Client);
    pair.write_all(Side::Client, id, b"done");
    pair.conn(Side::Client).stream_finish(id).expect("finish");
    pair.drive();
    assert_eq!(pair.accept_bi(Side::Server), id);
    assert_eq!(&pair.pump_until_read(Side::Server, id), b"done");

    let mut buf = [0u8; 16];
    assert_eq!(
        pair.conn(Side::Server).stream_read(id, &mut buf).ok(),
        Some(ReadOutcome::Finished),
        "Finished is idempotent while the stream is still the caller's concern"
    );

    pair.conn(Side::Server).forget_stream(id);

    assert!(
        pair.conn(Side::Server).stream_read(id, &mut buf).is_err(),
        "after forget_stream the id is simply unknown — quinn-proto freed the \
         receive stream at EOS, and the core is no longer remembering it on the \
         caller's behalf. 'Done' means done."
    );

    // Idempotent, and forgetting something never known is a no-op.
    pair.conn(Side::Server).forget_stream(id);
    pair.conn(Side::Server)
        .forget_stream(quinn_proto::StreamId::new(Side::Client, Dir::Bi, 999));
}

/// Reading after `stop()` is not a `Finished` — the caller abandoned the receive
/// half, so the bookkeeping goes with it. (This is the only case where the
/// eviction in `stream_stop`/`stream_reset` can have any effect at all: it
/// requires the receive half to have already reached EOS.)
#[test]
fn stopping_a_finished_stream_releases_its_bookkeeping_too() {
    let mut pair = connected_pair();

    let id = pair.open_bi(Side::Client);
    pair.write_all(Side::Client, id, b"x");
    pair.conn(Side::Client).stream_finish(id).expect("finish");
    pair.drive();
    assert_eq!(pair.accept_bi(Side::Server), id);
    assert_eq!(&pair.pump_until_read(Side::Server, id), b"x");

    // `stop` on an already-finished receive half is refused by quinn-proto (the
    // stream is gone), but the core's own memory of it is released regardless.
    let _ = pair.conn(Side::Server).stream_stop(id, 0);

    let mut buf = [0u8; 16];
    assert!(
        pair.conn(Side::Server).stream_read(id, &mut buf).is_err(),
        "the receive half was explicitly abandoned; there is no Finished to report"
    );
}

/// The eviction must not fire early: a stream whose receive half has NOT reached
/// EOS keeps answering `Finished` after FIN even though the send half was reset.
#[test]
fn resetting_the_send_half_does_not_break_post_fin_reads() {
    let mut pair = connected_pair();

    let id = pair.open_bi(Side::Client);
    pair.write_all(Side::Client, id, b"payload");
    pair.conn(Side::Client).stream_finish(id).expect("finish");
    pair.drive();
    assert_eq!(pair.accept_bi(Side::Server), id);

    // The server abandons its OWN send half before it has read anything. The
    // receive half is untouched, so nothing may be evicted here.
    pair.conn(Side::Server).stream_reset(id, 7).expect("reset");
    pair.drive();

    assert_eq!(&pair.pump_until_read(Side::Server, id), b"payload");
    let mut buf = [0u8; 16];
    assert_eq!(
        pair.conn(Side::Server).stream_read(id, &mut buf).ok(),
        Some(ReadOutcome::Finished),
        "resetting the send half must not cost the receive half its stable \
         end-of-stream answer"
    );
}
