// SPDX-License-Identifier: 0BSD
//! End-to-end exercise of the completed sans-IO [`Endpoint`], through the REAL
//! cloaking path, with **no sockets, no runtime, and no threads**.
//!
//! `core_streams.rs` deliberately drives a *stock* quinn-proto pair, because its
//! unit under test (`ConnState`) is transport-agnostic. This file is the other
//! half: every datagram here passes through
//! [`silentquic_proto::endpoint::Endpoint::handle_datagram`], so the blinded
//! selector DCID, the PSK-rekeyed Initial, the freshness/replay gates and the
//! rate limiter are all genuinely in the loop. If cloaking breaks, these fail.
//!
//! [`Endpoint`]: silentquic_proto::endpoint::Endpoint

use quinn_proto::{Side, VarInt};

use silentquic_proto::outcome::Event;
use silentquic_proto::testing::{connected_pair, Pair};

/// Bound on timer-firing passes when reaping a closed connection. A close timer
/// settles in a couple; this only exists so a regression fails fast.
const MAX_REAP_PASSES: usize = 64;

/// Did this side observe a `Connected` event for the given handle?
fn saw_connected(pair: &Pair, side: Side) -> bool {
    pair.events(side)
        .iter()
        .any(|e| matches!(e, Event::Connected(_)))
}

/// A cloaked handshake — blinded selector DCID, PSK-derived Initial keys, the
/// full server pre-filter — completes entirely in memory, and BOTH sides surface
/// `Event::Connected` through `poll_event`.
///
/// This is the first test in the tree that proves `new_client` and `new_server`
/// interoperate: `core_silence.rs` only ever proved what the server *refuses*.
#[test]
fn cloaked_pair_completes_handshake_and_both_sides_see_connected() {
    let pair = connected_pair();

    assert!(
        saw_connected(&pair, Side::Client),
        "the client must surface Event::Connected; got {:?}",
        pair.events(Side::Client)
    );
    assert!(
        saw_connected(&pair, Side::Server),
        "the server must surface Event::Connected; got {:?}",
        pair.events(Side::Server)
    );
}

/// A stream opened by the cloaked client is accepted and read back by the
/// server, byte for byte. This is the payload path the whole crate exists for.
#[test]
fn client_stream_is_accepted_and_read_by_the_server() {
    let mut pair = connected_pair();

    let id = pair.open_bi(Side::Client);
    pair.write_all(Side::Client, id, b"ping");
    pair.conn(Side::Client).stream_finish(id).expect("finish");
    pair.drive();

    let accepted = pair.accept_bi(Side::Server);
    assert_eq!(
        accepted, id,
        "the server accepts the stream the client opened"
    );

    let got = pair.pump_until_read(Side::Server, id);
    assert_eq!(&got, b"ping", "every byte survived the cloaked round trip");
}

/// Both directions, so the server's send path is exercised too.
#[test]
fn a_stream_echoes_in_both_directions() {
    let mut pair = connected_pair();

    let id = pair.open_bi(Side::Client);
    pair.write_all(Side::Client, id, b"echo-me");
    pair.conn(Side::Client).stream_finish(id).expect("finish");
    pair.drive();

    assert_eq!(pair.accept_bi(Side::Server), id);
    let got = pair.pump_until_read(Side::Server, id);
    assert_eq!(&got, b"echo-me");

    pair.write_all(Side::Server, id, &got);
    pair.conn(Side::Server).stream_finish(id).expect("finish");
    pair.drive();

    let back = pair.pump_until_read(Side::Client, id);
    assert_eq!(&back, b"echo-me", "the server's echo reaches the client");
}

/// THE `is_drained()` reaping guard, at the core level.
///
/// quinn-proto's `Connection::close()` only arms the close timer; the connection
/// reaches `Drained` WITHOUT ever setting the internal error field, so `poll()`
/// never yields `ConnectionLost` for a self-close. An endpoint that reaped only
/// on `progress.lost` would keep a locally-closed connection in its maps forever
/// — until quinn-proto reused the freed `ConnectionHandle` and the collision
/// wedged accept (~32 cycles; see `tests/connection_lifecycle.rs`).
///
/// So: close the CLIENT locally, fire its timers, and require that the endpoint
/// both drops the connection from its bookkeeping AND emits `ConnectionLost`.
#[test]
fn a_locally_closed_connection_is_reaped_and_reports_connection_lost() {
    let mut pair = connected_pair();
    let ch = pair.client_ch();
    let now = pair.now();

    assert!(
        pair.client().conn_mut(ch).is_some(),
        "the connection is live before the close"
    );

    pair.conn(Side::Client)
        .conn_mut()
        .close(now, VarInt::from_u32(0), bytes::Bytes::new());
    pair.drive();

    // Fire the close timer. Nothing else can complete the transition.
    let mut reaped = false;
    for _ in 0..MAX_REAP_PASSES {
        if pair.client().conn_mut(ch).is_none() {
            reaped = true;
            break;
        }
        pair.fire_timers();
        pair.drive();
    }

    assert!(
        reaped,
        "a locally-closed connection MUST be reaped via is_drained() — quinn-proto \
         never reports ConnectionLost for a self-close, so reaping on progress.lost \
         alone leaks the handle until a reused one wedges accept"
    );
    assert!(
        pair.events(Side::Client)
            .contains(&Event::ConnectionLost { conn: ch }),
        "the reap must surface ConnectionLost so the caller knows the handle is dead; \
         got {:?}",
        pair.events(Side::Client)
    );
}

/// CID attribution, end to end: the server minted and recorded this connection's
/// CIDs during the cloaked handshake, and losing the connection must remove
/// exactly those CIDs from the routing set.
///
/// This is what `admit()`'s spike stub (`pending_cids.clear()`) could not do:
/// without `cids_by_conn`, the CIDs were unattributable and leaked forever.
#[test]
fn a_lost_connections_cids_are_pruned_from_the_routing_set() {
    let mut pair = connected_pair();

    assert!(
        pair.server().issued_cid_count() > 0,
        "the server must have recorded the live connection's CIDs"
    );

    // A local close on the client sends CONNECTION_CLOSE, so the SERVER observes
    // a remote loss and reaps promptly.
    let now = pair.now();
    pair.conn(Side::Client)
        .conn_mut()
        .close(now, VarInt::from_u32(0), bytes::Bytes::new());
    pair.drive();

    let mut pruned = false;
    for _ in 0..MAX_REAP_PASSES {
        if pair.server().issued_cid_count() == 0 {
            pruned = true;
            break;
        }
        pair.fire_timers();
        pair.drive();
    }

    assert!(
        pruned,
        "a lost connection's CIDs must be pruned from the routing set; still {} left",
        pair.server().issued_cid_count()
    );
}
