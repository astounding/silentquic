# sans-IO core — spike decision note

**Date:** 2026-07-05
**Spike task:** Task 6 of `plans/2026-07-05-quietquic-sans-io-core.md`
**Outcome:** API shape confirmed; proceed with Tasks 7–10.

## What the spike proved

The cloaking pre-filter runs entirely inside `quietquic-proto`, with the
silence invariant expressed structurally. `proto/tests/core_silence.rs` drives a
real server endpoint with **no sockets, no runtime, and no threads**, and for
each unauthorized datagram asserts both that the outcome is
`DatagramOutcome::Dropped` *and* that `poll_transmit` yields nothing afterwards.

Cases green: junk bytes, an empty datagram, and a stock-QUIC-shaped v1 `Initial`
carrying a random 20-byte DCID.

The second assertion is the load-bearing one: it is what guarantees an embedder
driving the core from a hand-rolled loop cannot reply to an unauthorized peer,
because there is nothing queued to reply *with*.

## Confirmed signatures

```rust
pub const LOCAL_CID_LEN: usize = 8;

impl Endpoint {
    pub fn new_server(secrets: ServerSecrets) -> Result<Endpoint, ConfigError>;
    pub fn handle_datagram(&mut self, now: Instant, from: SocketAddr, data: &[u8])
        -> DatagramOutcome;
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Transmit>;
}

pub struct Transmit { pub destination: SocketAddr, pub contents: Vec<u8> }
pub enum DatagramOutcome { Dropped, Accepted(ConnectionHandle) }
pub enum ReadOutcome  { Read(usize), Blocked, Finished }
pub enum WriteOutcome { Wrote(usize), Blocked }
pub enum Event { Connected, StreamOpened, StreamReadable, StreamWritable, ConnectionLost }
```

## Deviations from the spec's §4 shape

1. **`poll_transmit` takes no output buffer.** The spec sketched
   `poll_transmit(&mut self, now, buf: &mut Vec<u8>) -> Option<Transmit>`,
   mirroring quinn-proto's borrow-the-caller's-buffer style. The implemented
   signature is `poll_transmit(&mut self, now) -> Option<Transmit>` with a
   `Transmit` that **owns** its bytes. Reason: the caller immediately does
   `send_to(&t.contents, t.destination)`, so handing back an owned buffer removes
   a lifetime knot and a class of "forgot to clear the buffer" bugs, at the cost
   of one allocation per datagram. Revisit only if profiling shows it matters.

2. **`Transmit` is a core-local type, not `quinn_proto::Transmit`.** quinn-proto's
   carries `ecn`, `segment_size`, and `src_ip`, none of which quietquic sets
   today. Re-exporting it would expose fields the core does not honour.

3. **`LOCAL_CID_LEN` is now public in the core.** It has to be, because
   short-header DCID extraction depends on it and the tokio layer's router needs
   the same constant.

## Pre-filter ordering — preserved exactly

The order is load-bearing and was ported unchanged from `Driver::on_datagram` /
`Driver::prefilter`:

1. active-CID check (post-handshake traffic bypasses the pre-filter entirely)
2. **rate limiter** — before any selector/MAC work, so a flood costs near-nothing
3. `peek_dcid` (long-header parse)
4. exact `DCID_LEN` check
5. `parse_dcid`
6. **freshness — before the replay guard**, so future-dated nonces cannot
   accumulate in the replay set
7. PSK selection (constant-time `selector_matches`)
8. anti-replay `check_and_record`

Any rejection returns `Dropped` **without touching the quinn-proto endpoint**.

## Carried forward to Tasks 7–10

- `admit()` currently clears the pending-CID queue rather than attributing CIDs
  to the connection handle; Task 8 must restore full attribution
  (`cids_by_conn`) so `prune_connection_cids` can reap on `ConnectionLost`.
- The spike stores bare `quinn_proto::Connection` values; Task 7 replaces that
  with `ConnState` carrying the per-stream buffers.
- `Endpoint::new_client`, `next_timeout`, `handle_timeout`, `poll_event`, and
  `conn_mut` are Task 8.
- The `is_drained()` reaping fix and its 48-cycle regression test
  (`tests/connection_lifecycle.rs`) must survive the move into the core.
