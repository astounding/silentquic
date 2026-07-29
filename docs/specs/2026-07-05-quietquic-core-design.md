# quietquic sans-IO core — Design Spec

**Date:** 2026-07-05
**Status:** Approved design, pre-implementation
**License:** 0BSD
**Language:** Rust

---

## 1. Context: why this exists

quietquic today is a tokio library. `Server::bind` and `Client::connect` call
`tokio::spawn` (see `src/server.rs:114`, `src/client.rs:195`), so the crate
requires an ambient tokio runtime and owns the UDP socket and the event loop.

That is fine for async/await applications, but it excludes a whole class of
consumer: an application with its **own** hand-rolled event loop. The motivating
case is the classic Unix reactor — a single process calling `select()` with a
**zero timeout** (immediate return, purely non-blocking), servicing whatever I/O
is ready, then going off to do other work, in a loop.

tokio cannot be embedded in such a loop. Its design assumption is that it owns
the thread and parks in `epoll`/`kqueue` when no task is runnable; there is no
public "advance the runtime one step, non-blocking, then return my thread"
operation. `block_on` blocks by construction. The two designs are mutually
exclusive: only one of them can own the thread's idle time.

The answer is not to adapt tokio but to **layer**: a sans-IO core that a caller
drives directly, with the tokio integration as a thin wrapper on top. This is the
standard structure for this problem — `quinn-proto`/`quinn` and Cloudflare's
`quiche` are both built this way, precisely so embedders can own the loop.

Two facts make this an *extraction* rather than an invention:

- **`quinn-proto` is already sans-IO.** It is a pure state machine that performs
  no I/O.
- **quietquic already runs without sockets in tests.** `tests/spike_silence.rs`
  drives two full endpoints entirely in memory, hand-passing datagrams, and
  completes a real PSK handshake plus a stream echo. The capability exists; it is
  simply not public API.

Likewise, the cloaking machinery (blinded-DCID selector, freshness, replay,
PSK `Initial` re-keying) is already independent of I/O. Only the UDP loop and the
driver task are tokio-bound.

### Where this sits in the roadmap

| # | Sub-project | Status |
|---|-------------|--------|
| 1 | **`quietquic-proto` sans-IO core** (this spec) | designed |
| 2 | `quietquic` tokio wrapper + quinn-parity split streams | planned |
| 3 | `squicusock` — Unix-domain-socket relay daemon | planned |
| — | *later, optional:* C FFI over the core (unlocks C and Go embedding) | queued |
| — | *later, optional:* dual-mode Ruby gem (sans-IO polling **and** tokio styles) | queued |

Sub-project 2 delivers the streaming capability the relay needs: `open_bi`/
`accept_bi`/`open_uni`/`accept_uni` returning `SendStream`/`RecvStream`,
incremental `read`, `read_to_end(size_limit)`, `reset`/`stop`, tokio
`AsyncRead`/`AsyncWrite`, and a quinn-shaped error taxonomy
(`ReadError`/`WriteError`/`ReadToEndError`) carrying only variants quietquic can
actually produce.

Sub-project 3 (`squicusock`) needs **no protocol of its own**: QUIC natively
multiplexes independent, individually flow-controlled streams, and a Unix socket
connection maps onto a QUIC bidirectional stream essentially losslessly —
ordered reliable bytes, `shutdown(SHUT_WR)` ↔ FIN, abrupt close ↔ `RESET_STREAM`.
One accepted Unix socket connection becomes one QUIC stream over a single shared
quietquic connection. No custom multiplexing or framing layer is required.

---

## 2. Goals and non-goals

### Goals
- Extract a **sans-IO core crate** that performs no I/O, spawns nothing, requires
  no runtime, and never blocks or parks.
- Preserve **all existing behavior and public API** of the `quietquic` crate, so
  every current test — most importantly the cloaking and silence suites — passes
  unmodified.
- Make the **silence invariant structural**: an embedder must be unable to reply
  to an unauthorized packet even by mistake.
- Ship a **reference zero-timeout poll loop** as executable documentation.

### Non-goals (explicitly deferred)
- Split streams, `AsyncRead`/`AsyncWrite`, unidirectional streams, the
  quinn-parity error taxonomy, and any new *public* streaming surface — all
  sub-project 2.
- C FFI, `squicusock`, and the dual-mode Ruby gem.
- Performance optimization. This refactor must not regress performance, but
  tuning is not its purpose.

---

## 3. Crate structure

The repository root remains the `quietquic` package **and** additionally becomes
the workspace root. A new member `proto/` holds the **`quietquic-proto`** crate.
`quietquic` depends on it with `path = "proto"`.

```
/                     quietquic      (tokio wrapper; workspace root)
/proto/               quietquic-proto (sans-IO core; no tokio dependency)
/bindings/ruby/       Ruby gem         (unchanged; sits on quietquic)
/fuzz/                fuzz targets     (own workspace)
```

**Rationale for keeping the root crate in place** rather than reshuffling into a
conventional `crates/` layout: the Ruby gem's path dependency, its `vendor_core`
packaging task, the fuzz crate, and CI all key off the root crate's location. That
packaging landed recently and was verified end-to-end through `gem build`,
`gem unpack`, and `gem install --local`. Moving the root crate risks re-breaking a
working install path for cosmetic gain. A `crates/` layout later is a mechanical
move.

`quietquic-proto` must have **no tokio dependency at all**, so a C embedder, the
future FFI, or a polling-mode Ruby binding compiles zero tokio. The crate boundary
makes layering violations compile errors rather than review comments.

**Known task:** `bindings/ruby`'s `vendor_core` rake task currently vendors the
root crate's `src/`, `Cargo.toml`, and `Cargo.lock` into the gem. It must also
vendor `proto/` and preserve the workspace relationship, and the packaged-gem
install path must be re-verified (`rake vendor_core && gem build && gem unpack`).

---

## 4. The core API

All operations return immediately. Nothing parks, blocks, allocates a runtime, or
spawns. The caller owns the socket and the clock, and passes `now` explicitly.

```rust
// Endpoint
Endpoint::new_server(secrets: ServerSecrets) -> Endpoint
Endpoint::new_client(cfg: ClientConfigFile) -> (Endpoint, ConnHandle)

handle_datagram(&mut self, now: Instant, from: SocketAddr, data: &[u8])
    -> DatagramOutcome                 // runs the cloaking pre-filter internally
poll_transmit(&mut self, now: Instant, buf: &mut Vec<u8>) -> Option<Transmit>
next_timeout(&self) -> Option<Instant>
handle_timeout(&mut self, now: Instant)
poll_event(&mut self) -> Option<Event>

// Streams — non-blocking
open_bi(&mut self, conn: ConnHandle)   -> Result<StreamId, ConnError>
accept_bi(&mut self, conn: ConnHandle) -> Result<Option<StreamId>, ConnError>  // None = none pending
stream_read(&mut self, conn: ConnHandle, id: StreamId, buf: &mut [u8])
    -> Result<ReadOutcome, ConnError>
stream_write(&mut self, conn: ConnHandle, id: StreamId, buf: &[u8])
    -> Result<WriteOutcome, ConnError>
stream_finish(&mut self, conn: ConnHandle, id: StreamId) -> Result<(), ConnError>
stream_reset(&mut self, conn: ConnHandle, id: StreamId, code: u64) -> Result<(), ConnError>
stream_stop(&mut self, conn: ConnHandle, id: StreamId, code: u64) -> Result<(), ConnError>
send_fin(&self, conn: ConnHandle, id: StreamId) -> Option<SendFin>
forget_send(&mut self, conn: ConnHandle, id: StreamId)

enum DatagramOutcome { Dropped, Accepted(ConnHandle) }
enum ReadOutcome  { Read(usize), Blocked, Finished }   // Finished = peer FIN
enum WriteOutcome { Wrote(usize), Blocked }            // Blocked = flow-control backpressure
enum SendFin { Queued, Acked, Stopped(u64) }
enum Event {
    Connected(ConnHandle),
    StreamOpened { conn: ConnHandle, id: StreamId, dir: Dir },
    StreamReadable { conn: ConnHandle, id: StreamId },
    StreamWritable { conn: ConnHandle, id: StreamId },
    StreamFinAcked { conn: ConnHandle, id: StreamId },
    StreamStopped { conn: ConnHandle, id: StreamId, error_code: u64 },
    ConnectionLost { conn: ConnHandle, reason: ConnectionError },
}
```

Exact signatures are confirmed by the implementation. `ConnError` is structured
and shared by the core and Tokio wrapper; `ConnectionError` is the terminal
connection fact carried by `ConnectionLost` and by the wrapper's
`Connection::closed()`. The three-way `ReadOutcome`/`WriteOutcome` enums still
express the outcomes sans-IO needs (progress, would-block, end-of-stream)
without turning "nothing available right now" into an error.

`ConnectionError::{ConnectionClosed, TransportError}.frame_type` is intentionally
`None` under quinn-proto 0.11. Quinn-proto stores the frame type as a public
`FrameType`, but the raw numeric value is not exposed; its tuple field and known
constants are private to quinn-proto. QuietQUIC keeps an `Option<u64>` field for
a future upstream accessor, but does not use unsafe private-layout extraction,
debug/display string parsing, or a patched quinn-proto dependency. We are not
submitting an upstream PR for this release and are not committing to submit one
later.

### The "extraction only" nuance

A sans-IO core **cannot** offer a blocking `read_to_end` — there is nothing to
park on — so the core's read primitive is necessarily incremental. This does not
leak into the public surface: in this sub-project the **`quietquic` crate's
Tokio `RecvStream::read_to_end` is implemented as a loop over the core's
incremental read, driven by the tokio driver's `pending_reads` parking.
Incremental reads are also public through `RecvStream::read(max)`.

---

## 5. What moves, what stays

| Moves into `quietquic-proto` | Stays in `quietquic` |
|---|---|
| `quinn_proto::Endpoint`/`Connection` driving | UDP socket ownership, `tokio::spawn` |
| **Cloaking pre-filter**: `peek_dcid` → `parse_dcid` → `is_fresh` → `select_psk` → replay guard | the driver's `select!` loop and timers |
| PSK `Initial` re-keying (`initial_keys.rs`) | command channel + oneshot replies |
| Rate limiter (takes `now` as a parameter rather than reading the clock) | public `Server`, `Client`, `Connection`, `SendStream`, `RecvStream` |
| Per-stream buffers; the `is_drained()` reaping fix | `pending_reads` parking (now over core primitives) |
| Config **types** and their parsing (`ServerSecrets`, `ClientConfigFile`, `Psk`, selector, freshness, replay) — deserialization from a string only | **`FileSource`** — it reads the filesystem, and a sans-IO core must not perform I/O of any kind. It also keeps the `chmod 600` warning where the gem already calls it. |

**Additional fix in scope:** the crate currently declares
`tokio = { features = [..., "rt-multi-thread", ...] }`, which forces the
multi-threaded scheduler on every consumer. It should require only `rt`, leaving
the runtime flavor to the application — a current-thread runtime is a legitimate
and useful configuration.

---

## 6. Silence is preserved and strengthened

The silence invariant — *the server emits zero bytes in response to any packet
that does not prove possession of a valid PSK* — is the project's headline
security property and must survive this refactor intact.

Moving the pre-filter into the core **strengthens** it. `handle_datagram` returns
`DatagramOutcome::Dropped` for an unauthorized packet and queues **no** transmit,
so a subsequent `poll_transmit` has nothing to hand back. An embedder driving the
core by hand therefore cannot reply to an unauthorized peer even by mistake:
invisibility becomes a property of the API rather than of the driver's control
flow. It also becomes provable with **zero sockets**, in fast deterministic tests.

The cloaking and silence suites are the regression net for the entire refactor and
must stay green at every step. This is the core safety argument for attempting the
extraction at all.

---

## 7. Front-loaded spike (first task)

The genuine uncertainty is the **API shape**, not feasibility. The spike:

1. Extracts a minimal core covering datagram → pre-filter → quinn-proto →
   transmit, exposed through the §4 endpoint API.
2. Re-runs the in-memory silence cases (junk, stock-QUIC-shaped, wrong PSK, stale
   freshness, replay) through that public core API, asserting zero transmits.
3. Completes one PSK handshake plus a stream echo entirely in memory.
4. Records the confirmed signatures, and any deviation from §4, in a decision note
   under `docs/superpowers/notes/`.

Only after the spike is green does the remaining extraction proceed.

---

## 8. Testing

- **Every existing behavioral suite passes after API migration.** `cloaking`,
  `spike_silence`, `server_prefilter`, `client_server_roundtrip`,
  `connection_lifecycle`, and the crate's unit tests continue to cover the same
  behavior, with call sites updated for the alpha.3 split stream API where
  needed.
- **New core-level tests** in `quietquic-proto`: drive an endpoint pair entirely
  in memory through the public core API — handshake, stream echo, and each silence
  case — with no sockets and no runtime.
- **Reference example**, compiled and exercised in CI: the zero-timeout poll loop
  (`select`-style, immediate return) showing correct use — service inbound
  datagrams, check the timeout deadline against the caller's own clock, drain
  `poll_transmit`, drain `poll_event`, then read/write streams non-blocking.
  Sans-IO cores are easy to misuse: skip draining transmits or servicing timers
  and connections stall silently, so this doubles as documentation and as a test.
- **Cross-platform**: macOS and the FreeBSD VM, matching existing practice.
- **Fuzz targets** continue to build and run against the parsers, which now live
  in the core.

---

## 9. Success criteria

1. `quietquic-proto` builds with **no tokio in its dependency tree**.
2. The `quietquic` crate's public API is byte-for-byte source-compatible; every
   existing test passes **unmodified**, including the Ruby gem's suite.
3. An endpoint pair completes a PSK handshake and a stream echo driven entirely
   through the core's public API, with no sockets and no runtime.
4. Every silence case is provable through the core API alone, asserting that an
   unauthorized datagram produces no transmit.
5. The reference zero-timeout poll-loop example compiles and runs in CI.
6. `tokio` is required at feature level `rt`, not `rt-multi-thread`.
7. Green on macOS and FreeBSD.

---

## 10. Risks

- **Silence regression during extraction.** Mitigated by the front-loaded spike,
  by the existing cloaking suites as an unmodified regression net, and by the
  invariant becoming structural rather than control-flow-dependent.
- **Connection-lifecycle regression.** The `is_drained()` reaping fix and its
  `tests/connection_lifecycle.rs` guard (48 cycles of server-side close) must
  survive the move into the core; that test is unmodified and must stay green.
- **Ruby gem packaging.** `vendor_core` must vendor the new `proto/` crate and the
  packaged-gem install path must be re-verified end-to-end.
- **Scope creep into sub-project 2.** The temptation to expose the core's
  incremental read publicly "while we're here" must be resisted; keeping the
  public API frozen is what makes the refactor reviewable.

---

## 11. Open questions

None blocking. Two items are settled deliberately and recorded here so they are
not relitigated mid-implementation:

- **Crate layout**: root package plus `proto/` member, not a `crates/` reshuffle
  (§3 rationale).
- **Scope**: extraction only; new public streaming capability is sub-project 2
  (§2, §4).

Exact core signatures are confirmed by the spike and recorded in its decision
note.
