# quietquic sans-IO core — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract quietquic's protocol logic into a new no-tokio `quietquic-proto` crate that a caller can drive from their own event loop, while the `quietquic` crate's public API stays byte-for-byte unchanged.

**Architecture:** The repository root remains the `quietquic` package and additionally becomes the workspace root; a new member `proto/` holds `quietquic-proto`. All protocol state (quinn-proto driving, cloaking pre-filter, PSK `Initial` re-keying, rate limiter, per-stream buffers, CID bookkeeping) moves into the core, which never performs I/O, never spawns, and never blocks. The tokio driver in `quietquic` becomes a thin loop that feeds datagrams and timer ticks in, and pumps transmits and events out.

**Tech Stack:** Rust, `quinn-proto` 0.11 (already sans-IO), `aws-lc-rs`, `rustls`; `tokio` only in the `quietquic` crate.

## Global Constraints

- **License:** 0BSD. Every new source file starts with `// SPDX-License-Identifier: 0BSD`.
- **`quietquic-proto` MUST have no tokio in its dependency tree.** Verified by `cargo tree -p quietquic-proto | grep -i tokio` returning nothing.
- **`quietquic`'s public API is UNCHANGED.** Every existing test must pass **unmodified**: `tests/cloaking.rs`, `tests/spike_silence.rs`, `tests/server_prefilter.rs`, `tests/client_server_roundtrip.rs`, `tests/connection_lifecycle.rs`, the crate's unit tests, and the Ruby gem's 62 RSpec examples. **A test that must be edited is a signal the extraction leaked — stop and report it.**
- **No new error taxonomy.** The core reuses the existing `ConnError`. Read/write outcomes are `ReadOutcome { Read(usize), Blocked, Finished }` and `WriteOutcome { Wrote(usize), Blocked }`. The quinn-parity `ReadError`/`WriteError`/`ReadToEndError` types are sub-project 2 and MUST NOT appear here.
- **No public `read_to_end` in the core.** It is a convenience the tokio layer composes over the core's incremental read.
- **`FileSource` stays in `quietquic`** — it touches the filesystem, and the core performs no I/O of any kind. Config *types* and their string-parsing move to the core.
- **The silence invariant is non-negotiable:** an unauthorized datagram must produce no transmit. `handle_datagram` returns `DatagramOutcome::Dropped` and queues nothing.
- **Platforms:** macOS and FreeBSD both green (FreeBSD via the VM; see `docs/superpowers/STATUS.md` for prereqs).
- **TDD:** failing test first, watch it fail, minimal implementation, watch it pass, commit.

### Sequencing note (deviation from the spec, deliberate)

The spec calls the API-shape spike "the first task." It is scheduled here as **Task 6**, after the mechanical module moves, because the spike must exercise the cloaking pre-filter *through the core*, and `quietquic-proto` cannot depend on `quietquic` (circular). Tasks 2–5 are low-risk verbatim moves that make the spike possible. The spike still lands **before** the risky Endpoint extraction (Tasks 7–10), which is what the spec's front-loading is protecting against.

## File Structure

```
proto/Cargo.toml                 quietquic-proto — no tokio
proto/src/lib.rs                 crate docs + re-exports
proto/src/selector.rs            moved verbatim from src/
proto/src/freshness.rs           moved verbatim
proto/src/replay.rs              moved verbatim
proto/src/transport.rs           moved verbatim (peek_dcid)
proto/src/initial_keys.rs        moved verbatim
proto/src/crypto.rs              NEW: endpoint crypto helpers lifted from server.rs
proto/src/config.rs              config TYPES only (no FileSource)
proto/src/ratelimit.rs           moved; takes `now` as a parameter
proto/src/outcome.rs             NEW: DatagramOutcome, Event, ReadOutcome, WriteOutcome
proto/src/conn.rs                NEW: per-connection state + stream buffers
proto/src/endpoint.rs            NEW: the Endpoint state machine
proto/examples/poll_loop.rs      NEW: reference zero-timeout loop
proto/tests/core_silence.rs      NEW: in-memory silence proof via the core API

src/lib.rs                       re-exports proto types + tokio API (public API unchanged)
src/config.rs                    FileSource only; re-exports proto config types
src/server.rs                    Server + tokio driver over proto::Endpoint
src/client.rs                    Client + tokio driver over proto::Endpoint
src/conn.rs                      Connection/Stream handles + command channel (unchanged API)
```

---

### Task 1: Workspace scaffold

**Files:**
- Create: `proto/Cargo.toml`, `proto/src/lib.rs`
- Modify: `Cargo.toml` (add `[workspace]`, add dependency)

**Interfaces:**
- Produces: an empty `quietquic-proto` crate that compiles, is a workspace member, is depended on by `quietquic`, and has **no tokio** in its tree.

- [ ] **Step 1: Create `proto/Cargo.toml`**

```toml
[package]
name = "quietquic-proto"
version = "0.0.0"
edition = "2021"
license = "0BSD"
description = "Sans-IO core for quietquic: cloaked QUIC protocol state machine with no I/O, no runtime, and no threads."

[dependencies]
aws-lc-rs = "1"
blake3 = "1"
bytes = "1"
hex = "0.4"
quinn-proto = { version = "0.11", default-features = false, features = ["rustls-aws-lc-rs", "log", "bloom"] }
rcgen = "0.14"
rustls = { version = "0.23", default-features = false, features = ["aws-lc-rs", "std"] }
serde = { version = "1", features = ["derive"] }
thiserror = "2"
toml = "0.8"
tracing = "0.1"
zeroize = { version = "1", features = ["derive"] }
```

There is deliberately **no `tokio`** entry. Do not add one in any later task.

- [ ] **Step 2: Create `proto/src/lib.rs`**

```rust
// SPDX-License-Identifier: 0BSD
//! Sans-IO core for quietquic.
//!
//! This crate performs no I/O, spawns no tasks, requires no async runtime, and
//! never blocks. The caller owns the socket and the clock and drives the state
//! machine directly, which makes quietquic embeddable in a hand-rolled event
//! loop (see `examples/poll_loop.rs`). The `quietquic` crate is a tokio
//! wrapper over this core.
```

- [ ] **Step 3: Make the root a workspace root and depend on the core**

In `Cargo.toml`, add after the `[package]` block:

```toml
[workspace]
members = ["proto"]
```

and add to `[dependencies]`:

```toml
quietquic-proto = { path = "proto" }
```

- [ ] **Step 4: Verify the whole tree still builds and tests pass**

Run: `cargo build --all && cargo test --all`
Expected: builds; all existing tests pass (58 total across the suites).

- [ ] **Step 5: Verify the core has no tokio**

Run: `cargo tree -p quietquic-proto | grep -i tokio`
Expected: **no output** (exit status 1 from grep is correct here).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock proto
git commit -m "chore: add quietquic-proto workspace member"
```

---

### Task 2: Move the pure-logic modules

`selector.rs`, `freshness.rs`, `replay.rs`, and `transport.rs` are already pure functions with inline unit tests and no I/O. They move verbatim.

**Files:**
- Move: `src/selector.rs` → `proto/src/selector.rs`; `src/freshness.rs` → `proto/src/freshness.rs`; `src/replay.rs` → `proto/src/replay.rs`; `src/transport.rs` → `proto/src/transport.rs`
- Modify: `proto/src/lib.rs`, `src/lib.rs`

**Interfaces:**
- Produces: `quietquic_proto::{selector, freshness, replay, transport}` with identical items (`build_dcid`, `parse_dcid`, `selector_matches`, `DcidParts`, `DCID_LEN`, `CONTEXT`, `now_minutes`, `is_fresh`, `WINDOW_MINUTES`, `ReplayGuard`, `peek_dcid`).
- `quietquic` re-exports all of them at the same paths so its public API is unchanged.

- [ ] **Step 1: Move the four files**

```bash
git mv src/selector.rs src/freshness.rs src/replay.rs src/transport.rs proto/src/
```

Contents are unchanged — including their `#[cfg(test)]` modules, which now run as part of `quietquic-proto`.

- [ ] **Step 2: Declare them in `proto/src/lib.rs`**

Append:

```rust
pub mod freshness;
pub mod replay;
pub mod selector;
pub mod transport;
```

- [ ] **Step 3: Re-export from `quietquic` so its API is unchanged**

In `src/lib.rs`, replace the `pub mod selector; pub mod freshness; pub mod replay; pub mod transport;` declarations with:

```rust
pub use quietquic_proto::{freshness, replay, selector, transport};
```

- [ ] **Step 4: Fix intra-crate `use` paths**

In `src/server.rs`, `src/client.rs`, and `src/conn.rs`, any `use crate::selector::…` (likewise `freshness`, `replay`, `transport`) becomes `use quietquic_proto::selector::…`. Find them with:

```bash
grep -rn "crate::\(selector\|freshness\|replay\|transport\)" src/
```

- [ ] **Step 5: Verify — existing tests must pass UNMODIFIED**

Run: `cargo test --all`
Expected: all pass. The unit tests that lived in these modules now report under `quietquic-proto`. If any *integration* test needs editing, stop — the public API leaked.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor: move selector/freshness/replay/transport into quietquic-proto"
```

---

### Task 3: Move `initial_keys` and the endpoint crypto helpers

**Files:**
- Move: `src/initial_keys.rs` → `proto/src/initial_keys.rs`
- Create: `proto/src/crypto.rs`
- Modify: `src/server.rs` (remove the lifted helpers), `proto/src/lib.rs`, `src/lib.rs`

**Interfaces:**
- Produces: `quietquic_proto::initial_keys::initial_keys_from_psk(psk: &[u8; 32], dcid: &[u8], side: Side, version: u32)` (signature unchanged), plus `quietquic_proto::crypto::{HmacResetKey, reset_key, token_key, random_bytes, RecordingCidGenerator, SelfSigned}`.

- [ ] **Step 1: Move `initial_keys.rs`**

```bash
git mv src/initial_keys.rs proto/src/initial_keys.rs
```

- [ ] **Step 2: Create `proto/src/crypto.rs`**

Move these items **verbatim** out of `src/server.rs` into the new file, adding `// SPDX-License-Identifier: 0BSD` as line 1 and a `//! Endpoint crypto helpers: reset keys, retry-token keys, CID generation, and the self-signed TLS identity.` doc line:

- `struct HmacResetKey` and its `impl quinn_proto::crypto::HmacKey`
- `fn random_bytes<const N: usize>()`
- `fn reset_key()`
- `fn token_key()`
- `struct RecordingCidGenerator`, its `impl RecordingCidGenerator`, and its `impl ConnectionIdGenerator`
- `struct SelfSigned`, its `impl` (`generate`, `quic_server_config`)

Change their visibility from private to `pub` (or `pub(crate)` where only the core uses them) so the core's `endpoint.rs` can use them in Task 8. `RecordingCidGenerator::new` and its fields must be reachable from `endpoint.rs`.

- [ ] **Step 3: Declare in `proto/src/lib.rs`**

```rust
pub mod crypto;
pub mod initial_keys;
```

- [ ] **Step 4: Update `quietquic` to use the moved items**

In `src/lib.rs`, replace `pub mod initial_keys;` with:

```rust
pub use quietquic_proto::initial_keys;
```

In `src/server.rs`, delete the moved definitions and add `use quietquic_proto::crypto::{random_bytes, reset_key, token_key, RecordingCidGenerator, SelfSigned};` — keeping only the names it still references. Fix `use crate::initial_keys::…` → `use quietquic_proto::initial_keys::…` across `src/`.

- [ ] **Step 5: Verify**

Run: `cargo test --all`
Expected: all pass unmodified. `src/server.rs` should now be roughly 250 lines shorter.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor: move initial_keys and endpoint crypto helpers into quietquic-proto"
```

---

### Task 4: Split config — types to the core, `FileSource` stays

**Files:**
- Create: `proto/src/config.rs`
- Modify: `src/config.rs`, `proto/src/lib.rs`, `src/lib.rs`

**Interfaces:**
- Produces: `quietquic_proto::config::{Psk, ClientEntry, ServerSecrets, ClientConfigFile, ConfigError}` — the types and their `serde`/TOML **string** parsing only.
- `quietquic::config` keeps `FileSource` (which reads the filesystem, including the `chmod 600` permission warning) and re-exports the types, so `quietquic::config::ServerSecrets` still resolves and the Ruby gem is unaffected.

- [ ] **Step 1: Create `proto/src/config.rs`**

Move from `src/config.rs`, verbatim, with the SPDX header and a `//! Configuration types and their parsing. Contains no filesystem access — see `quietquic::config::FileSource` for loading from disk.` doc line:

- `struct Psk` with its `as_bytes`, manual `Debug` (prints `Psk(***)`), manual `Deserialize` (64-hex → 32 bytes), and `Zeroize`/`ZeroizeOnDrop` derives
- `struct ClientEntry`, `struct ServerSecrets`, `struct ClientConfigFile`
- `enum ConfigError`

Its inline `#[cfg(test)]` tests move too, **except** `file_source_loads`, which stays in `src/config.rs` with `FileSource`.

- [ ] **Step 2: Reduce `src/config.rs` to the filesystem loader**

Leave only the `SecretSource` trait, `FileSource`, its `impl`, and the `file_source_loads` test. Add at the top:

```rust
pub use quietquic_proto::config::{ClientConfigFile, ClientEntry, ConfigError, Psk, ServerSecrets};
```

- [ ] **Step 3: Declare in `proto/src/lib.rs`**

```rust
pub mod config;
```

- [ ] **Step 4: Verify**

Run: `cargo test --all`
Expected: all pass unmodified.

- [ ] **Step 5: Verify the Ruby gem still builds against the re-exports**

Run: `cd bindings/ruby && bundle exec rake compile && bundle exec rspec && cd ../..`
Expected: 62 examples, 0 failures. The gem calls `FileSource::new(path).load()` and the config types; both still resolve.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor: move config types into quietquic-proto, keep FileSource in quietquic"
```

---

### Task 5: Move the rate limiter, parameterized on `now`

**Files:**
- Move: `src/ratelimit.rs` → `proto/src/ratelimit.rs`
- Modify: `src/server.rs`, `proto/src/lib.rs`, `src/lib.rs`

**Interfaces:**
- Produces: `quietquic_proto::ratelimit::{TokenBucket, RateLimiter}` where `RateLimiter::check(&mut self, src: IpAddr, now: Instant) -> bool` already takes `now`. Confirm no internal `Instant::now()` call remains — the core must never read the clock itself.

- [ ] **Step 1: Move the file**

```bash
git mv src/ratelimit.rs proto/src/ratelimit.rs
```

- [ ] **Step 2: Assert the core never reads the clock**

Run: `grep -n "Instant::now()" proto/src/ratelimit.rs`
Expected: **no output.** If any is found, thread the caller's `now` through instead — the sans-IO contract requires the caller to own the clock.

- [ ] **Step 3: Declare and re-export**

`proto/src/lib.rs`: `pub mod ratelimit;`
`src/lib.rs`: replace `pub mod ratelimit;` with `pub use quietquic_proto::ratelimit;`
`src/server.rs`: `use crate::ratelimit::…` → `use quietquic_proto::ratelimit::…`

- [ ] **Step 4: Verify**

Run: `cargo test --all`
Expected: all pass unmodified, including the flood test.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: move rate limiter into quietquic-proto"
```

---

### Task 6: SPIKE — prove the core Endpoint API shape

**This is a feasibility spike. Its deliverable is a decision note plus a passing in-memory silence proof, not polished API.** It validates the §4 API shape before the risky extraction in Tasks 7–10.

**Files:**
- Create: `proto/src/outcome.rs`, `proto/src/endpoint.rs` (minimal), `proto/tests/core_silence.rs`
- Create: `docs/superpowers/notes/sans-io-core-decision.md`

**Interfaces (target — confirm or adjust during the spike, then record):**

```rust
pub enum DatagramOutcome { Dropped, Accepted(ConnHandle) }

impl Endpoint {
    pub fn new_server(secrets: ServerSecrets) -> Result<Endpoint, ConfigError>;
    pub fn handle_datagram(&mut self, now: Instant, from: SocketAddr, data: &[u8]) -> DatagramOutcome;
    pub fn poll_transmit(&mut self, now: Instant, buf: &mut Vec<u8>) -> Option<Transmit>;
}
```

- [ ] **Step 1: Create `proto/src/outcome.rs` with the outcome types**

```rust
// SPDX-License-Identifier: 0BSD
//! Non-blocking outcome types for the sans-IO core.
//!
//! These express the three states a caller-driven API needs — progress,
//! would-block, and end-of-stream — without inventing an error taxonomy.
//! `ConnError` remains the error type; "no data right now" is an expected,
//! non-fatal outcome, matching the POSIX shape callers already reason in.

/// Result of a non-blocking stream read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOutcome {
    /// `n` bytes were copied into the caller's buffer.
    Read(usize),
    /// No data is buffered right now; try again after a `StreamReadable` event.
    Blocked,
    /// The peer finished the stream (FIN); no more data will arrive.
    Finished,
}

/// Result of a non-blocking stream write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// `n` bytes were accepted (may be fewer than offered).
    Wrote(usize),
    /// Flow control is closed; try again after a `StreamWritable` event.
    Blocked,
}

/// Outcome of feeding one inbound datagram to the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramOutcome {
    /// The datagram failed the cloaking pre-filter. Nothing was queued to send:
    /// this is what makes server invisibility structural.
    Dropped,
    /// The datagram was admitted and routed to this connection.
    Accepted(quinn_proto::ConnectionHandle),
}
```

- [ ] **Step 2: Write the failing spike test `proto/tests/core_silence.rs`**

```rust
// SPDX-License-Identifier: 0BSD
//! Spike: prove the core API shape upholds the silence invariant with no sockets.

use quietquic_proto::config::ServerSecrets;
use quietquic_proto::endpoint::Endpoint;
use quietquic_proto::outcome::DatagramOutcome;
use std::net::SocketAddr;
use std::time::Instant;

fn server() -> Endpoint {
    let psk = "00".repeat(31) + "09";
    let secrets: ServerSecrets = toml::from_str(&format!(
        "listen = \"127.0.0.1:0\"\n[[clients]]\nclient_id=\"a\"\npsk=\"{psk}\"\n"
    ))
    .unwrap();
    Endpoint::new_server(secrets).expect("core server endpoint")
}

#[test]
fn junk_datagram_is_dropped_and_queues_no_transmit() {
    let mut ep = server();
    let now = Instant::now();
    let from: SocketAddr = "127.0.0.1:9999".parse().unwrap();

    let outcome = ep.handle_datagram(now, from, &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(outcome, DatagramOutcome::Dropped, "junk must be dropped");

    let mut buf = Vec::new();
    assert!(
        ep.poll_transmit(now, &mut buf).is_none(),
        "SILENCE VIOLATION: a dropped datagram queued a transmit"
    );
}

#[test]
fn stock_quic_shaped_initial_is_dropped_and_queues_no_transmit() {
    let mut ep = server();
    let now = Instant::now();
    let from: SocketAddr = "127.0.0.1:9998".parse().unwrap();

    // A long-header QUIC v1 Initial with a random 20-byte DCID: right shape,
    // no valid selector.
    let mut pkt = vec![0xc0];
    pkt.extend_from_slice(&0x0000_0001u32.to_be_bytes());
    pkt.push(20);
    pkt.extend_from_slice(&[0x5a; 20]);
    pkt.push(0);
    pkt.extend_from_slice(&[0u8; 1200]);

    assert_eq!(ep.handle_datagram(now, from, &pkt), DatagramOutcome::Dropped);

    let mut buf = Vec::new();
    assert!(
        ep.poll_transmit(now, &mut buf).is_none(),
        "SILENCE VIOLATION: an unauthorized Initial queued a transmit"
    );
}
```

- [ ] **Step 3: Run it and watch it fail**

Run: `cargo test -p quietquic-proto --test core_silence`
Expected: FAIL to compile — `quietquic_proto::endpoint` does not exist.

- [ ] **Step 4: Build the minimal Endpoint**

Create `proto/src/endpoint.rs` with just enough to satisfy the test: hold a `quinn_proto::Endpoint` (built with `crypto::reset_key()`, `crypto::token_key()`, `crypto::RecordingCidGenerator`, and the per-client crypto from `build_clients`), a `Vec<ClientCrypto>`, a `ReplayGuard`, a `RateLimiter`, and a `VecDeque<Transmit>` outbound queue.

`handle_datagram` runs the existing pre-filter logic — lifted from `Driver::prefilter` / `select_psk` / `is_active_dcid` in `src/server.rs` — in the same order: rate limit → `peek_dcid` → length check → `parse_dcid` → `is_fresh` → `select_psk` → `ReplayGuard::check_and_record`. On any rejection it returns `Dropped` **without touching the quinn-proto endpoint**. `poll_transmit` pops the outbound queue.

Declare in `proto/src/lib.rs`: `pub mod endpoint; pub mod outcome;`

- [ ] **Step 5: Run and watch it pass**

Run: `cargo test -p quietquic-proto --test core_silence`
Expected: 2 passed.

- [ ] **Step 6: Record the decision note**

Write `docs/superpowers/notes/sans-io-core-decision.md` capturing: the confirmed `Endpoint` signatures; any deviation from the spec's §4 shape and why; how the outbound transmit queue is represented; and how the pre-filter ordering was preserved. Tasks 7–10 build on this note.

- [ ] **Step 7: Verify nothing regressed and commit**

Run: `cargo test --all`
Expected: all existing tests still pass unmodified.

```bash
git add -A
git commit -m "spike(proto): prove core Endpoint API shape and silence with no sockets"
```

---

### Task 7: Core connection and stream state

**Files:**
- Create: `proto/src/conn.rs`
- Modify: `proto/src/lib.rs`

**Interfaces:**
- Produces: `quietquic_proto::conn::ConnState` owning one `quinn_proto::Connection` plus its per-stream buffers, with **non-blocking** stream operations:

```rust
impl ConnState {
    pub fn open_bi(&mut self) -> Result<StreamId, ConnError>;
    pub fn accept_bi(&mut self) -> Result<Option<StreamId>, ConnError>;
    pub fn stream_read(&mut self, id: StreamId, buf: &mut [u8]) -> Result<ReadOutcome, ConnError>;
    pub fn stream_write(&mut self, id: StreamId, buf: &[u8]) -> Result<WriteOutcome, ConnError>;
    pub fn stream_finish(&mut self, id: StreamId) -> Result<(), ConnError>;
    pub fn stream_reset(&mut self, id: StreamId, code: u64) -> Result<(), ConnError>;
    pub fn stream_stop(&mut self, id: StreamId, code: u64) -> Result<(), ConnError>;
    pub fn is_drained(&self) -> bool;
}
```

- Consumes: `ReadOutcome`/`WriteOutcome` from Task 6, `ConnError` (re-exported from `quietquic_proto`).

**Note:** `ConnError` currently lives in `src/conn.rs`. Move the enum itself into `proto/src/conn.rs` and re-export it from `quietquic::conn` so `quietquic::conn::ConnError` still resolves.

- [ ] **Step 1: Write the failing test** (append to `proto/tests/core_silence.rs` or a new `proto/tests/core_streams.rs`)

```rust
// proto/tests/core_streams.rs
// SPDX-License-Identifier: 0BSD
use quietquic_proto::outcome::ReadOutcome;

#[test]
fn read_on_an_idle_stream_reports_blocked_not_an_error() {
    // Build a connected pair in memory (helper from core_silence), open a bi
    // stream on side A, and read on side B before any data is sent.
    let (mut a, mut b) = quietquic_proto::testing::connected_pair();
    let id = a.open_bi().expect("open_bi");
    a.stream_write(id, b"x").expect("write");
    // Drive datagrams A -> B so B learns about the stream, but read *before*
    // pumping the data through.
    let mut buf = [0u8; 16];
    match b.stream_read(id, &mut buf) {
        Ok(ReadOutcome::Blocked) | Ok(ReadOutcome::Read(_)) => {}
        other => panic!("expected Blocked or Read, got {other:?}"),
    }
}
```

Add a `pub mod testing` to the core (gated behind `#[cfg(any(test, feature = "testing"))]` or simply `pub` — record which in the decision note) exposing `connected_pair()`, which drives two endpoints' datagrams into each other in memory until both report `Connected`. The spike's in-memory driving logic is the basis for it.

- [ ] **Step 2: Run and watch it fail**

Run: `cargo test -p quietquic-proto --test core_streams`
Expected: FAIL — `conn` / `testing` do not exist.

- [ ] **Step 3: Implement `proto/src/conn.rs`**

Port the stream servicing from `src/conn.rs`'s `ConnState` — `start_write`, `read_into`, the `pending_reads` map, `fail_all`, and the `is_drained()` reaping check — but **without** the command channel or oneshot replies. Reads return `ReadOutcome::Blocked` where the old code would have parked a `PendingRead`; that parking becomes the tokio layer's job.

- [ ] **Step 4: Run and watch it pass**

Run: `cargo test -p quietquic-proto --test core_streams`
Expected: PASS.

- [ ] **Step 5: Verify nothing regressed; commit**

Run: `cargo test --all`

```bash
git add -A
git commit -m "feat(proto): non-blocking connection and stream state"
```

---

### Task 8: Complete the core Endpoint

**Files:**
- Modify: `proto/src/endpoint.rs`, `proto/src/outcome.rs`

**Interfaces:**
- Produces, on `Endpoint`:

```rust
pub fn new_client(cfg: ClientConfigFile) -> Result<(Endpoint, ConnHandle), ConfigError>;
pub fn next_timeout(&self) -> Option<Instant>;
pub fn handle_timeout(&mut self, now: Instant);
pub fn poll_event(&mut self) -> Option<Event>;
pub fn conn_mut(&mut self, ch: ConnHandle) -> Option<&mut ConnState>;
```

- Adds to `outcome.rs`:

```rust
pub enum Event {
    Connected(quinn_proto::ConnectionHandle),
    StreamOpened { conn: quinn_proto::ConnectionHandle, id: StreamId },
    StreamReadable { conn: quinn_proto::ConnectionHandle, id: StreamId },
    StreamWritable { conn: quinn_proto::ConnectionHandle, id: StreamId },
    ConnectionLost { conn: quinn_proto::ConnectionHandle },
}
```

- [ ] **Step 1: Write the failing test** — extend `proto/tests/core_streams.rs`:

```rust
#[test]
fn in_memory_pair_completes_handshake_and_echoes_a_stream() {
    let (mut client, mut server) = quietquic_proto::testing::connected_pair();
    let id = client.open_bi().expect("open_bi");
    client.stream_write(id, b"ping").expect("write");
    client.stream_finish(id).expect("finish");
    let got = quietquic_proto::testing::pump_until_read(&mut client, &mut server, id);
    assert_eq!(&got, b"ping");
}
```

`pump_until_read` shuttles `poll_transmit` output between the two endpoints, calling `handle_datagram` and draining `poll_event`, until the target stream yields `Finished`, accumulating what `stream_read` returns.

- [ ] **Step 2: Run and watch it fail**

Run: `cargo test -p quietquic-proto --test core_streams`
Expected: FAIL — `new_client` / `poll_event` missing.

- [ ] **Step 3: Implement**

Port from `src/server.rs`: `admit`, the connection map, `drain_pending_cids`, `prune_connection_cids`, the `issued_cids` set with the `closed`/shutdown handling, and the reaping condition `progress.lost || state.conn.is_drained()`. Port the client-side endpoint construction from `src/client.rs`.

**Critical:** where the old `drive_connections` called `self.socket.send_to(...).await`, the core instead pushes onto the outbound transmit queue drained by `poll_transmit`. Where it emitted connections onto a channel, the core pushes `Event::Connected`.

- [ ] **Step 4: Run and watch it pass**

Run: `cargo test -p quietquic-proto --test core_streams`
Expected: PASS.

- [ ] **Step 5: Verify and commit**

Run: `cargo test --all`

```bash
git add -A
git commit -m "feat(proto): complete Endpoint with events, timers, and client construction"
```

---

### Task 9: Rewrite the tokio server over the core

**Files:**
- Modify: `src/server.rs`, `src/conn.rs`

**Interfaces:**
- Consumes: the full `quietquic_proto::endpoint::Endpoint` API.
- Produces: **no public API change.** `Server::bind`, `Server::local_addr`, `Server::accept`, `Connection`, and `Stream` keep their exact current signatures and behavior.

- [ ] **Step 1: Rewrite `Driver` as a thin pump**

The `select!` loop keeps its four arms (socket recv, command channel, timer, pending-accept delivery), but each now delegates:

| Old | New |
|---|---|
| `on_datagram` → `prefilter` → `feed_endpoint` | `core.handle_datagram(now, from, data)` |
| `drive_connections` sending inline | `while let Some(t) = core.poll_transmit(now, &mut buf) { socket.send_to(..).await }` |
| `next_timeout` returning `Sleep` | `core.next_timeout()` → wrap in `tokio::time::sleep_until` |
| `on_timeout` | `core.handle_timeout(now)` |
| connection/stream bookkeeping | `core.poll_event()` → dispatch |

`Cmd::ReadToEnd` keeps its `pending_reads` parking **in the tokio layer**, now looping over `core.conn_mut(ch).stream_read(...)`: `Read(n)` accumulates, `Blocked` parks until a `StreamReadable` event, `Finished` fires the oneshot with the accumulated `Vec<u8>`. This is what preserves `Stream::read_to_end`'s existing behavior with no public change.

- [ ] **Step 2: Verify the silence and lifecycle suites — unmodified**

Run: `cargo test --test cloaking --test server_prefilter --test spike_silence --test connection_lifecycle`
Expected: all pass with **zero test edits**. These are the crown jewels; a failure here means the extraction changed behavior.

- [ ] **Step 3: Verify the full suite**

Run: `cargo test --all && cargo clippy --all --all-targets -- -D warnings`
Expected: all pass, clippy clean.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: quietquic server driver becomes a thin pump over the core"
```

---

### Task 10: Rewrite the tokio client over the core

**Files:**
- Modify: `src/client.rs`

**Interfaces:**
- Produces: **no public API change.** `Client::connect`, `ClientError` (including `TimedOut` and `DEFAULT_CONNECT_TIMEOUT`) keep their exact signatures.

- [ ] **Step 1: Rewrite `ClientDriver` as a thin pump**

Same transformation as Task 9: `core.handle_datagram` / `poll_transmit` / `next_timeout` / `handle_timeout` / `poll_event`. The connect-completion oneshot fires on `Event::Connected`; the driver loop breaks on `Event::ConnectionLost`, preserving the `is_drained()` reaping behaviour that `tests/connection_lifecycle.rs` guards.

- [ ] **Step 2: Verify the client paths — unmodified**

Run: `cargo test --test client_server_roundtrip --test connection_lifecycle`
Expected: pass with zero test edits, including the 48-cycle server-side-close regression.

- [ ] **Step 3: Full suite plus the Ruby gem**

Run: `cargo test --all && cargo clippy --all --all-targets -- -D warnings`
Run: `cd bindings/ruby && bundle exec rake compile && bundle exec rspec && cd ../..`
Expected: 62 RSpec examples pass; the gem's Ruby API is untouched.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: quietquic client driver becomes a thin pump over the core"
```

---

### Task 11: Reference zero-timeout poll loop + core test suite

**Files:**
- Create: `proto/examples/poll_loop.rs`
- Modify: `proto/tests/core_silence.rs` (complete the silence matrix)

**Interfaces:** none new — this is documentation and coverage.

- [ ] **Step 1: Write the reference example**

`proto/examples/poll_loop.rs` demonstrates the target consumer's idiom: a single thread, a non-blocking UDP socket, and a loop that never parks. It must show, in order, the four things a sans-IO caller must not forget:

```rust
// SPDX-License-Identifier: 0BSD
//! Reference: driving quietquic from a hand-rolled, zero-timeout event loop.
//!
//! This is the shape a classic Unix reactor uses — `select()`/`poll()` with a
//! zero timeout, servicing whatever is ready and then getting on with other
//! work. Nothing here blocks or parks, and no async runtime is involved.
//!
//! The four obligations a sans-IO caller MUST honour every pass, in this order:
//!   1. feed inbound datagrams        (`handle_datagram`)
//!   2. service the timer deadline    (`next_timeout` / `handle_timeout`)
//!   3. drain ALL events, doing the caller's stream work as they arrive
//!                                    (`poll_event`, then `stream_read`/`stream_write`/…)
//!   4. drain ALL outbound transmits  (`poll_transmit`) — LAST
//! Skipping 2 or 4 makes connections stall silently — the classic sans-IO bug.
//!
//! Step 4 comes AFTER step 3, and that ordering is load-bearing, not stylistic.
//! `poll_transmit` is the only method that services connections, so it is what
//! turns caller-side stream work into bytes. Draining it *before* the stream
//! work leaves the MAX_STREAM_DATA/MAX_DATA credit a `stream_read` released
//! sitting unsent: the peer stays flow-control blocked, sends nothing, nothing
//! wakes the loop, and the connection hangs until the idle timeout. The
//! endpoint's `next_timeout()` defends against exactly this by reporting an
//! already-elapsed deadline while any connection has unflushed stream work, but
//! the loop should not need the safety net.
//!
//! And `next_timeout()` is only meaningful once `poll_transmit` has returned
//! `None`, which is why the sleep/deadline read at the bottom of the loop reads
//! it again rather than reusing the value from step 2.
```

The body: build a server `Endpoint`, a non-blocking `std::net::UdpSocket`, then loop — `recv_from` handling `WouldBlock`, feed via `handle_datagram`, compare `next_timeout()` against `Instant::now()` and call `handle_timeout` when due, drain `poll_event` dispatching stream reads/writes, then drain `poll_transmit` with `send_to` (last, after that stream work), then re-read `next_timeout()` for the sleep bound, then a placeholder comment marking where the caller's *other* work goes. Exit cleanly after a bounded number of passes so it can run in CI.

- [ ] **Step 2: Verify the example compiles and runs**

Run: `cargo run -p quietquic-proto --example poll_loop`
Expected: builds and exits 0.

- [ ] **Step 3: Complete the silence matrix in the core tests**

Extend `proto/tests/core_silence.rs` with the remaining cases, each asserting `DatagramOutcome::Dropped` **and** that `poll_transmit` yields nothing: wrong-PSK selector, stale freshness (`now_minutes() - 10`), and replay (a valid selector datagram accepted once, then the identical bytes rejected). Mirror the assertions in `tests/cloaking.rs`, but through the core API with no sockets.

- [ ] **Step 4: Verify**

Run: `cargo test -p quietquic-proto`
Expected: all core tests pass, including the full silence matrix.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "docs(proto): reference zero-timeout poll loop; complete core silence matrix"
```

---

### Task 12: Ruby gem packaging — vendor the core crate

**Files:**
- Modify: `bindings/ruby/Rakefile`, `bindings/ruby/ext/quietquic/extconf.rb`, `bindings/ruby/quietquic.gemspec`, `bindings/ruby/ext/quietquic/Cargo.toml`

**Interfaces:** none new. The gem's Ruby API is unchanged.

- [ ] **Step 1: Extend `vendor_core` to vendor both crates**

The `vendor_core` rake task currently copies the root crate's `src/`, `Cargo.toml`, `Cargo.lock`, and `LICENSE` into `ext/quietquic/vendor/quietquic-core/`. It must now also copy `proto/` and preserve the workspace relationship so the vendored root crate's `quietquic-proto = { path = "proto" }` still resolves inside the gem. Apply the same `rm_rf`-then-copy discipline already used.

- [ ] **Step 2: Verify the in-repo dev flow still works**

Run: `cd bindings/ruby && bundle exec rake compile && bundle exec rspec`
Expected: 62 examples pass.

- [ ] **Step 3: Verify the packaged gem installs**

```bash
cd bindings/ruby
rake vendor_core && gem build quietquic.gemspec
gem unpack quietquic-*.gem --target /tmp/sqcheck3
```

Expected: unpack succeeds with **no `Gem::Package::PathError`**. Confirm `/tmp/sqcheck3` contains both the vendored root crate and its `proto/` subdirectory. Clean up the built gem and `/tmp/sqcheck3` afterwards.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "build(ruby): vendor quietquic-proto into the gem"
```

---

### Task 13: tokio feature reduction, CI, and docs

**Files:**
- Modify: `Cargo.toml`, `.github/workflows/ci.yml`, `README.md`, `docs/superpowers/STATUS.md`

- [ ] **Step 1: Reduce the tokio feature requirement**

In the root `Cargo.toml`, change the tokio dependency from `features = ["net", "rt-multi-thread", "macros", "time", "sync"]` to `features = ["net", "rt", "macros", "time", "sync"]`. Forcing `rt-multi-thread` on consumers is wrong: a current-thread runtime is a legitimate and useful configuration, and the flavor is the application's choice.

- [ ] **Step 2: Verify with a current-thread runtime**

Run: `cargo test --all`
Expected: all pass. If a test uses `#[tokio::test(flavor = "multi_thread")]` it keeps working via dev-dependencies, which still enable `full`.

- [ ] **Step 3: Add the example to CI**

In `.github/workflows/ci.yml`, add `cargo run -p quietquic-proto --example poll_loop` to the Rust job so the reference loop cannot rot, and ensure `cargo test --all` covers the workspace.

- [ ] **Step 4: Update the docs**

In `README.md`, add a short "Architecture" section: `quietquic-proto` is the sans-IO core (no I/O, no runtime, no threads — drive it from your own event loop, see `proto/examples/poll_loop.rs`), and `quietquic` is the tokio wrapper. In `docs/superpowers/STATUS.md`, move sub-project **A1** from "📐 Spec approved, not implemented" to "✅ Done", and note that the core is embeddable in a hand-rolled loop.

- [ ] **Step 5: Full cross-platform verification**

Run: `cargo test --all && cargo clippy --all --all-targets -- -D warnings`
Run on FreeBSD (rsync the tree to the VM per `STATUS.md`): `cargo test --all`, plus `cd bindings/ruby && bundle exec rake compile && bundle exec rspec` with `MAKE=gmake` and `LIBCLANG_PATH` set.
Expected: green on both platforms.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: require tokio rt not rt-multi-thread; CI example; architecture docs"
```

---

## Self-Review

**Spec coverage:**
- §2 goals (no-I/O core; unchanged public API; structural silence; reference loop) → Tasks 1–11, 13. ✓
- §3 crate structure (root package + `proto/` member; no tokio in core; `vendor_core` task) → Tasks 1, 12. ✓
- §4 core API (`handle_datagram`/`poll_transmit`/`next_timeout`/`handle_timeout`/`poll_event`, stream ops, outcome enums) → Tasks 6, 7, 8. ✓
- §4 "extraction only" nuance (no public `read_to_end` in core; tokio composes it) → Task 9 Step 1. ✓
- §5 what moves / what stays (incl. `FileSource` staying, ratelimit `now`-parameterized, tokio `rt`) → Tasks 2–5, 13. ✓
- §6 silence preserved and strengthened → Tasks 6, 9 (unmodified suites), 11 (full matrix through the core). ✓
- §7 front-loaded spike → Task 6, with the sequencing deviation explained in the header. ✓
- §8 testing (existing unmodified, new core tests, reference example, cross-platform, fuzz) → Tasks 2–13. Fuzz targets build against parsers that moved to the core; `cargo test --all` and CI cover it. ✓
- §9 success criteria (1–7) → Task 1 Step 5 (no tokio), Tasks 2–10 (unmodified tests), Task 8 (in-memory handshake+echo), Task 11 (silence matrix, example), Task 13 (tokio `rt`, FreeBSD). ✓
- §10 risks → mitigated by the spike (Task 6), the unmodified-suite gates (Tasks 9, 10), the lifecycle test (Task 10 Step 2), and packaging re-verification (Task 12). ✓

**Placeholder scan:** Task 6 is an explicit spike with recorded outcomes; Tasks 7–10 reference the spike's decision note for exact signatures rather than fabricating them against unported code. Moves are specified as verbatim `git mv` plus the exact `use`-path edits, which is complete information for a move. No "TBD", no "add error handling", no "similar to Task N".

**Type consistency:** `ReadOutcome`/`WriteOutcome`/`DatagramOutcome`/`Event`, `Endpoint::{new_server, new_client, handle_datagram, poll_transmit, next_timeout, handle_timeout, poll_event, conn_mut}`, and `ConnState::{open_bi, accept_bi, stream_read, stream_write, stream_finish, stream_reset, stream_stop, is_drained}` are used identically across Tasks 6–11. `ConnError` is reused throughout and never joined by a second taxonomy.

**Known risk:** the largest single step is Task 9 (rewriting the server driver). Its gate is deliberately harsh — the cloaking, prefilter, silence, and lifecycle suites must pass with **zero edits** — so a behavioral drift fails loudly rather than being absorbed into an adjusted test.
