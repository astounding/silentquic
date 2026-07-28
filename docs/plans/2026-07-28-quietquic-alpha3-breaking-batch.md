# QuietQUIC 0.1.0-alpha.3 — send-half completion + quinn-alignment breaking batch

## Scoping principle

Alpha.3 is the last cheap moment to break the API: alpha.1 was published and
revoked, alpha.2 was never published, and there are no serious users yet.
Therefore alpha.3 deliberately batches EVERY known breaking change —
signatures, type shapes, error taxonomy, event vocabulary — while deferring
purely ADDITIVE surface (uni streams, stats/rtt, datagrams, `AsyncRead`/
`AsyncWrite`), which can land in any later alpha without breaking anyone.
A secondary goal throughout: converge on quinn 0.11's names and shapes so
developers who know quinn can transfer their habits directly.

## 0. Starting point: skip alpha.2, migrate the prototype

`0.1.0-alpha.2` was prepared in git but not published to crates.io. Since
`0.1.0-alpha.1` was published and later deleted/revoked, the next public
crate release is `0.1.0-alpha.3`; do not publish alpha.2 as a catch-up.

The working tree already contains a first pass of the finish feature: a
core-to-driver `StreamFinished` signal (`proto/src/conn.rs`,
`proto/src/endpoint.rs`, `proto/src/outcome.rs`), a compound finish-and-wait
driver command, a driver-side `finished_sends: HashSet<StreamId>` cache, and
a one-shot `Stream::finish_and_wait()`. Alpha.3 converts that prototype to
the durable split API; nothing from it ships as-is, and nothing new is added
beside a surviving duplicate.

Disposition of the existing edits:

- KEEP (as the seed of §5): the `StreamFinished` event plumbing through
  `ConnProgress` / `Event` / endpoint translation. Rename per D2
  (`StreamFinAcked`) and extend it to carry `Stopped` as well — the
  prototype handles only the acknowledgement half.
- CONVERT: the compound finish-and-wait command becomes `Cmd::WaitFinished`
  (§6). The compound form cannot serve the split `finish();
  wait_finished()` contract without a second `stream_finish`, which errors
  on an already-finished stream. `finish_and_wait()` survives only as
  sugar composed from the two primitives.
- DELETE: the driver-side `finished_sends` `HashSet`, entirely. Its job
  (bridging "ack arrived before the waiter registered") moves into the
  core's `send_fins` map (§5), which `apply_cmd` consults on the same
  driver task that processes events — the race the cache papered over
  cannot occur by construction. This also removes the unbounded-growth
  path: ordinary `finish()` calls with no waiter no longer accrete driver
  state, and the core fact has a documented forget/eviction lifecycle.
- RESHAPE: anything prototype-side built on the unsplit `Stream` type
  moves to `SendStream` under D5 (the unsplit type is deleted).
- SALVAGE: prototype tests, reshaped to the §8 matrix.

Process: diff the working tree against the alpha.2 release commit first and
audit it against this plan. Prefer re-deriving the work following §11's
sequencing, treating the prototype as a spike to cherry-pick from.

## 1. Goals

1. Send-half completion: callers can learn the terminal outcome of a
   stream's send half — FIN fully acknowledged, refused via STOP_SENDING,
   or lost with the connection. Motivation: bindings (Ruby). The current
   API has no completion barrier (`finish()` only queues FIN) and
   `Connection::close()` fires CONNECTION_CLOSE immediately, so
   write → finish → close can silently lose unacked data.
2. Quinn-alignment breaking batch: structured errors, a quinn-parity
   `ConnectionError` for terminal connection facts, quinn-shaped stream
   handles and method names, `close(code, reason)` + `closed()`, local
   `reset`/`stop`, `Clone` connections, future-proofed event vocabulary.
3. Correctness riders discovered during planning: the blocked-write-on-
   STOP_SENDING hang, and unadvertised-but-granted uni-stream credit
   (§5, transport config).

## 2. Non-goals (explicitly out of alpha.3 — all additive later)

- Unidirectional streams. Additive later BECAUSE alpha.3 does two things
  now: `StreamOpened` gains a `dir` field (the breaking part), and the
  transport config pins `max_concurrent_uni_streams(0)` so no peer can
  open a stream this release cannot service (§5). Required before h3.
- `rtt()`, `stats()`, QUIC datagrams, 0-RTT (0-RTT additionally
  interacts with the cloaking design and needs its own analysis).
- `AsyncRead`/`AsyncWrite` impls. Quinn offers them because its streams
  share locked state; faking `poll_read` over a oneshot command channel
  means holding in-flight command futures inside handles — deferred
  until demand is proven.
- By-`StreamId` read/write on `QuinnHandle`. Docs corrected instead;
  by-id ops on a `Clone` handle would expose the single-entry parked-map
  clobber semantics, defined when h3 work needs the surface.
- Policy timeouts. Rust callers use `tokio::time::timeout`; bindings
  supply their own defaults.
- `quinn_proto::VarInt` in any public signature. All application error
  codes are `u64`, validated eagerly (§3a `InvalidErrorCode`); the core
  converts internally. Keeps the API self-contained for FFI bindings.

## 3. Error taxonomy (B1 — the deepest breaking change; do it first)

Two distinct vocabularies, because stream-operation failures and terminal
connection facts are different concepts (quinn separates them too):

### 3a. `ConnError` — stream/connection *operation* errors (core-shared)

    #[non_exhaustive]
    #[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
    pub enum ConnError {
        #[error("connection closed")]
        Closed,                          // op failed because the connection is gone
        #[error("stream stopped by peer: code {code}")]
        Stopped { code: u64 },           // send half: PEER sent STOP_SENDING
        #[error("stream reset by peer: code {code}")]
        Reset { code: u64 },             // recv half: PEER sent RESET_STREAM
        #[error("closed or unknown stream")]
        ClosedStream,                    // wrong-state/unknown-stream ops,
                                         // including ops after a LOCAL reset()/stop()
        #[error("stream exceeded read limit of {limit} bytes")]
        ReadLimitExceeded { limit: usize },
        #[error("invalid application error code {code} (exceeds varint range)")]
        InvalidErrorCode { code: u64 },
        #[error("transport: {0}")]
        Transport(String),               // escape hatch for the long tail
    }

Peer-vs-local rule (normative): `Stopped`/`Reset` ALWAYS mean the peer
did it. A LOCAL `reset()` or `stop()` renders subsequent local operations
(including a parked `wait_finished` / `pending_read`) `ClosedStream` —
which is also exactly quinn's answer for post-local-terminal ops, so the
reuse is the alignment, not a shortcut. No `LocallyReset` variant.

Every `map_err(... format!("{e:?}"))` site in the core is audited and
mapped to a variant; `Transport(String)` catches only the genuinely rare
remainder. Outcome enums (`ReadOutcome`, `WriteOutcome`) are untouched.

### 3b. `ConnectionError` — terminal connection facts (quinn-parity name)

Lives in `quietquic-proto::outcome`; RE-EXPORTED from the root crate as
`quietquic::conn::ConnectionError`, exactly mirroring the existing
`ConnError` re-export, so `Connection::closed()`'s return type has an
obvious import path. Returned by `closed()`; carried by
`Event::ConnectionLost`. Mirrors quinn's variant set, with reason bytes
AND structured codes preserved (all of quinn-proto's underlying data is
cleanly numeric: `TransportErrorCode` wraps a bare `u64`, `FrameType` is
a varint — no lossy mapping needed):

    #[non_exhaustive]
    #[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
    pub enum ConnectionError {
        #[error("closed by peer application: code {code}")]
        ApplicationClosed { code: u64, reason: Vec<u8> },
        #[error("closed by peer transport: code {code}")]
        ConnectionClosed  { code: u64, frame_type: Option<u64>, reason: Vec<u8> },
        #[error("transport error: code {code}: {reason}")]
        TransportError    { code: u64, frame_type: Option<u64>, reason: String },
        #[error("stateless reset")]
        Reset,
        #[error("timed out")]
        TimedOut,
        #[error("closed locally")]
        LocallyClosed,
        #[error("version mismatch")]
        VersionMismatch,
        #[error("connection IDs exhausted")]
        CidsExhausted,
    }

Mapped from `quinn_proto::ConnectionError` at the single point the core
observes loss today; the `is_drained()` self-close reap path reports
`LocallyClosed`. Stream ops still fail with plain `ConnError::Closed`;
callers who want the rich reason use `closed()`.

Decision D1 (unchanged): the shared structured `ConnError` above
(recommended) vs additional per-operation quinn-parity enums
(`WriteError`/`ReadError`/...) at the tokio layer with `From`
conversions. Either way, 3a and 3b both land.

## 4. Public API (root crate `quietquic`) — quinn-shaped

D5 (recommended, breaking): adopt quinn's stream shape. `open_bi` /
`accept_bi` return `(SendStream, RecvStream)`; the unsplit `Stream` type
and `split()` are DELETED. Removes the three-way method duplication and
the `split(self)`-vs-`Drop` E0509 pitfall; gives quinn users the exact
shape they know.

    impl Connection {          // now #[derive(Clone)] — quinn's Connection is Clone
        pub async fn open_bi(&self)   -> Result<(SendStream, RecvStream), ConnError>;
        pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), ConnError>;
        pub async fn close(&self, code: u64, reason: &[u8]) -> Result<(), ConnError>;
        pub async fn closed(&self) -> ConnectionError;
        // remote_address, handle, client_id, quinn_connection unchanged
    }

`close`: the handle validates `VarInt::from_u64(code)` EAGERLY (a pure
check) and returns `InvalidErrorCode` immediately; after validation the
command is fire-and-forget exactly as today (driver already gone ⇒ `Ok`,
the connection is effectively closed anyway). No reply channel.
Document the reason semantics: the local copy is caller-controlled
memory (no artificial API bound), and quinn-proto TRUNCATES the reason
phrase on the wire to fit a single packet (`reason.len().min(max_len)`
in its close-frame encoders) — keep reasons short; bytes beyond a
packet's room are silently dropped by the transport, not by quietquic.

`closed()`: NOT a driver command. Each connection owns a
`tokio::sync::watch::Receiver<Option<ConnectionError>>` cloned into
every `Connection` (and clone); the driver holds the sender and sets the
terminal value at the single place it reaps (both loss paths: remote
loss AND the `is_drained()` self-close reap), BEFORE dropping per-
connection state. `closed()` awaits the watch locally, so EVERY retained
clone gets the same terminal answer, before or after reap, even if the
driver task itself is gone (sender dropped ⇒ receivers wake ⇒ report
`LocallyClosed`). This replaces the earlier `Cmd::WaitClosed` design,
which lost the terminal reason exactly when callers need it most.

    impl SendStream {
        pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), ConnError>;
        pub async fn finish(&mut self) -> Result<(), ConnError>;        // unchanged semantics
        pub async fn wait_finished(&mut self) -> Result<(), ConnError>; // new
        pub async fn finish_and_wait(&mut self) -> Result<(), ConnError> {
            self.finish().await?; self.wait_finished().await
        }
        pub async fn reset(&mut self, code: u64) -> Result<(), ConnError>;  // eager varint check
        pub fn id(&self) -> StreamId;
    }

    impl RecvStream {
        pub async fn read(&mut self, max: usize) -> Result<Vec<u8>, ConnError>;
        pub async fn read_to_end(&mut self, limit: usize) -> Result<Vec<u8>, ConnError>;
        pub async fn stop(&mut self, code: u64) -> Result<(), ConnError>;   // eager varint check
        pub fn id(&self) -> StreamId;
    }

    impl QuinnHandle {         // h3 seam; docs corrected to actual surface
        pub async fn open_bi(&self)   -> Result<(SendStream, RecvStream), ConnError>;
        pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), ConnError>;
        pub async fn finish(&self, id: StreamId) -> Result<(), ConnError>;
        pub async fn wait_finished(&self, id: StreamId) -> Result<(), ConnError>;
        pub async fn finish_and_wait(&self, id: StreamId) -> Result<(), ConnError>;
        pub async fn forget_send(&self, id: StreamId);   // by-id release, see D3
    }

`forget_send` delivery semantics (explicit): awaits command-channel
capacity and enqueues the release; if the driver is gone, the release is
moot and the call returns silently. No `Result` — there is no failure a
caller could act on. (Contrast: `SendStream::drop` uses `try_send`,
because `Drop` cannot await; channel-full there means the entry lives
until connection teardown.)

`wait_finished()` contract:

- Resolves `Ok(())` on full FIN acknowledgement; `Err(Stopped { code })`
  on peer STOP_SENDING; `Err(Closed)` on connection loss. Never blocks
  the driver, a worker thread, or other streams; never stays parked past
  a terminal stream fact.
- Repeated calls after a terminal fact keep returning the same answer
  until the send state is released (§6 lifecycle).
- Multiple concurrent waiters all receive the terminal fact (broadcast).
- Called before any successful local `finish()`: immediate `ClosedStream`
  — never parks forever. Exception: if the peer already stopped the
  stream, `Stopped { code }` is returned (terminal, more informative).
- Local `reset()` before or while waiting: `ClosedStream` (peer-vs-local
  rule, §3a) — the waiter never hangs.
- Document plainly: FIN ack proves the peer's *transport* received all
  stream data — not that the peer *application* read or processed it.
  Application-level responses remain the stronger signal.
- Decision D6: name. `wait_finished()` (recommended) vs quinn's
  `stopped() -> Ok(Option<code>)` parity shape. Either way the "coming
  from quinn" table (§9) documents the mapping.

## 5. Sans-IO core (`quietquic-proto`)

`proto/src/conn.rs` — send-half state machine:

    #[non_exhaustive]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SendFin {
        Queued,       // stream_finish succeeded; FIN not yet fully acked
        Acked,        // all data + FIN acknowledged by the peer
        Stopped(u64), // peer STOP_SENDING
    }

    pub fn send_fin(&self, id: StreamId) -> Option<SendFin>;  // None = no finish, no stop

- Storage: `send_fins: HashMap<StreamId, SendFin>`.
- `stream_finish` consults `send_fins[id]` BEFORE touching quinn-proto,
  and the rule is explicit (the core's recorded fact is authoritative;
  never re-enter quinn in a state the core already knows is terminal):
  - existing `Stopped(code)` → return `Err(ConnError::Stopped { code })`;
  - existing `Acked`         → return `Err(ConnError::ClosedStream)`
    (quinn has freed the stream; this short-circuits to the same answer);
  - existing `Queued`        → return `Err(ConnError::ClosedStream)`
    (double finish — quinn's `FinishError::ClosedStream`, short-circuited);
  - no entry → call quinn's `finish()`; on success insert `Queued`.
- `service_streams` handles the two events currently lost to `_ => {}`:
  `StreamEvent::Finished { id }` → `Acked`; `StreamEvent::Stopped { id,
  error_code }` → `Stopped(code)`; both recorded in progress. `Stopped`
  is recorded even without a prior local finish.
- TERMINAL STICKINESS (normative): the first terminal fact (`Acked` or
  `Stopped`) wins and is never overwritten — not by the other terminal,
  and never by `Queued`. This is not hypothetical: quinn-proto's
  `received_stop_sending` leaves `SendState::DataSent` intact, so a
  late ACK of fully-in-flight data can emit `Finished` AFTER `Stopped`;
  that late `Finished` is deliberately ignored (matching quinn's
  `stopped()`, which resolves on the first fact). Conversely `Stopped`
  cannot arrive after `Acked` (the acked stream is freed), but the
  guard is unconditional anyway.
- Eviction, mirroring `finished_reads`: new explicit `forget_send(id)`;
  `forget_stream` releases both halves; `stream_reset` removes the entry.
  `stream_stop` (recv half) leaves it alone. Same documented growth
  contract: a caller multiplexing many streams must release.

Transport config rider (correctness fix): quietquic constructs NO
`TransportConfig` today, so quinn-proto's default uni-stream credit
(100) is silently advertised while `service_streams` strands any
peer-opened uni stream. Alpha.3 pins `max_concurrent_uni_streams(0)`
(client and server) until uni support lands, so no peer can open a
stream this release cannot service. The `StreamOpened.dir` field below
therefore only ever carries `Dir::Bi` in practice this release.

`ConnProgress` gains (and becomes `#[non_exhaustive]`):

    pub fin_acked: Vec<StreamId>,
    pub stopped: Vec<(StreamId, u64)>,
    pub lost: Option<ConnectionError>,      // was `lost: bool`

`proto/src/outcome.rs` `Event` (becomes `#[non_exhaustive]`; also drops
`Copy` — `ConnectionError` carries `Vec<u8>`/`String`. `Event` is
`Clone` from here on; `ConnectionHandle` stays `Copy`):

    StreamOpened   { conn: ConnectionHandle, id: StreamId, dir: Dir },
    StreamFinAcked { conn: ConnectionHandle, id: StreamId },
    StreamStopped  { conn: ConnectionHandle, id: StreamId, error_code: u64 },
    ConnectionLost { conn: ConnectionHandle, reason: ConnectionError },

Rationale for `dir` and `reason` landing now: field additions to
existing variants are breaking even under `#[non_exhaustive]`; doing
them in alpha.3 makes uni streams and rich close reporting purely
additive later.

`proto/src/endpoint.rs`: translate the new `ConnProgress` fields in the
same staging loop; map `quinn_proto::ConnectionError` → §3b at the
single loss point (self-close reap → `LocallyClosed`; `ConnectionClose`
/ `ApplicationClose` / `TransportError` fields map numerically —
`TransportErrorCode` and `FrameType` are `u64`-clean).

`proto/examples/poll_loop.rs`: add match arms — the sans-IO consumer
demo must show the new events, not lose them in a wildcard.

Changelog note (from `#[non_exhaustive]`): external code can no longer
construct `ConnProgress` by struct literal or exhaustively match `Event`
/ the error enums; same-crate code is unaffected. Listed explicitly in
the BREAKING section with the migration (use `Default` + field
assignment; add wildcard arms).

## 6. Tokio layer (root crate)

`src/conn.rs`:

- `Cmd` gains:

      WaitFinished { id: StreamId, reply: oneshot::Sender<Result<(), ConnError>> },
      Reset  { id: StreamId, code: VarInt, reply: oneshot::Sender<Result<(), ConnError>> },
      Stop   { id: StreamId, code: VarInt, reply: oneshot::Sender<Result<(), ConnError>> },
      ReleaseSend { id: StreamId },     // best-effort from Drop; awaited from forget_send

  and `Close` gains `{ code: VarInt, reason: Vec<u8> }` (validated
  eagerly caller-side, so commands carry `VarInt`, not `u64`; `VarInt`
  never appears in public signatures). `Finish` unchanged. There is NO
  `WaitClosed` command — `closed()` is watch-based (§4).
  `finish_and_wait` is composed sugar; the core fact bridges the gap if
  the ack lands between the two commands.

- `Parked` gains:

      fin_waiters: HashMap<StreamId, Vec<oneshot::Sender<Result<(), ConnError>>>>,

  `apply_cmd(WaitFinished)`: consult `core.send_fin(id)` first —
  `Some(Acked)` → Ok now; `Some(Stopped(c))` → `Stopped{code}` now;
  `Some(Queued)` → push waiter; `None` → `ClosedStream` now. Same-task
  command/event processing closes the registration race by construction.

  `apply_cmd(Reset)`: forward to `core.stream_reset` (which evicts the
  send-fin entry); fail `fin_waiters[id]` and any `blocked_writes[id]`
  with `ClosedStream` (local action — peer-vs-local rule).
  `apply_cmd(Stop)`: forward to `core.stream_stop`; fail any
  `pending_reads[id]` with `ClosedStream`.

  Dispatch hooks, called from both drivers:
  `on_fin_acked(id)`: drain `fin_waiters[id]`, Ok to all.
  `on_stopped(core, id, code)`: fail `fin_waiters[id]` with
  `Stopped{code}`; re-offer `blocked_writes[id]` (existing `on_writable`
  path; `pump_write` surfaces the structured stop error).
  `fail_all()`: extend to drain `fin_waiters` with `Closed`.
  Driver reap path: set the `closed`-watch value (§4) BEFORE dropping
  per-connection state, on both loss paths.
  Delete the prototype-only `pending_finishes`/`finished_sends` path.

  NOTE — the `Stopped` plumbing fixes a latent bug: a `write_all` parked
  on flow control never wakes on peer STOP_SENDING today. Test it (§8).

`src/client.rs` / `src/server.rs`: new `CoreEvent` arms
(`StreamFinAcked`, `StreamStopped`, enriched `ConnectionLost`), routed
to the hooks, symmetric with readable/writable dispatch; watch sender
creation at connection-surface time.

Release lifecycle (D3, recommended): `impl Drop for SendStream` does a
best-effort `try_send(Cmd::ReleaseSend)`; channel-full ⇒ entry lives
until connection teardown (documented). With unsplit `Stream` deleted,
the E0509 pitfall is gone. RETENTION GAP CLOSED for by-id users:
`QuinnHandle::forget_send(id)` (§4) is the explicit release for flows
where no `SendStream` handle exists to drop. Documented contract: by-id
users own release, exactly as sans-IO embedders own `forget_stream`.
Also documented: a by-id `wait_finished` issued after the originating
`SendStream` was dropped may find the fact already released
(`ClosedStream`).

## 7. Edge-case semantics (normative summary)

| Situation                                    | `wait_finished` result           |
|----------------------------------------------|----------------------------------|
| FIN fully acked (before or after the call)   | `Ok(())`, repeatable             |
| Peer STOP_SENDING (before or after)          | `Stopped { code }`               |
| Peer stop, then late ack of in-flight data   | `Stopped { code }` (first wins)  |
| Connection lost while parked                 | `Closed`                         |
| No local `finish()` yet, no stop             | immediate `ClosedStream`         |
| Local `reset()` before/while waiting         | `ClosedStream`; never hangs      |
| Called again after terminal fact             | same answer, until released      |
| Two+ waiters, same stream                    | all resolve identically          |
| `finish()` twice                             | `ClosedStream` (short-circuited) |

`closed()` resolves with §3b's `ConnectionError` for every termination
path — peer app close (code + reason bytes), peer transport close,
transport error, stateless reset, idle timeout, local `close()` — on
EVERY retained clone, before or after the driver has reaped the
connection (watch invariant). Ordering: `wait_finished` observes command
order on the driver channel; `finish().await` completing before
`wait_finished()` is issued gives callers the intuitive guarantee for
free.

## 8. Tests

Sans-IO (`proto/tests/`), driving both endpoints by hand:

- core_streams.rs: `finish` → `Queued`; ack → `Acked` + `fin_acked`;
  stop → `Stopped(code)` + `stopped`; stop-before-finish recorded;
  finish-after-stop returns `Stopped{code}` from the core's recorded
  fact; finish-after-ack and double-finish return `ClosedStream`
  (short-circuit rule); TERMINAL STICKINESS: deliver STOP_SENDING, then
  the ACK that completes the in-flight FIN — state stays `Stopped`, the
  late `Finished` is ignored; `forget_send` / `forget_stream` /
  `stream_reset` evict; repeated short-lived finished streams stay
  bounded when released.
- core_driving.rs: withhold datagram delivery to prove `send_fin` stays
  `Queued` when FIN is merely queued locally, then deliver + ack and
  observe `Acked` (transport ACKs are independent of peer app reads; a
  "slow reader" does not test this).
- core_endpoint.rs: `StreamFinAcked`/`StreamStopped` carry the right
  handle/id/code; `ConnectionLost` carries the right `ConnectionError`
  incl. reason bytes and structured codes for peer app close, peer
  transport close (frame_type), `TimedOut`, `TransportError`, and
  `LocallyClosed` on the `is_drained()` reap path; `StreamOpened`
  carries `dir`; a peer attempting `open_uni` gets no credit
  (`max_concurrent_uni_streams(0)`).
- Error taxonomy: mapped `map_err` sites produce their variants; no
  test asserts on error strings.

Tokio integration (`tests/`, new `stream_finish.rs` + updates; key
scenarios against both drivers):

- `finish_and_wait` completes end-to-end once the peer acks; split
  `finish(); wait_finished()` completes without a second finish;
  `wait_finished` after the ack already landed returns Ok.
- Peer STOP_SENDING (via the new `RecvStream::stop`) resolves a pending
  wait promptly with `Stopped{code}`; a parked `write_all` wakes with
  `Stopped{code}` (regression for the latent hang).
- `SendStream::reset` fails a parked local `wait_finished` with
  `ClosedStream`; local `stop` fails a parked local read with
  `ClosedStream` (peer-vs-local rule).
- `close(code, reason)`: peer's `closed()` reports
  `ApplicationClosed { code, reason }` with the bytes round-tripped;
  `close` with an out-of-range code returns `InvalidErrorCode` without
  sending; `closed()` resolves on idle-timeout and transport-error
  paths.
- WATCH INVARIANT: create several `Connection` clones; some call
  `closed()` before the loss, some after the driver has reaped the
  connection — ALL resolve, all with the SAME terminal reason (this is
  the scenario the command-based design failed).
- Connection loss wakes fin waiters with `Closed`; independent streams
  don't cross-wake; multiple waiters (cloned `QuinnHandle`, cloned
  `Connection`) all complete; wait-before-finish errors immediately;
  repeated wait after ack is idempotent.
- Unit tests in `src/conn.rs`: plain `finish()` leaves no waiter;
  `SendStream` drop releases the core fact; `QuinnHandle::forget_send`
  releases it for by-id flows and returns silently when the driver is
  gone.
- Full existing suite green after the migration (cloaking,
  spike_silence, server_prefilter, client_server_roundtrip, lifecycle,
  proto tests — all updated to `open_bi`/tuple).

Gates:

    cargo fmt --all --check
    cargo clippy --workspace --all-targets   # if CI enforces it
    cargo test --workspace
    cargo deny check
    cargo package -p quietquic-proto
    cargo package -p quietquic

Inspect both `.crate` archives; record source commit and checksums.

## 9. Documentation

- README: rewrite the stream example in the new shape; caveat paragraph
  (transport ack ≠ app processing; acks may be delayed; no built-in
  timeout — show `tokio::time::timeout`; a binding-supplied deadline
  like Ruby's 10 s is an upper bound, never an unconditional delay).
- "Coming from quinn" section: mapping table (`open_bi` ↔ `open_bi`,
  `wait_finished` ↔ `stopped()`, `closed()` ↔ `closed()`,
  `ConnectionError` ↔ `ConnectionError`, structured `ConnError` ↔
  per-op errors, `u64` codes ↔ `VarInt`) plus deliberate divergences
  (command-channel architecture, no uni streams yet — credit pinned to
  0, no `AsyncRead`/`AsyncWrite` yet, PSK handshake instead of certs,
  close-reason truncation note).
- Peer-vs-local error rule (§3a) documented on `reset`, `stop`,
  `wait_finished`, and both error enums.
- Fix `QuinnHandle` docs; note its future (grow for h3 or collapse into
  `Clone`able `Connection`); `forget_send` delivery semantics.
- `docs/specs/2026-07-05-quietquic-core-design.md`: update the binding
  `Event` enum, `ConnState` operation list, and error notes (`SendFin`,
  `send_fin`, `forget_send`, `stream_finish` short-circuit rule, new
  events, `ConnectionError`, terminal stickiness, transport-config uni
  pin); retire the "quinn-parity errors are sub-project 2" deferral.
- CHANGELOG: explicit BREAKING section listing every renamed/reshaped
  item and migration, including `Event: Copy` → `Clone` and the
  `#[non_exhaustive]` construction/matching impact. STATUS.md,
  HISTORY.md, rustdoc in the house style.

## 10. Release

1. Bump both crates to `0.1.0-alpha.3`; root pin `=0.1.0-alpha.3`.
2. Do not publish `0.1.0-alpha.2`; alpha.3 is the next public release.
3. All gates in §8 green on CI (all platforms).
4. Publish `quietquic-proto` first, then `quietquic`; verify docs.rs.
5. Tag `v0.1.0-alpha.3`; record archives' commit + checksums per
   RELEASE.md.

## 11. Sequencing

0. Audit the working-tree prototype against this plan; carry the event
   plumbing forward, park the compound command/cache for reference.
1. Core: structured `ConnError` + `ConnectionError` (§3) — FIRST; every
   later signature depends on them (+ core tests).
2. Core: `SendFin` state machine (terminal stickiness, `stream_finish`
   short-circuit rule) + `forget_send` eviction (+ core tests).
3. Core: event vocabulary — `fin_acked`, `stopped`, `StreamOpened.dir`,
   `ConnectionLost.reason`, `Event: Clone` not `Copy`,
   `#[non_exhaustive]`, uni-credit pin, endpoint translation,
   `poll_loop` (+ core tests).
4. Tokio: `Cmd` additions (`WaitFinished`/`Reset`/`Stop`/enriched
   `Close`), `Parked` waiters/hooks, closed-watch plumbing, driver
   dispatch, blocked-write-on-stop fix (+ unit tests).
5. Tokio shape: D5 tuple `open_bi`/`accept_bi`, delete unsplit `Stream`,
   `Connection: Clone`, `closed()`, `reset`/`stop`, `ConnectionError`
   re-export, migrate all tests/examples (+ integration tests).
6. D3 drop-release + `QuinnHandle::forget_send` (separable commit).
7. Docs: README rewrite, "Coming from quinn", spec update, CHANGELOG
   breaking list.
8. Release mechanics.

## 12. Open decisions

- D1: structured shared `ConnError` only (recommended) vs additional
  per-operation quinn-parity error enums at the tokio layer.
- D2: event names `StreamFinAcked`/`StreamStopped` (recommended) vs
  quinn-parity `StreamFinished`.
- D3: `SendStream` drop-release + `QuinnHandle::forget_send` in alpha.3
  (recommended) vs documented retention only.
- D5: tuple-return `open_bi`/`accept_bi` + delete unsplit `Stream`
  (recommended) vs keeping the unsplit type alongside.
- D6: `wait_finished()` name and Ok/Err shape (recommended) vs quinn's
  `stopped() -> Ok(Option<code>)` parity shape.

  Resolved: `closed()` is watch-based, not a driver command; error codes
  are `u64` + eager validation + `InvalidErrorCode` — `quinn_proto::
  VarInt` stays out of all public signatures; `ConnectionError` (quinn's
  name, quietquic::conn re-export) replaces `LostReason` and preserves
  structured codes, frame types, and reason bytes; close reasons are
  documented as wire-truncated by quinn-proto, no API bound.

## 13. Implementation cautions (from final review; normative)

- `Connection::close()` MUST NOT surface `CmdSender::send`'s dead-channel
  mapping. `CmdSender::send` returns `Err(ConnError::Closed)` when the
  driver is gone (src/conn.rs:89); `close()`'s contract is the opposite —
  after the eager varint check, driver-gone is `Ok(())` (the connection
  is effectively closed already). Implement by discarding the send
  result (as today's `close()` does with `let _ =`), never by `?`.
  The only `Err` out of `close()` is `InvalidErrorCode`.
- The closed-watch SENDER lives in driver-owned per-connection state
  (beside `Parked`), created when the connection is admitted — NOT held
  only via the surfaced `Connection`. Every `Connection` handed out
  (accept path, connect path, clones) carries a receiver cloned from
  that one sender, so accepted-but-not-yet-surfaced connections and all
  clones observe the same single terminal write at reap time.
- D5 sweep includes re-exports: `src/server.rs:62` currently re-exports
  `{ConnError, Connection, QuinnHandle, Stream}`; `Stream` becomes
  `{SendStream, RecvStream}` there (and anywhere else a workspace-wide
  `grep 'pub use.*Stream'` finds). Client has no equivalent today.
- Land the `quietquic::conn::ConnectionError` re-export in sequencing
  step 1 (with the type itself), not step 5 — otherwise every
  intermediate commit that touches `closed()`/events produces noisy
  unresolved-import errors during the migration.

## 14. Adopted decisions (final)

D1 shared structured `ConnError` (no per-op enums this release);
D2 `StreamFinAcked`/`StreamStopped`; D3 drop-release +
`QuinnHandle::forget_send`; D5 tuple `open_bi`/`accept_bi`, unsplit
`Stream` deleted; D6 `wait_finished()` name and Ok/Err shape. §12's
"resolved" list stands. Implementation proceeds in §11 order.
