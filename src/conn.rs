// SPDX-License-Identifier: 0BSD
//! Post-handshake connection and stream handles, shared by client and server.
//!
//! In sans-IO `quinn-proto`, the DRIVER owns the `quinn_proto::Connection` and
//! must pump it continuously (poll_transmit → socket, feed inbound datagrams,
//! service timers, drain app events). Application code cannot hold the
//! `Connection` directly without stalling that pump. So [`Connection`] and
//! [`Stream`] here are *lightweight handles*: they send commands to the driver
//! over a [`tokio::sync::mpsc`] channel and await replies over
//! [`tokio::sync::oneshot`] channels. The driver applies each command against
//! the owned `quinn_proto::Connection` inside its event loop and routes stream
//! events back.
//!
//! This module is deliberately transport-agnostic: the server driver
//! ([`crate::server`]) and the client driver ([`crate::client`]) both translate
//! the same `Cmd`s, so the stream plumbing is written once and lives in
//! neither `server.rs` nor `client.rs`.
//!
//! # Why the *parking* lives here and not in the core
//!
//! `quietquic_proto` is sans-IO: it cannot wait for anything, so its
//! `ConnState::stream_read` answers `Read(n)` / `Blocked` / `Finished` right
//! now and never completes later. But this crate's public API promises
//! `Stream::read_to_end(limit).await` — a call that *does* complete later. The
//! difference between those two shapes is exactly `Parked`: the map of handle
//! operations that have been offered to the core, come back `Blocked`, and are
//! now waiting for the [`quietquic_proto::outcome::Event`] that says "try
//! again". The driver owns one `Parked` per live connection and services it
//! from its event dispatch; the core stays free of channels and runtimes.
//!
//! # Forward-compat seam ([`Connection::quinn_connection`])
//!
//! HTTP/3 (`h3`) and other stream protocols need a handle onto the underlying
//! QUIC connection to open/accept streams and drive protocol frames. Because the
//! driver — not the application — owns the `quinn_proto::Connection`, we cannot
//! hand out a `&quinn_proto::Connection` reference (it lives on another task,
//! mutated behind the command channel). Instead [`Connection::quinn_connection`]
//! returns a [`QuinnHandle`]: the minimal, `Clone`able command surface an
//! `h3`-style layer needs (open/accept bidirectional streams, read/write/finish
//! by `StreamId`) without ever touching the cloaking/pre-filter layer. See
//! [`QuinnHandle`] for the shape and the rationale.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use quietquic_proto::conn::ConnState as CoreConn;
use quietquic_proto::outcome::{ConnectionHandle, ReadOutcome, WriteOutcome};
use quinn_proto::StreamId;
use tokio::sync::{mpsc, oneshot};

/// Errors surfaced by [`Connection`] and [`Stream`] operations.
///
/// The enum itself lives in the sans-IO core (`quietquic_proto::conn`) so both
/// layers report failures in the same vocabulary — a hand-rolled embedder and a
/// tokio application see one error type, not two that must be translated. It is
/// re-exported here so `quietquic::conn::ConnError` keeps resolving.
pub use quietquic_proto::conn::ConnError;

/// A command paired with the connection it targets. The driver owns one
/// `mpsc::Receiver<Tagged>` across all its connections and routes each command
/// to the matching [`ConnState`] by `handle`. (The server owns many connections;
/// the client owns one — the same channel shape serves both.)
pub(crate) struct Tagged {
    pub(crate) handle: ConnectionHandle,
    pub(crate) cmd: Cmd,
}

/// A [`Cmd`] channel sender pre-bound to one connection's handle, so handles can
/// enqueue commands without knowing the routing key. Cloned freely across a
/// connection's [`Connection`] / [`Stream`] / [`QuinnHandle`] handles.
#[derive(Clone)]
pub(crate) struct CmdSender {
    handle: ConnectionHandle,
    tx: mpsc::Sender<Tagged>,
}

impl CmdSender {
    pub(crate) fn new(handle: ConnectionHandle, tx: mpsc::Sender<Tagged>) -> Self {
        Self { handle, tx }
    }

    async fn send(&self, cmd: Cmd) -> Result<(), ConnError> {
        self.tx
            .send(Tagged {
                handle: self.handle,
                cmd,
            })
            .await
            .map_err(|_| ConnError::Closed)
    }
}

/// One command the driver applies against its owned `quinn_proto::Connection`.
///
/// Every variant that produces a result carries a [`oneshot::Sender`] the driver
/// fires once it has serviced the command (immediately for open/finish, or once
/// data/FIN arrives for a read). This keeps the driver in sole control of the
/// `Connection` while letting handles await outcomes.
pub(crate) enum Cmd {
    /// Open a new bidirectional stream; reply with its assigned id.
    OpenBi(oneshot::Sender<Result<StreamId, ConnError>>),
    /// Await the next peer-initiated bidirectional stream; reply with its id.
    AcceptBi(oneshot::Sender<Result<StreamId, ConnError>>),
    /// Append `data` to a send stream. Replies once fully buffered (the driver
    /// handles write-blocking internally and re-tries on `Writable`).
    Write {
        id: StreamId,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), ConnError>>,
    },
    /// Finish (FIN) a send stream.
    Finish {
        id: StreamId,
        reply: oneshot::Sender<Result<(), ConnError>>,
    },
    /// Read a recv stream to end-of-stream; reply with all bytes once FIN is
    /// observed (or an error if the stream is reset).
    ReadToEnd {
        id: StreamId,
        limit: usize,
        reply: oneshot::Sender<Result<Vec<u8>, ConnError>>,
    },
    /// Read up to `max` bytes, completing as soon as any data or FIN is
    /// available. An empty vector means clean end-of-stream.
    Read {
        id: StreamId,
        max: usize,
        reply: oneshot::Sender<Result<Vec<u8>, ConnError>>,
    },
    /// Close the connection with an application error code, sending a
    /// CONNECTION_CLOSE frame so the peer (and this side's driver) tear down
    /// promptly rather than waiting out the idle timeout.
    Close,
}

/// A post-handshake, PSK-authenticated QUIC connection.
///
/// Produced by the server (on `accept`) and the client (once its handshake
/// reaches `Connected`), so both sides surface the same type. A `Connection` is
/// a handle onto a connection the driver still owns and pumps; dropping it does
/// not tear the connection down (the driver keeps running until the peer closes
/// or the driver's owner is dropped).
pub struct Connection {
    remote: std::net::SocketAddr,
    handle: ConnectionHandle,
    client_id: Option<String>,
    cmds: CmdSender,
}

impl Connection {
    /// Build a handle for a connection the driver owns. `cmds` is the driver's
    /// command channel, pre-tagged with this connection's handle.
    pub(crate) fn new(
        handle: ConnectionHandle,
        remote: std::net::SocketAddr,
        client_id: Option<String>,
        cmds: CmdSender,
    ) -> Self {
        Self {
            remote,
            handle,
            client_id,
            cmds,
        }
    }

    /// The remote peer's socket address.
    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.remote
    }

    /// The endpoint-local handle identifying this connection.
    pub fn handle(&self) -> ConnectionHandle {
        self.handle
    }

    /// Authenticated server-side client identity.
    ///
    /// On a connection accepted by [`crate::server::Server`], this is the
    /// unique configured `client_id` whose PSK admitted the peer. Client-side
    /// connections return `None`.
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    /// Open a new bidirectional stream.
    pub async fn open_stream(&self) -> Result<Stream, ConnError> {
        let (tx, rx) = oneshot::channel();
        self.cmds.send(Cmd::OpenBi(tx)).await?;
        let id = rx.await.map_err(|_| ConnError::Closed)??;
        Ok(Stream::new(id, self.cmds.clone()))
    }

    /// Await the next bidirectional stream the peer opens.
    pub async fn accept_stream(&self) -> Result<Stream, ConnError> {
        let (tx, rx) = oneshot::channel();
        self.cmds.send(Cmd::AcceptBi(tx)).await?;
        let id = rx.await.map_err(|_| ConnError::Closed)??;
        Ok(Stream::new(id, self.cmds.clone()))
    }

    /// Close the connection, sending a CONNECTION_CLOSE frame so the peer tears
    /// down promptly (rather than waiting out the idle timeout). Best-effort: if
    /// the driver is already gone the connection is effectively closed anyway.
    pub async fn close(&self) {
        let _ = self.cmds.send(Cmd::Close).await;
    }

    /// The forward-compat escape hatch: a minimal, `Clone`able handle onto the
    /// underlying QUIC connection that lets `h3` (or any other stream protocol)
    /// be layered on top **without touching the cloaking / pre-filter layer**.
    ///
    /// It intentionally does *not* return `&quinn_proto::Connection`: the driver
    /// owns that value on another task and mutates it behind the command
    /// channel, so a borrow cannot be handed out. Instead this exposes the
    /// operations an h3 layer actually needs — open/accept bidirectional
    /// streams and read/write/finish by `StreamId` — as async methods that route
    /// through the same command channel. When h3 is added it drives its control
    /// and request streams entirely through this handle; nothing in `server.rs`
    /// / `client.rs` (the silence-critical routing) has to change. See
    /// [`QuinnHandle`].
    pub fn quinn_connection(&self) -> QuinnHandle {
        QuinnHandle {
            handle: self.handle,
            cmds: self.cmds.clone(),
        }
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("handle", &self.handle)
            .field("remote", &self.remote)
            .field("client_id", &self.client_id)
            .finish()
    }
}

/// The minimal command surface onto the driver-owned QUIC connection that a
/// higher-level stream protocol (e.g. `h3`) layers on top of. This is the
/// documented seam that keeps HTTP/3 layering decoupled from the cloaking layer:
/// h3 opens/accepts streams and moves bytes through *this*, never through the
/// server/client driver internals.
///
/// It mirrors [`Connection`]'s stream API (which is why both are thin wrappers
/// over the same `Cmd` channel) but is `Clone` and carries the raw
/// [`ConnectionHandle`], the identity h3 keys its per-connection
/// state on.
#[derive(Clone)]
pub struct QuinnHandle {
    handle: ConnectionHandle,
    cmds: CmdSender,
}

impl QuinnHandle {
    /// The endpoint-local handle identifying this connection.
    pub fn handle(&self) -> ConnectionHandle {
        self.handle
    }

    /// Open a new bidirectional stream.
    pub async fn open_bi(&self) -> Result<Stream, ConnError> {
        let (tx, rx) = oneshot::channel();
        self.cmds.send(Cmd::OpenBi(tx)).await?;
        let id = rx.await.map_err(|_| ConnError::Closed)??;
        Ok(Stream::new(id, self.cmds.clone()))
    }

    /// Await the next peer-initiated bidirectional stream.
    pub async fn accept_bi(&self) -> Result<Stream, ConnError> {
        let (tx, rx) = oneshot::channel();
        self.cmds.send(Cmd::AcceptBi(tx)).await?;
        let id = rx.await.map_err(|_| ConnError::Closed)??;
        Ok(Stream::new(id, self.cmds.clone()))
    }
}

/// A bidirectional QUIC stream handle. Like [`Connection`], it talks to the
/// driver over the shared command channel; the driver applies each write/finish/
/// read against the owned `quinn_proto::Connection` and its send/recv streams.
pub struct Stream {
    id: StreamId,
    cmds: CmdSender,
}

impl Stream {
    pub(crate) fn new(id: StreamId, cmds: CmdSender) -> Self {
        Self { id, cmds }
    }

    /// The stream's id.
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Write all of `buf` to the stream, waiting out flow-control back-pressure.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), ConnError> {
        let (tx, rx) = oneshot::channel();
        self.cmds
            .send(Cmd::Write {
                id: self.id,
                data: buf.to_vec(),
                reply: tx,
            })
            .await?;
        rx.await.map_err(|_| ConnError::Closed)?
    }

    /// Finish (send FIN on) the stream, signalling end-of-data to the peer.
    pub async fn finish(&mut self) -> Result<(), ConnError> {
        let (tx, rx) = oneshot::channel();
        self.cmds
            .send(Cmd::Finish {
                id: self.id,
                reply: tx,
            })
            .await?;
        rx.await.map_err(|_| ConnError::Closed)?
    }

    /// Read the stream to end-of-stream, up to `limit` bytes.
    ///
    /// Returns [`ConnError::ReadLimitExceeded`] instead of allowing an
    /// authenticated peer to grow memory without bound.
    pub async fn read_to_end(&mut self, limit: usize) -> Result<Vec<u8>, ConnError> {
        let (tx, rx) = oneshot::channel();
        self.cmds
            .send(Cmd::ReadToEnd {
                id: self.id,
                limit,
                reply: tx,
            })
            .await?;
        rx.await.map_err(|_| ConnError::Closed)?
    }

    /// Read up to `max` bytes. Returns an empty vector after clean FIN.
    pub async fn read(&mut self, max: usize) -> Result<Vec<u8>, ConnError> {
        read_chunk(&self.cmds, self.id, max).await
    }

    /// Split this bidirectional stream into independently movable receive and
    /// send handles so callers can relay both directions concurrently.
    pub fn split(self) -> (RecvStream, SendStream) {
        (
            RecvStream {
                id: self.id,
                cmds: self.cmds.clone(),
            },
            SendStream {
                id: self.id,
                cmds: self.cmds,
            },
        )
    }
}

/// Receive half of a split bidirectional stream.
pub struct RecvStream {
    id: StreamId,
    cmds: CmdSender,
}

impl RecvStream {
    pub async fn read(&mut self, max: usize) -> Result<Vec<u8>, ConnError> {
        read_chunk(&self.cmds, self.id, max).await
    }
}

/// Send half of a split bidirectional stream.
pub struct SendStream {
    id: StreamId,
    cmds: CmdSender,
}

impl SendStream {
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), ConnError> {
        let (tx, rx) = oneshot::channel();
        self.cmds
            .send(Cmd::Write {
                id: self.id,
                data: buf.to_vec(),
                reply: tx,
            })
            .await?;
        rx.await.map_err(|_| ConnError::Closed)?
    }

    pub async fn finish(&mut self) -> Result<(), ConnError> {
        let (tx, rx) = oneshot::channel();
        self.cmds
            .send(Cmd::Finish {
                id: self.id,
                reply: tx,
            })
            .await?;
        rx.await.map_err(|_| ConnError::Closed)?
    }
}

async fn read_chunk(cmds: &CmdSender, id: StreamId, max: usize) -> Result<Vec<u8>, ConnError> {
    if max == 0 {
        return Ok(Vec::new());
    }
    let (tx, rx) = oneshot::channel();
    cmds.send(Cmd::Read { id, max, reply: tx }).await?;
    rx.await.map_err(|_| ConnError::Closed)?
}

// ---------------------------------------------------------------------------
// Driver-side per-connection state. Owned by the driver task; not part of the
// public handle API. Holds only the *waiting* — the core owns the protocol.
// ---------------------------------------------------------------------------

/// How much of a stream to ask the core for per [`CoreConn::stream_read`] call.
/// The core copies at most `buf.len()` bytes and never stashes a remainder, so
/// this is purely a batching knob; a `read_to_end` loops until `Blocked` or
/// `Finished` regardless.
const READ_CHUNK: usize = 16 * 1024;

/// A write that is blocked on flow control: the remaining bytes, and the reply
/// channel to fire once the whole buffer has been accepted.
struct PendingWrite {
    data: Vec<u8>,
    offset: usize,
    reply: oneshot::Sender<Result<(), ConnError>>,
}

/// A read waiting for end-of-stream: the bytes gathered so far and the reply
/// channel to fire once FIN (or a reset) is seen.
struct PendingRead {
    buf: Vec<u8>,
    /// `Some` for a read-to-FIN operation. We read at most one byte beyond this
    /// bound to distinguish an exact-size stream from an oversized one.
    end_limit: Option<usize>,
    max: Option<usize>,
    reply: oneshot::Sender<Result<Vec<u8>, ConnError>>,
}

/// One live connection's parked handle operations.
///
/// This is the whole of the tokio layer's per-connection state: everything else
/// — streams, flow control, CIDs, timers, lifecycle — belongs to the core's
/// [`CoreConn`], which the driver borrows via
/// `Endpoint::conn_mut(handle)` and passes into every method here.
///
/// Each map holds operations the core answered with "not right now". They are
/// retried from the driver's event dispatch:
///
/// | parked in           | offered again on                        |
/// |---------------------|-----------------------------------------|
/// | `pending_accepts`   | `Event::StreamOpened`                   |
/// | `blocked_writes`    | `Event::StreamWritable`                 |
/// | `pending_reads`     | `Event::StreamReadable`                 |
///
/// and all three are failed with [`ConnError::Closed`] by [`Parked::fail_all`]
/// when `Event::ConnectionLost` names this connection.
#[derive(Default)]
pub(crate) struct Parked {
    /// Accept requests waiting for a peer-opened bi stream, FIFO.
    pending_accepts: VecDeque<oneshot::Sender<Result<StreamId, ConnError>>>,
    /// Writes blocked on flow control, keyed by stream.
    blocked_writes: HashMap<StreamId, PendingWrite>,
    /// Reads awaiting end-of-stream, keyed by stream.
    pending_reads: HashMap<StreamId, PendingRead>,
}

impl Parked {
    /// Apply one handle-issued command against `core`, answering immediately
    /// where the core can and parking where it cannot.
    ///
    /// Note what is *absent*: no transmit is sent from here and no timer is
    /// read. Every operation below marks its connection dirty inside the core,
    /// and the driver's pump drains `poll_transmit` after this returns — which
    /// is the documented order (stream work first, transmits last) and what
    /// gets the flow-control credit a read released onto the wire.
    pub(crate) fn apply_cmd(&mut self, core: &mut CoreConn, cmd: Cmd, now: Instant) {
        match cmd {
            Cmd::OpenBi(reply) => {
                let _ = reply.send(core.open_bi());
            }
            Cmd::AcceptBi(reply) => match core.accept_bi() {
                Ok(Some(id)) => {
                    let _ = reply.send(Ok(id));
                }
                // Nothing pending: park until `Event::StreamOpened`.
                Ok(None) => self.pending_accepts.push_back(reply),
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
            },
            Cmd::Write { id, data, reply } => {
                let mut pending = PendingWrite {
                    data,
                    offset: 0,
                    reply,
                };
                if !Self::pump_write(core, id, &mut pending) {
                    self.blocked_writes.insert(id, pending);
                }
            }
            Cmd::Finish { id, reply } => {
                let _ = reply.send(core.stream_finish(id));
            }
            Cmd::ReadToEnd { id, limit, reply } => {
                let mut pending = PendingRead {
                    buf: Vec::new(),
                    end_limit: Some(limit),
                    max: None,
                    reply,
                };
                if !Self::pump_read(core, id, &mut pending) {
                    self.pending_reads.insert(id, pending);
                }
            }
            Cmd::Read { id, max, reply } => {
                let mut pending = PendingRead {
                    buf: Vec::new(),
                    end_limit: None,
                    max: Some(max.max(1)),
                    reply,
                };
                if !Self::pump_read(core, id, &mut pending) {
                    self.pending_reads.insert(id, pending);
                }
            }
            Cmd::Close => {
                // The core deliberately exposes no `close`: it is a
                // connection-level operation with no non-blocking/blocking
                // distinction, so it goes straight to the owned connection.
                // The CONNECTION_CLOSE frame it queues leaves on the pump's
                // next `poll_transmit` drain, and the close timer it arms is
                // what eventually drives the connection to `Drained` — which
                // the core reaps and reports as `Event::ConnectionLost`.
                core.conn_mut()
                    .close(now, quinn_proto::VarInt::from_u32(0), bytes::Bytes::new());
            }
        }
    }

    /// A peer-opened stream arrived: hand queued streams to parked accepts,
    /// FIFO, for as long as both are available.
    ///
    /// The stream id is taken from `core.accept_bi()` rather than from the
    /// event, so the core's own accept queue is consumed in step with the
    /// replies — otherwise the next `accept_bi` would re-issue an id we have
    /// already handed out.
    pub(crate) fn on_stream_opened(&mut self, core: &mut CoreConn) {
        while !self.pending_accepts.is_empty() {
            match core.accept_bi() {
                Ok(Some(id)) => {
                    if let Some(reply) = self.pending_accepts.pop_front() {
                        let _ = reply.send(Ok(id));
                    }
                }
                Ok(None) => return,
                Err(e) => {
                    if let Some(reply) = self.pending_accepts.pop_front() {
                        let _ = reply.send(Err(e));
                    }
                    return;
                }
            }
        }
    }

    /// `id` has data buffered: resume a parked `read_to_end`, if any.
    pub(crate) fn on_readable(&mut self, core: &mut CoreConn, id: StreamId) {
        let Some(mut pending) = self.pending_reads.remove(&id) else {
            return;
        };
        if !Self::pump_read(core, id, &mut pending) {
            self.pending_reads.insert(id, pending);
        }
    }

    /// `id`'s flow control opened: resume a parked `write_all`, if any.
    pub(crate) fn on_writable(&mut self, core: &mut CoreConn, id: StreamId) {
        let Some(mut pending) = self.blocked_writes.remove(&id) else {
            return;
        };
        if !Self::pump_write(core, id, &mut pending) {
            self.blocked_writes.insert(id, pending);
        }
    }

    /// Fail every parked handle operation with [`ConnError::Closed`].
    ///
    /// Called when the connection is lost, so awaiting handles wake with an
    /// error rather than hanging until their oneshot senders happen to drop.
    pub(crate) fn fail_all(&mut self) {
        for reply in self.pending_accepts.drain(..) {
            let _ = reply.send(Err(ConnError::Closed));
        }
        for (_, pending) in self.blocked_writes.drain() {
            let _ = pending.reply.send(Err(ConnError::Closed));
        }
        for (_, pending) in self.pending_reads.drain() {
            let _ = pending.reply.send(Err(ConnError::Closed));
        }
    }

    /// Offer the rest of `pending` to the core, looping while it accepts bytes.
    /// Returns true when the write is complete or has errored (the reply has
    /// been sent); false when it is still blocked and should stay parked.
    fn pump_write(core: &mut CoreConn, id: StreamId, pending: &mut PendingWrite) -> bool {
        loop {
            if pending.offset >= pending.data.len() {
                let reply = replace_reply_ok(&mut pending.reply);
                let _ = reply.send(Ok(()));
                return true;
            }
            match core.stream_write(id, &pending.data[pending.offset..]) {
                // `stream_write` only reports `Wrote(0)` for an empty buffer,
                // which the length check above has already excluded, so this
                // always advances.
                Ok(WriteOutcome::Wrote(n)) => pending.offset += n,
                Ok(WriteOutcome::Blocked) => return false,
                Err(e) => {
                    let reply = replace_reply_ok(&mut pending.reply);
                    let _ = reply.send(Err(e));
                    return true;
                }
            }
        }
    }

    /// Drain everything the core has buffered for `id` into `pending`. Returns
    /// true when end-of-stream (or an error) was reached and the reply has been
    /// sent; false when more data may still arrive and the read stays parked.
    ///
    /// This loop **is** `read_to_end`: the core offers only the incremental
    /// `Read`/`Blocked`/`Finished` answer, and accumulating across `Blocked`s
    /// until `Finished` is what turns it back into the crate's one-shot
    /// `Stream::read_to_end` promise.
    fn pump_read(core: &mut CoreConn, id: StreamId, pending: &mut PendingRead) -> bool {
        loop {
            // Read straight into the tail of the accumulator, so a large
            // transfer costs no per-chunk allocation and no extra copy.
            let filled = pending.buf.len();
            let request = pending
                .max
                .map(|max| max.saturating_sub(filled).min(READ_CHUNK))
                .unwrap_or_else(|| {
                    pending
                        .end_limit
                        .map(|limit| {
                            limit
                                .saturating_add(1)
                                .saturating_sub(filled)
                                .min(READ_CHUNK)
                        })
                        .unwrap_or(READ_CHUNK)
                })
                .max(1);
            pending.buf.resize(filled + request, 0);
            let outcome = core.stream_read(id, &mut pending.buf[filled..]);
            match outcome {
                Ok(ReadOutcome::Read(n)) => {
                    pending.buf.truncate(filled + n);
                    if pending
                        .end_limit
                        .is_some_and(|limit| pending.buf.len() > limit)
                    {
                        let limit = pending.end_limit.expect("checked above");
                        let reply = replace_reply_read(&mut pending.reply);
                        let _ = reply.send(Err(ConnError::ReadLimitExceeded { limit }));
                        return true;
                    }
                    if pending.max.is_some() {
                        let buf = std::mem::take(&mut pending.buf);
                        let reply = replace_reply_read(&mut pending.reply);
                        let _ = reply.send(Ok(buf));
                        return true;
                    }
                }
                Ok(ReadOutcome::Blocked) => {
                    pending.buf.truncate(filled);
                    return false;
                }
                Ok(ReadOutcome::Finished) => {
                    pending.buf.truncate(filled);
                    // The core keeps one `StreamId` per cleanly-finished stream
                    // so a *repeat* read can answer `Finished` instead of
                    // erroring. This layer has no repeat read to serve — the
                    // `read_to_end` that owns this stream is completing right
                    // now — so release it, which both bounds that set on a
                    // connection carrying many short-lived streams and keeps
                    // this crate's pre-core behaviour (a second `read_to_end`
                    // on a drained stream is an error).
                    if pending.end_limit.is_some() {
                        core.forget_stream(id);
                    }
                    let buf = std::mem::take(&mut pending.buf);
                    let reply = replace_reply_read(&mut pending.reply);
                    let _ = reply.send(Ok(buf));
                    return true;
                }
                Err(e) => {
                    pending.buf.truncate(filled);
                    let reply = replace_reply_read(&mut pending.reply);
                    let _ = reply.send(Err(e));
                    return true;
                }
            }
        }
    }
}

// The reply senders live inside `&mut` structs while we may still need the
// struct afterward, so we swap in a throwaway closed channel to take ownership
// of the real sender. (oneshot::Sender is not Clone and send consumes it.)
fn replace_reply_ok(
    slot: &mut oneshot::Sender<Result<(), ConnError>>,
) -> oneshot::Sender<Result<(), ConnError>> {
    let (dead, _) = oneshot::channel();
    std::mem::replace(slot, dead)
}

fn replace_reply_read(
    slot: &mut oneshot::Sender<Result<Vec<u8>, ConnError>>,
) -> oneshot::Sender<Result<Vec<u8>, ConnError>> {
    let (dead, _) = oneshot::channel();
    std::mem::replace(slot, dead)
}
