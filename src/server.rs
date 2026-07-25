// SPDX-License-Identifier: 0BSD
//! Scanner-invisible cloaked QUIC server — a tokio pump over the sans-IO core.
//!
//! Every line of protocol logic this module used to carry now lives in
//! [`silentquic_proto::endpoint::Endpoint`]: the silence pre-filter (rate
//! limiter → long-header parse → selector length → PSK match → freshness →
//! anti-replay), the CID routing set that lets post-handshake packets bypass
//! that pre-filter, the per-PSK transport configs, connection admission,
//! servicing and reaping. What is left here is the part that genuinely needs a
//! runtime: a UDP socket, a timer, and the channels behind the public
//! [`Connection`] / [`Stream`] handles.
//!
//! # The pump
//!
//! [`Driver::run`] is one `select!` over four wakeups — an inbound datagram, a
//! handle command, the connection timer, and accept-channel capacity — and each
//! one is a single call into the core. Between wakeups, [`Driver::pump`] drains
//! the core in the order [`silentquic_proto::endpoint`] documents, **which is
//! load-bearing**:
//!
//! 1. feed datagrams / fire timers / apply commands (the `select!` arms),
//! 2. drain [`Endpoint::poll_event`](silentquic_proto::endpoint::Endpoint::poll_event)
//!    and do the stream work each event unblocks,
//! 3. drain [`Endpoint::poll_transmit`](silentquic_proto::endpoint::Endpoint::poll_transmit)
//!    to `None` — **after** the stream work of this pass, because that is what
//!    carries a read's released flow-control credit to the peer,
//! 4. and only then read
//!    [`Endpoint::next_timeout`](silentquic_proto::endpoint::Endpoint::next_timeout)
//!    to arm the sleep.
//!
//! Draining transmits before stream work is the classic sans-IO stall: the
//! credit never reaches the peer, the peer sends nothing, nothing wakes the
//! loop, and the connection hangs until the idle timeout.
//!
//! # Silence
//!
//! The invariant — *a datagram that fails the cloaking pre-filter queues nothing
//! to send* — is now structural rather than a property of this loop.
//! `handle_datagram` returns before a failing packet reaches quinn-proto, so
//! there is nothing for `poll_transmit` to hand back and this driver cannot
//! reply to an unauthorized peer even by mistake. Note the corollary that shapes
//! the code below: the driver **never branches its sends on
//! [`DatagramOutcome`](silentquic_proto::outcome::DatagramOutcome)**. `Dropped`
//! does not mean "nothing queued" (an authorized peer asking for an unsupported
//! QUIC version earns a Version Negotiation packet *and* a `Dropped`), so the
//! outcome is discarded and `poll_transmit` is always drained.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use quinn_proto::ConnectionHandle;
use silentquic_proto::endpoint::Endpoint as Core;
use silentquic_proto::outcome::Event as CoreEvent;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::config::ServerSecrets;
use crate::conn::{CmdSender, Parked, Tagged};

pub use crate::conn::{ConnError, Connection, QuinnHandle, Stream};

/// Max UDP datagram we will read.
const MAX_DATAGRAM: usize = 65_535;

/// Capacity of the channel that surfaces accepted connections to
/// [`Server::accept`]. When it fills (a slow `accept()` consumer), newly
/// surfaced connections queue in the driver's `pending_accept` instead of
/// blocking the pump path — see `Driver::run`'s reserve arm.
const ACCEPT_CHANNEL_CAP: usize = 32;

/// Capacity of the shared command channel every handle enqueues onto.
const CMD_CHANNEL_CAP: usize = 256;

/// How long to sleep when no connection has a pending deadline. The value is
/// arbitrary: any wakeup that matters (a datagram, a command, the `Server` being
/// dropped) arrives on another `select!` arm, so this only bounds how long an
/// utterly idle driver parks.
const IDLE_SLEEP: Duration = Duration::from_secs(3600);

/// A running cloaked QUIC server.
///
/// [`Server::bind`] starts a background driver task that owns the socket and the
/// core endpoint; [`Server::accept`] yields authenticated connections as the
/// core completes their handshakes. The driver *never* emits a byte for an
/// unauthenticated peer.
pub struct Server {
    local_addr: SocketAddr,
    incoming: mpsc::Receiver<Connection>,
    _driver: tokio::task::JoinHandle<()>,
}

impl Server {
    /// Bind the server to `secrets.listen` and start driving.
    pub async fn bind(secrets: ServerSecrets) -> io::Result<Server> {
        Self::bind_with_capacity(secrets, ACCEPT_CHANNEL_CAP).await
    }

    /// Bind with an explicit accept-channel capacity. Factored out of [`bind`] so
    /// tests can shrink the channel to force the "accept channel full" condition
    /// deterministically without opening dozens of real connections.
    ///
    /// [`bind`]: Server::bind
    async fn bind_with_capacity(
        secrets: ServerSecrets,
        accept_capacity: usize,
    ) -> io::Result<Server> {
        let socket = UdpSocket::bind(secrets.listen).await?;
        let local_addr = socket.local_addr()?;

        // The core builds the per-PSK transport configs, the replay guards, the
        // rate limiter and the recording CID generator; this layer never sees
        // any of them again.
        let core = Core::new_server(secrets).map_err(|e| io::Error::other(e.to_string()))?;

        let (tx, rx) = mpsc::channel(accept_capacity);
        let handle = tokio::spawn(Driver::new(socket, core, tx).run());

        Ok(Server {
            local_addr,
            incoming: rx,
            _driver: handle,
        })
    }

    /// Test-only: bind with a tiny accept-channel capacity so the full-channel /
    /// slow-consumer path is reachable without dozens of handshakes.
    #[cfg(test)]
    pub(crate) async fn bind_with_accept_capacity(
        secrets: ServerSecrets,
        accept_capacity: usize,
    ) -> io::Result<Server> {
        Self::bind_with_capacity(secrets, accept_capacity).await
    }

    /// The address the server is actually listening on (useful when bound to
    /// port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Await the next authenticated connection.
    ///
    /// Yields `Some` only for a peer that passed the full pre-filter and
    /// completed the QUIC handshake. It never yields for an unauthorized peer.
    /// Returns `None` if the driver has shut down.
    pub async fn accept(&mut self) -> Option<Connection> {
        self.incoming.recv().await
    }
}

/// The background task: owns the socket, the core endpoint, and the per-handle
/// channel plumbing. It owns no protocol state at all.
struct Driver {
    socket: UdpSocket,
    /// The sans-IO endpoint. Everything protocol-shaped lives in here.
    core: Core,
    /// Parked handle operations, per live connection. Keyed by the core's
    /// [`ConnectionHandle`], and — critically — an entry is removed the moment
    /// `Event::ConnectionLost` names it, because quinn-proto hands a freed
    /// handle straight back out to the next accept.
    parked: HashMap<ConnectionHandle, Parked>,
    /// Handles already surfaced to `Server::accept`, so a connection is offered
    /// exactly once. Cleared for a handle on `ConnectionLost`, so a reused
    /// handle is surfaced again as the new connection it now names.
    surfaced: HashSet<ConnectionHandle>,
    /// Where accepted connections are surfaced to `Server::accept`.
    accepted: mpsc::Sender<Connection>,
    /// Connections that have been surfaced but not yet delivered into the
    /// `accepted` channel because it was full at the time. The pump path NEVER
    /// blocks on `accepted.send().await` — instead it pushes here, and a
    /// dedicated `select!` arm drains this queue as capacity frees up. That is
    /// what keeps a slow `accept()` consumer from freezing the whole driver: a
    /// connection sitting here is fully live and still being pumped. FIFO, so
    /// connections are delivered in the order they connected.
    pending_accept: VecDeque<Connection>,
    /// Single command channel shared across all connections' handles. Each
    /// [`Tagged`] command names the connection it targets; the driver routes it
    /// to the matching [`Parked`] + core connection. Cloned (pre-tagged) into
    /// every `Connection` / `Stream` handle the driver hands out.
    cmd_tx: mpsc::Sender<Tagged>,
    cmd_rx: mpsc::Receiver<Tagged>,
}

impl Driver {
    fn new(socket: UdpSocket, core: Core, accepted: mpsc::Sender<Connection>) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(CMD_CHANNEL_CAP);
        Self {
            socket,
            core,
            parked: HashMap::new(),
            surfaced: HashSet::new(),
            accepted,
            pending_accept: VecDeque::new(),
            cmd_tx,
            cmd_rx,
        }
    }

    /// The main event loop. Returns only when the accept channel closes (i.e.
    /// the `Server` was dropped).
    ///
    /// The body order — pump, *then* arm the sleep, *then* wait — is the core's
    /// driving contract: the deadline is only meaningful once `poll_transmit`
    /// has been drained to `None`, because every servicing pass refreshes it.
    async fn run(mut self) {
        let mut recv_buf = vec![0u8; MAX_DATAGRAM];
        // A clone of the accept sender used SOLELY by the delivery arm below to
        // await a permit. Reserving on this clone (rather than on `self.accepted`)
        // keeps the `reserve()` future from borrowing `self`, so the other arms
        // can still take `&mut self`. A permit obtained on a clone sends into the
        // same channel, so ordering and capacity semantics are unchanged.
        let accept_tx = self.accepted.clone();
        loop {
            self.pump().await;

            // Read AFTER the pump. While any connection is dirty the core
            // deliberately reports an already-elapsed deadline; the pump has
            // just flushed that work, so what we get here is the real one.
            let sleep = match self.core.next_timeout() {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)),
                None => tokio::time::sleep(IDLE_SLEEP),
            };
            tokio::pin!(sleep);

            tokio::select! {
                res = self.socket.recv_from(&mut recv_buf) => {
                    match res {
                        Ok((len, from)) => {
                            // The outcome is deliberately discarded: rejection is
                            // the core's business, and `Dropped` does not imply
                            // "nothing queued". Sends are never branched on it —
                            // the pump just drains `poll_transmit`.
                            let _ = self.core.handle_datagram(
                                Instant::now(), from, &recv_buf[..len],
                            );
                        }
                        Err(_e) => continue, // transient socket error; keep serving
                    }
                }
                Some(tagged) = self.cmd_rx.recv() => {
                    self.on_command(tagged);
                }
                _ = &mut sleep => {
                    self.core.handle_timeout(Instant::now());
                }
                // Deliver a surfaced-but-undelivered connection into the accept
                // channel, but ONLY when one is waiting. This arm awaits a channel
                // *permit* (`reserve`) rather than blocking a `send` inside the
                // pump path, so waiting for a slow `accept()` consumer to make room
                // never stalls the socket-recv / command / timeout arms: existing
                // live connections keep being pumped while the app catches up. The
                // `if` disables the arm when the queue is empty, so an idle driver
                // never busy-spins on this branch.
                permit = accept_tx.reserve(), if !self.pending_accept.is_empty() => {
                    match permit {
                        // The guard guarantees a front element exists.
                        Ok(permit) => {
                            if let Some(conn) = self.pending_accept.pop_front() {
                                permit.send(conn);
                            }
                        }
                        // Channel closed → the `Server` handle was dropped.
                        Err(_) => return,
                    }
                }
                _ = self.accepted.closed() => {
                    return; // Server handle dropped
                }
            }
        }
    }

    /// Drain the core to quiescence: events first (doing the stream work each
    /// one unblocks), transmits second, repeating until a whole pass produces
    /// neither.
    ///
    /// The repeat is not belt-and-braces. `poll_transmit` is the call that
    /// services connections lazily, so the *transmit* drain is itself a
    /// producer of events — a `StreamReadable` discovered while servicing, or
    /// the `ConnectionLost` of a connection reaped by this very pass. Draining
    /// events only once would leave those sitting until something else happened
    /// to wake the `select!`, which for a quiet connection is the idle timeout.
    async fn pump(&mut self) {
        loop {
            let now = Instant::now();
            let mut progressed = false;

            // Events BEFORE transmits: an event may unpark a `read_to_end`
            // whose `stream_read` releases MAX_STREAM_DATA credit, and that
            // credit only reaches the peer via the drain below.
            while let Some(event) = self.core.poll_event() {
                self.on_event(event);
                progressed = true;
            }

            // Drained to `None`, every pass. Stopping early strands bytes.
            while let Some(transmit) = self.core.poll_transmit(now) {
                let _ = self
                    .socket
                    .send_to(&transmit.contents, transmit.destination)
                    .await;
                progressed = true;
            }

            if !progressed {
                return;
            }
        }
    }

    /// React to one core event.
    fn on_event(&mut self, event: CoreEvent) {
        match event {
            CoreEvent::Connected(ch) => self.surface(ch),
            CoreEvent::StreamOpened { conn, .. } => {
                if let (Some(parked), Some(state)) =
                    (self.parked.get_mut(&conn), self.core.conn_mut(conn))
                {
                    parked.on_stream_opened(state);
                }
            }
            CoreEvent::StreamReadable { conn, id } => {
                if let (Some(parked), Some(state)) =
                    (self.parked.get_mut(&conn), self.core.conn_mut(conn))
                {
                    parked.on_readable(state, id);
                }
            }
            CoreEvent::StreamWritable { conn, id } => {
                if let (Some(parked), Some(state)) =
                    (self.parked.get_mut(&conn), self.core.conn_mut(conn))
                {
                    parked.on_writable(state, id);
                }
            }
            CoreEvent::ConnectionLost { conn } => self.on_lost(conn),
        }
    }

    /// A connection finished its handshake: hand it to `Server::accept`.
    ///
    /// The driver keeps owning and pumping it; what leaves here is a
    /// [`Connection`] handle carrying a command sender pre-tagged with `ch`.
    /// Delivery is deferred to `run`'s reserve arm rather than awaited, so a
    /// slow consumer cannot stall the pump.
    fn surface(&mut self, ch: ConnectionHandle) {
        if !self.surfaced.insert(ch) {
            return;
        }
        let Some(state) = self.core.conn_mut(ch) else {
            self.surfaced.remove(&ch);
            return;
        };
        let remote = state.conn().remote_address();
        self.parked.insert(ch, Parked::default());
        let cmds = CmdSender::new(ch, self.cmd_tx.clone());
        self.pending_accept
            .push_back(Connection::new(ch, remote, cmds));
    }

    /// A connection is gone. **Every** retained copy of its handle is dropped
    /// here, before any retained handle is used again.
    ///
    /// This is not tidiness. `ConnectionHandle` is quinn-proto's slab index and
    /// a freed index is handed straight back out to the next accept, so a
    /// handle that outlives its `ConnectionLost` does not merely go stale — it
    /// starts naming a *different, live* connection, and `core.conn_mut` will
    /// happily return `Some` for it. A stale `surfaced` entry would then swallow
    /// the new connection's `Connected` (it would never be offered to
    /// `accept()`), and stale `parked` entries would route one connection's
    /// stream replies into another. That collision is precisely what
    /// `tests/connection_lifecycle.rs` reproduces around cycle ~32.
    ///
    /// Ordering is what makes it safe: the core queues `ConnectionLost` when it
    /// reaps, quinn-proto only frees the slab index at that same terminal
    /// transition, and `pump` drains every queued event before the next
    /// `select!` arm can feed the core again. So no accept can reuse `ch`
    /// between the reap and this cleanup.
    fn on_lost(&mut self, ch: ConnectionHandle) {
        if let Some(mut parked) = self.parked.remove(&ch) {
            // Wake anything awaiting a stream op with `Closed` rather than
            // letting the handles hang on a silently-dropped sender.
            parked.fail_all();
        }
        self.surfaced.remove(&ch);
        // A connection can be lost while still queued for delivery (surfaced,
        // but the app never called `accept()`). Dropping it here is what stops a
        // dead handle from being handed to the application and then routing its
        // commands into whichever connection later reuses `ch`.
        self.pending_accept.retain(|conn| conn.handle() != ch);
    }

    /// Route one handle-issued command to its connection.
    ///
    /// A command for a connection that is gone is simply dropped: that drops its
    /// reply `oneshot::Sender`, which wakes the awaiting handle with
    /// [`ConnError::Closed`].
    fn on_command(&mut self, tagged: Tagged) {
        let ch = tagged.handle;
        if let (Some(parked), Some(state)) = (self.parked.get_mut(&ch), self.core.conn_mut(ch)) {
            parked.apply_cmd(state, tagged.cmd, Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression proof for the non-blocking accept-delivery fix: a full accept
    /// channel plus queued-but-undelivered connections must NOT freeze the driver.
    ///
    /// The accept channel is shrunk to capacity 1. We accept one connection (A)
    /// and start echoing on its stream. Then two MORE authorized clients (B, C)
    /// connect but are never accepted: B fills the size-1 channel, and C has to
    /// sit in the driver's `pending_accept` queue with no channel permit. Under
    /// the old code, surfacing C called `accepted.send().await` inside the pump
    /// path, which blocked the whole select loop while the channel was full —
    /// freezing A. With the fix, C is enqueued and delivery waits in its own
    /// select arm, so A's stream must keep echoing.
    #[tokio::test]
    async fn slow_accept_consumer_does_not_freeze_live_connections() {
        use crate::client::Client;
        use crate::config::ClientConfigFile;

        let psk_hex = "0000000000000000000000000000000000000000000000000000000000000009";
        let secrets: ServerSecrets = toml::from_str(&format!(
            "listen = \"127.0.0.1:0\"\n[[clients]]\nclient_id=\"a\"\npsk=\"{psk_hex}\"\n"
        ))
        .unwrap();

        // Capacity 1: a single undelivered surfaced connection saturates the
        // channel, so a second one is forced to wait for a permit.
        let mut server = Server::bind_with_accept_capacity(secrets, 1).await.unwrap();
        let addr = server.local_addr();

        let mk_cfg = || -> ClientConfigFile {
            toml::from_str(&format!(
                "client_id=\"a\"\npsk=\"{psk_hex}\"\nserver=\"{addr}\"\n"
            ))
            .unwrap()
        };

        // Connection A: accept it so the channel is empty again, then hold it.
        let (conn_a, client_a) = tokio::join!(server.accept(), Client::connect(mk_cfg()));
        let conn_a = conn_a.expect("server accepts client A");
        let client_a = client_a.expect("client A handshakes");

        // Connections B and C connect but are NEVER accepted. B will occupy the
        // size-1 channel; C must queue in `pending_accept` awaiting a permit.
        // (Old blocking code would stall the driver here — including A.)
        let client_b = Client::connect(mk_cfg()).await.expect("client B handshakes");
        let client_c = Client::connect(mk_cfg()).await.expect("client C handshakes");

        // Give the driver time to surface B and C (one into the full channel, one
        // into pending_accept) without us accepting them.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // THE PROOF: with B/C undelivered and the accept channel full, A's stream
        // must still round-trip. If the driver were frozen on a blocking send,
        // this echo would time out.
        let mut a_stream = client_a.open_stream().await.expect("A opens a stream");
        a_stream.write_all(b"still-alive").await.expect("A writes");
        a_stream.finish().await.expect("A finishes");

        let mut srv_stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            conn_a.accept_stream(),
        )
        .await
        .expect("server servicing A must not be frozen by a full accept channel")
        .expect("server accepts A's stream");
        let got = srv_stream.read_to_end().await.expect("server reads A's stream");
        assert_eq!(&got, b"still-alive", "A's stream data must flow while B/C wait");
        srv_stream.write_all(&got).await.expect("server echoes to A");
        srv_stream.finish().await.expect("server finishes echo to A");

        let echo = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            a_stream.read_to_end(),
        )
        .await
        .expect("A's echo read must not time out")
        .expect("A reads the echo");
        assert_eq!(&echo, b"still-alive", "A round-trips while B/C sit undelivered");

        // And no connection was dropped or double-delivered: draining accept()
        // now must still yield B and C (two distinct connections), proving the
        // queued connection was delivered once the consumer caught up.
        let first = tokio::time::timeout(std::time::Duration::from_secs(10), server.accept())
            .await
            .expect("draining B must not time out")
            .expect("B is delivered");
        let second = tokio::time::timeout(std::time::Duration::from_secs(10), server.accept())
            .await
            .expect("draining C must not time out")
            .expect("C is delivered once a permit frees up");

        // Two more distinct connections were delivered (order is FIFO, but we only
        // assert both arrived without loss or duplication).
        assert_ne!(
            first.remote_address(),
            second.remote_address(),
            "B and C are delivered as two distinct connections (no drop, no double-deliver)"
        );

        // Keep clients alive to the end so their connections are not torn down
        // mid-test (which would confound the delivery assertions).
        drop((client_a, client_b, client_c));
    }
}
