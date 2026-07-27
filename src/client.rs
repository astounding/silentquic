// SPDX-License-Identifier: 0BSD
//! Cloaked QUIC client — a tokio pump over the sans-IO core.
//!
//! Every seam that makes a dial *cloaked* rather than stock QUIC now lives in
//! [`quietquic_proto::endpoint::Endpoint`]: the PSK-blinded selector DCID
//! (`build_dcid(psk, nonce, freshness)` installed as the Initial DCID), the
//! PSK-rekeyed Initial packet keys, the stock TLS 1.3 client crypto with
//! certificate verification skipped (the PSK authenticates, not the cert), and
//! the per-connection state machine. What is left here is the part that needs a
//! runtime: a UDP socket, a timer, and the channels behind the public
//! [`Connection`] / [`crate::conn::Stream`] handles.
//!
//! # The pump
//!
//! `ClientDriver::run` is one `select!` over three wakeups — an inbound
//! datagram, a handle command, and the connection timer — and each one is a
//! single call into the core. Between wakeups, `ClientDriver::pump` drains the
//! core in the order [`quietquic_proto::endpoint`] documents, **which is
//! load-bearing**:
//!
//! 1. feed datagrams / fire timers / apply commands (the `select!` arms),
//! 2. drain [`Endpoint::poll_event`](quietquic_proto::endpoint::Endpoint::poll_event)
//!    and do the stream work each event unblocks,
//! 3. drain [`Endpoint::poll_transmit`](quietquic_proto::endpoint::Endpoint::poll_transmit)
//!    to `None` — **after** the stream work of this pass, because that is what
//!    carries a read's released flow-control credit to the peer,
//! 4. and only then read
//!    [`Endpoint::next_timeout`](quietquic_proto::endpoint::Endpoint::next_timeout)
//!    to arm the sleep.
//!
//! Draining transmits before stream work is the classic sans-IO stall: the
//! credit never reaches the peer, the peer sends nothing, nothing wakes the
//! loop, and the connection hangs until the idle timeout.
//!
//! # A client answers nothing at the endpoint level
//!
//! A client endpoint has no server config, so any short-header datagram with an
//! unrecognized 8-byte DCID reaches quinn-proto's stateless-reset path. The core
//! gates endpoint-level responses on role — it emits one only for a
//! [`Role::Server`](quietquic_proto::endpoint) — so a client feeding such a
//! datagram queues nothing and this pump cannot emit an unsolicited packet even
//! by mistake. That closes a small reflection primitive the previous
//! hand-rolled driver had: it forwarded quinn-proto's endpoint response to the
//! configured server address, so an off-path party who could reach the client's
//! ephemeral port could make it spray unsolicited packets at the server. The
//! pump never re-creates that misdirection because it never sends anything the
//! core did not hand it, and the core hands a client nothing.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::ControlFlow;
use std::time::{Duration, Instant};

use quietquic_proto::endpoint::Endpoint as Core;
use quietquic_proto::freshness::now_minutes;
use quietquic_proto::outcome::ConnectionHandle;
use quietquic_proto::outcome::Event as CoreEvent;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use crate::config::{ClientConfigFile, ConfigError};
use crate::conn::{CmdSender, Connection, Parked, Tagged};

/// Max UDP datagram we will read.
const MAX_DATAGRAM: usize = 65_535;

/// Capacity of the command channel the returned handles enqueue onto.
const CMD_CHANNEL_CAP: usize = 256;

/// How long to sleep when the connection has no pending deadline. Arbitrary: any
/// wakeup that matters (a datagram, a command) arrives on another `select!` arm,
/// so this only bounds how long an utterly idle driver parks.
const IDLE_SLEEP: Duration = Duration::from_secs(3600);

/// Default bound on how long [`Client::connect`] will wait for the handshake to
/// reach `Connected` before giving up. `quinn_proto`'s own idle timer alone is
/// not a sufficient bound for a library caller who forgets to wrap the call in
/// their own timeout: a server that never responds at all (rather than one that
/// times out mid-handshake) can otherwise stall the caller indefinitely. Chosen
/// generously relative to a loopback handshake (sub-millisecond) so it never
/// fires on a connection that is progressing normally. May become configurable
/// later; a fixed default is sufficient for now.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Errors that can occur while connecting a cloaked QUIC client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Binding the local UDP socket or a socket I/O error while driving.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// Building the rustls / quinn-proto client crypto config failed.
    #[error("tls config: {0}")]
    Tls(String),
    /// `quinn_proto` refused to start the connection (e.g. bad transport params).
    #[error("connect: {0}")]
    Connect(#[from] quinn_proto::ConnectError),
    /// The peer terminated the handshake before it completed.
    #[error("connection lost during handshake: {0}")]
    ConnectionLost(#[from] quinn_proto::ConnectionError),
    /// The socket closed / the endpoint went quiet without ever connecting.
    #[error("handshake ended without connecting")]
    HandshakeIncomplete,
    /// The handshake did not reach `Connected` within the connect timeout (see
    /// the default connect timeout). Distinct from `ConnectionLost`: this fires
    /// when the peer never responds at all, rather than when it actively tears
    /// the handshake down.
    #[error("connect timed out")]
    TimedOut,
}

/// Map a core [`ConfigError`] onto the client's error taxonomy.
///
/// [`Core::new_client`] wraps every crypto / connect failure as
/// `ConfigError::Io(io::Error::other(..))`, so `Io` is the reachable arm; the
/// `Parse` arm cannot occur here (the config is already parsed) but is mapped
/// rather than panicked on.
fn client_error(err: ConfigError) -> ClientError {
    match err {
        ConfigError::Io(io) => ClientError::Io(io),
        ConfigError::Parse(parse) => ClientError::Io(io::Error::other(parse.to_string())),
        ConfigError::Invalid(message) => {
            ClientError::Io(io::Error::new(io::ErrorKind::InvalidInput, message))
        }
    }
}

/// A cloaked QUIC client.
///
/// The primary entry point is the associated [`Client::connect`] function, which
/// dials a server and drives the handshake to completion. `Client` currently
/// holds no long-lived state (the driving loop owns everything for the duration
/// of the connection); it exists as the named type the task interface calls for
/// and as the attachment point for future client-side configuration.
pub struct Client {
    _private: (),
}

impl Client {
    /// Dial the server named in `cfg`, embedding the blinded selector in the
    /// Initial DCID and re-keying the Initial packet from the PSK, and drive the
    /// handshake to completion.
    ///
    /// Returns a [`Connection`] the moment the QUIC handshake reaches
    /// `Connected`; the background driver keeps pumping so post-handshake stream
    /// I/O flows.
    ///
    /// Bounded internally by the default connect timeout: this does not rely
    /// solely on `quinn_proto`'s idle timer, so a caller who omits their own
    /// timeout still cannot hang forever against a server that never responds.
    pub async fn connect(cfg: ClientConfigFile) -> Result<Connection, ClientError> {
        connect(cfg).await
    }
}

/// Free-function form of [`Client::connect`], per the task interface. Bounded by
/// the default connect timeout; an injectable timeout is used internally for the
/// version used by tests.
pub async fn connect(cfg: ClientConfigFile) -> Result<Connection, ClientError> {
    connect_with_timeout(cfg, DEFAULT_CONNECT_TIMEOUT).await
}

/// Dial the server and drive the handshake to completion, bounded by
/// `connect_timeout`. `connect` delegates here with the default connect timeout;
/// kept private with an overridable duration so tests can force the timeout
/// path quickly without waiting out the production default.
async fn connect_with_timeout(
    cfg: ClientConfigFile,
    connect_timeout: Duration,
) -> Result<Connection, ClientError> {
    let server_addr = cfg.server;

    // Own a local UDP socket. By default bind the wildcard address of the
    // server's family with an ephemeral port — what ordinary QUIC clients do,
    // and the least distinctive choice for a transport whose job is to look
    // unremarkable. `cfg.bind` overrides it when the deployment requires a
    // specific interface and/or source port (egress firewall policy, pinning a
    // multi-homed host to one NIC, NAT traversal); see `ClientConfigFile::bind`.
    let bind_addr: SocketAddr = match cfg.bind {
        Some(explicit) => {
            // Catch a family mismatch here: binding v4 then dialing v6 (or vice
            // versa) otherwise fails deep in the OS with an opaque error.
            if explicit.is_ipv4() != server_addr.is_ipv4() {
                return Err(ClientError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "bind address {explicit} and server address {server_addr} are \
                         different IP versions"
                    ),
                )));
            }
            explicit
        }
        None if server_addr.is_ipv4() => (Ipv4Addr::UNSPECIFIED, 0).into(),
        None => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(bind_addr).await?;

    // Build the cloaked client endpoint and start dialing. The core owns all the
    // protocol crypto — the PSK-blinded selector DCID, the PSK-rekeyed Initial,
    // the stock TLS client config — and both clocks it needs are supplied here:
    // the monotonic `now` seeds the connection's timers, and the wall-clock
    // freshness minute goes into the selector DCID the server re-derives.
    let now = Instant::now();
    let freshness_minute = now_minutes();
    let (core, handle) = Core::new_client(now, freshness_minute, cfg).map_err(client_error)?;

    // One-shot handshake result: the driver sends `Ok(Connection)` once it sees
    // `Event::Connected`, or `Err(..)` if the connection is lost before then.
    let (connected_tx, connected_rx) = oneshot::channel();
    let driver = ClientDriver::new(socket, core, handle, connected_tx);
    let driver_task = tokio::spawn(driver.run());

    // Bound the handshake wait: without this, a server that never responds at
    // all (no packets, so quinn-proto's idle timer never even starts ticking
    // meaningfully) would leave a caller who forgot their own timeout awaiting
    // forever. On timeout we abort the driver task, cleanly tearing down the
    // socket/endpoint/connection — no leaked task.
    match tokio::time::timeout(connect_timeout, connected_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_recv)) => {
            // Driver dropped the sender without connecting (socket died / loop
            // exited); surface as an incomplete handshake.
            Err(ClientError::HandshakeIncomplete)
        }
        Err(_elapsed) => {
            driver_task.abort();
            Err(ClientError::TimedOut)
        }
    }
}

/// The background task: owns the socket, the core endpoint, and the per-handle
/// channel plumbing for the one connection this client dials. It owns no
/// protocol state at all — the core does.
struct ClientDriver {
    socket: UdpSocket,
    /// The sans-IO endpoint. Everything protocol-shaped lives in here.
    core: Core,
    /// The one connection this client owns, for its whole lifetime. A client
    /// never accepts, so this handle is never reused: the driver simply stops
    /// once it is lost.
    handle: ConnectionHandle,
    /// Parked handle operations (reads/writes/accepts the core answered "not
    /// right now") for `handle`. The tokio layer's whole per-connection state.
    parked: Parked,
    /// The command channel the surfaced [`Connection`] / [`Stream`] handles
    /// enqueue onto. The driver keeps its own sender so `cmd_rx.recv()` never
    /// resolves to `None` while the driver lives.
    cmd_tx: mpsc::Sender<Tagged>,
    cmd_rx: mpsc::Receiver<Tagged>,
    /// Fires once, with the `Connection` on `Event::Connected` or an error if the
    /// connection is lost first. `Option` so it is consumed on first use.
    connected: Option<oneshot::Sender<Result<Connection, ClientError>>>,
}

impl ClientDriver {
    fn new(
        socket: UdpSocket,
        core: Core,
        handle: ConnectionHandle,
        connected: oneshot::Sender<Result<Connection, ClientError>>,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(CMD_CHANNEL_CAP);
        Self {
            socket,
            core,
            handle,
            parked: Parked::default(),
            cmd_tx,
            cmd_rx,
            connected: Some(connected),
        }
    }

    /// The main event loop. Returns once the connection is lost.
    ///
    /// The body order — pump, *then* arm the sleep, *then* wait — is the core's
    /// driving contract: the deadline is only meaningful once `poll_transmit`
    /// has been drained to `None`, because every servicing pass refreshes it.
    async fn run(mut self) {
        let mut recv_buf = vec![0u8; MAX_DATAGRAM];
        loop {
            if self.pump().await.is_break() {
                return;
            }

            // Read AFTER the pump. While the connection is dirty the core
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
                            // The outcome is deliberately discarded: a client
                            // never branches its sends on it — the pump just
                            // drains `poll_transmit`, which for a client can only
                            // ever carry its own connection's packets (the core
                            // emits no endpoint-level response for a client).
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
            }
        }
    }

    /// Drain the core to quiescence: events first (doing the stream work each one
    /// unblocks), transmits second, repeating until a whole pass produces
    /// neither. Returns `Break` once the connection has been lost.
    ///
    /// The repeat is not belt-and-braces. `poll_transmit` services connections
    /// lazily, so the *transmit* drain is itself a producer of events — a
    /// `StreamReadable` discovered while servicing, or the `ConnectionLost` of a
    /// connection reaped by this very pass. Draining events only once would leave
    /// those sitting until something else happened to wake the `select!`.
    async fn pump(&mut self) -> ControlFlow<()> {
        loop {
            let now = Instant::now();
            let mut progressed = false;
            let mut lost = false;

            // Events BEFORE transmits: an event may unpark a `read_to_end` whose
            // `stream_read` releases MAX_STREAM_DATA credit, and that credit only
            // reaches the peer via the drain below.
            while let Some(event) = self.core.poll_event() {
                if self.on_event(event) {
                    lost = true;
                }
                progressed = true;
            }

            // Drained to `None`, every pass. Stopping early strands bytes. Done
            // even on the losing pass so any final CONNECTION_CLOSE still flushes
            // before we tear the socket down.
            while let Some(transmit) = self.core.poll_transmit(now) {
                let _ = self
                    .socket
                    .send_to(&transmit.contents, transmit.destination)
                    .await;
                progressed = true;
            }

            if lost {
                return ControlFlow::Break(());
            }
            if !progressed {
                return ControlFlow::Continue(());
            }
        }
    }

    /// React to one core event. Returns `true` iff the connection was lost and
    /// the driver should stop.
    fn on_event(&mut self, event: CoreEvent) -> bool {
        match event {
            CoreEvent::Connected(ch) if ch == self.handle => {
                self.surface();
                false
            }
            CoreEvent::StreamOpened { conn, .. } if conn == self.handle => {
                if let Some(state) = self.core.conn_mut(conn) {
                    self.parked.on_stream_opened(state);
                }
                false
            }
            CoreEvent::StreamReadable { conn, id } if conn == self.handle => {
                if let Some(state) = self.core.conn_mut(conn) {
                    self.parked.on_readable(state, id);
                }
                false
            }
            CoreEvent::StreamWritable { conn, id } if conn == self.handle => {
                if let Some(state) = self.core.conn_mut(conn) {
                    self.parked.on_writable(state, id);
                }
                false
            }
            CoreEvent::ConnectionLost { conn } if conn == self.handle => {
                // Wake anything awaiting a stream op with `Closed` rather than
                // letting the handles hang on a silently-dropped sender.
                self.parked.fail_all();
                // If the handshake never completed, tell the waiter so it does
                // not sit out the connect timeout for a connection already gone.
                if let Some(tx) = self.connected.take() {
                    let _ = tx.send(Err(ClientError::HandshakeIncomplete));
                }
                true
            }
            // A client owns exactly one connection, so every event names
            // `self.handle`; the guards above are defensive and this arm is
            // unreachable in practice.
            _ => false,
        }
    }

    /// The handshake completed: surface the [`Connection`] to the awaiting
    /// [`Client::connect`], carrying a command sender pre-tagged with `handle`.
    /// The driver keeps owning and pumping the connection.
    fn surface(&mut self) {
        let Some(tx) = self.connected.take() else {
            return;
        };
        let Some(state) = self.core.conn_mut(self.handle) else {
            return;
        };
        let remote = state.conn().remote_address();
        let cmds = CmdSender::new(self.handle, self.cmd_tx.clone());
        let _ = tx.send(Ok(Connection::new(self.handle, remote, None, cmds)));
    }

    /// Route one handle-issued command to the connection.
    ///
    /// A command for a connection that is gone is simply dropped: that drops its
    /// reply `oneshot::Sender`, which wakes the awaiting handle with
    /// [`ConnError::Closed`](crate::conn::ConnError).
    fn on_command(&mut self, tagged: Tagged) {
        if tagged.handle != self.handle {
            return;
        }
        if let Some(state) = self.core.conn_mut(self.handle) {
            self.parked.apply_cmd(state, tagged.cmd, Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientConfigFile;

    /// A server that never sends a single byte back must not hang `connect`
    /// forever: with a short internal timeout, `connect_with_timeout` must
    /// return `ClientError::TimedOut` well within a bounded wall-clock budget.
    ///
    /// Binds a real UDP socket and drops it immediately: the port is silent
    /// (RST/ICMP-unreachable is *not* guaranteed to surface to the client's
    /// unconnected UDP socket on all platforms), which is exactly the "server
    /// never responds" case the timeout guards against — no Initial ack, no
    /// handshake progress, ever.
    #[tokio::test]
    async fn connect_times_out_when_nothing_answers() {
        let silent_addr = {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let addr = socket.local_addr().unwrap();
            drop(socket);
            addr
        };

        let psk_hex = "0000000000000000000000000000000000000000000000000000000000000009";
        let cfg: ClientConfigFile = toml::from_str(&format!(
            "client_id=\"a\"\npsk=\"{psk_hex}\"\nserver=\"{silent_addr}\"\n"
        ))
        .unwrap();

        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(12),
            connect_with_timeout(cfg, Duration::from_millis(500)),
        )
        .await
        .expect("connect_with_timeout itself must not hang past the outer test guard");

        match result {
            Err(ClientError::TimedOut) => {}
            Err(other) => panic!("expected ClientError::TimedOut, got a different error: {other}"),
            Ok(_) => panic!("expected ClientError::TimedOut, but connect unexpectedly succeeded"),
        }
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "connect should have returned promptly after its short internal timeout, took {:?}",
            start.elapsed()
        );
    }
}
