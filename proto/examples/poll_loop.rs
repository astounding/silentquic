// SPDX-License-Identifier: 0BSD
//! Reference: driving quietquic from a hand-rolled, **zero-timeout** event loop.
//!
//! This is the classic Unix reactor shape — a single thread that polls its
//! sockets without ever blocking, services whatever is ready, and then gets on
//! with its own work. No async runtime, no threads, no `.await`, nothing that
//! parks. Contrast `quietquic`, the tokio wrapper, which is the right choice if
//! your application is already async.
//!
//! To keep the example self-contained it drives **both** ends — a cloaked server
//! and a client — from the *same* loop, over two real UDP sockets on loopback.
//! That is unusual for a real program but it makes the example a genuine proof:
//! bytes actually flow, so if the loop shape were wrong the example would hang
//! rather than quietly appear to work.
//!
//! # The four obligations, in order
//!
//! Every pass must do these, **in this order**:
//!
//! 1. **Feed inbound datagrams** — `handle_datagram`.
//! 2. **Service the timer** if its deadline has passed — `next_timeout` /
//!    `handle_timeout`. QUIC's loss detection lives in userspace; the kernel
//!    will not do it for you as it does for TCP.
//! 3. **Drain events and do your stream work** — `poll_event`, then
//!    `stream_read` / `stream_write` / …
//! 4. **Drain transmits LAST** — `poll_transmit` until it returns `None`.
//!
//! Step 4 must come after step 3. `poll_transmit` is what services connections,
//! so draining it *before* your stream work leaves the flow-control credit a
//! `stream_read` just released unsent: the peer stays blocked, sends nothing,
//! nothing arrives to wake your loop, and the connection stalls until the idle
//! timeout. That is the classic sans-IO bug, and it is silent.
//!
//! The core defends against it rather than merely documenting it — any stream
//! operation marks its connection dirty, and while anything is dirty
//! `next_timeout()` returns an already-elapsed deadline, so a loop that sleeps on
//! it wakes immediately instead of sleeping through the stall.
//!
//! # Where `select()` goes
//!
//! One socket per endpoint here, so a non-blocking `recv_from` returning
//! `WouldBlock` *is* the zero-timeout poll. With several descriptors you would
//! wrap the same thing in `select()`/`poll()`/`kqueue` with a zero timeout, then
//! read whichever are ready — the structure below is unchanged.
//!
//! Run with: `cargo run -p quietquic-proto --example poll_loop`

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

use quietquic_proto::config::{ClientConfigFile, ServerSecrets};
use quietquic_proto::endpoint::Endpoint;
use quietquic_proto::freshness::now_minutes;
use quietquic_proto::outcome::{ConnectionHandle, Event, ReadOutcome};
use quinn_proto::StreamId;

/// A 64-hex-character pre-shared key, shared by both ends.
const PSK_HEX: &str = "00000000000000000000000000000000000000000000000000000000000000bb";
const PAYLOAD: &[u8] = b"hello from a hand-rolled event loop";

/// Bound the run so the example terminates in CI. A real loop runs forever.
const MAX_PASSES: usize = 20_000;

/// One end of the conversation: an endpoint plus the socket the caller owns.
struct Peer {
    name: &'static str,
    endpoint: Endpoint,
    socket: UdpSocket,
    buf: Vec<u8>,
}

impl Peer {
    /// Steps 1 and 2 of the pass: drain the socket, then service the timer.
    ///
    /// Never blocks: `WouldBlock` simply means "nothing more right now".
    fn ingest(&mut self, now: Instant) {
        loop {
            match self.socket.recv_from(&mut self.buf) {
                Ok((n, from)) => {
                    // The cloaking pre-filter runs inside here. A datagram that
                    // fails it queues nothing, so an unauthorized peer gets no
                    // reply — we do not have to (and must not) branch on the
                    // returned outcome to stay silent.
                    let _ = self.endpoint.handle_datagram(now, from, &self.buf[..n]);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => {
                    eprintln!("{}: recv error: {e}", self.name);
                    break;
                }
            }
        }

        if self.endpoint.next_timeout().is_some_and(|t| t <= now) {
            self.endpoint.handle_timeout(now);
        }
    }

    /// Step 4 of the pass: flush everything the endpoint wants to send.
    ///
    /// Called only after this pass's stream work, and drained all the way to
    /// `None`.
    fn flush(&mut self, now: Instant) {
        while let Some(t) = self.endpoint.poll_transmit(now) {
            if let Err(e) = self.socket.send_to(&t.contents, t.destination) {
                eprintln!("{}: send error: {e}", self.name);
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- set up both ends -------------------------------------------------

    let server_socket = UdpSocket::bind("127.0.0.1:0")?;
    server_socket.set_nonblocking(true)?; // the loop must never block
    let server_addr: SocketAddr = server_socket.local_addr()?;

    let secrets: ServerSecrets = toml::from_str(&format!(
        "listen = \"{server_addr}\"\n[[clients]]\nclient_id=\"demo\"\npsk=\"{PSK_HEX}\"\n"
    ))?;
    let mut server = Peer {
        name: "server",
        endpoint: Endpoint::new_server(secrets)?,
        socket: server_socket,
        buf: vec![0u8; 65_535],
    };

    let client_socket = UdpSocket::bind("127.0.0.1:0")?;
    client_socket.set_nonblocking(true)?;

    let cfg: ClientConfigFile = toml::from_str(&format!(
        "client_id=\"demo\"\npsk=\"{PSK_HEX}\"\nserver=\"{server_addr}\"\n"
    ))?;
    // The caller owns the clock: the core reads neither the monotonic nor the
    // wall clock, so both `now` and the coarse freshness minute are passed in.
    let (client_endpoint, client_conn) = Endpoint::new_client(Instant::now(), now_minutes(), cfg)?;
    let mut client = Peer {
        name: "client",
        endpoint: client_endpoint,
        socket: client_socket,
        buf: vec![0u8; 65_535],
    };

    // --- application state the loop drives --------------------------------

    let mut client_stream: Option<StreamId> = None;
    let mut server_stream: Option<(ConnectionHandle, StreamId)> = None;
    let mut received = Vec::new();
    let mut done = false;

    // --- the loop ---------------------------------------------------------

    for pass in 0..MAX_PASSES {
        let now = Instant::now();

        // Steps 1 + 2, for each endpoint.
        client.ingest(now);
        server.ingest(now);

        // Step 3: drain events and do the stream work they unblock.
        while let Some(ev) = client.endpoint.poll_event() {
            if let Event::Connected(ch) = ev {
                // `new_client` already told us the handle; `Connected` is when it
                // becomes usable. They name the same connection.
                assert_eq!(ch, client_conn, "Connected names the dialled connection");
                // Handshake done: open a stream, send, and half-close.
                let state = client.endpoint.conn_mut(ch).expect("live connection");
                let id = state.open_bi()?;
                state.stream_write(id, PAYLOAD)?;
                state.stream_finish(id)?;
                client_stream = Some(id);
            }
        }

        while let Some(ev) = server.endpoint.poll_event() {
            match ev {
                Event::StreamOpened { conn, id, .. } => server_stream = Some((conn, id)),
                // A handle is invalid the moment this fires — quinn-proto hands
                // freed handles straight back out, so drop yours here.
                Event::ConnectionLost { conn, .. }
                    if server_stream.map(|(c, _)| c) == Some(conn) =>
                {
                    server_stream = None;
                }
                _ => {}
            }
        }

        // Read whatever has arrived. `Blocked` is not an error — it means "not
        // yet"; we simply try again next pass.
        if let Some((conn, id)) = server_stream {
            if let Some(state) = server.endpoint.conn_mut(conn) {
                let mut chunk = [0u8; 4096];
                loop {
                    match state.stream_read(id, &mut chunk)? {
                        ReadOutcome::Read(n) => received.extend_from_slice(&chunk[..n]),
                        ReadOutcome::Blocked => break,
                        ReadOutcome::Finished => {
                            done = true;
                            break;
                        }
                    }
                }
            }
        }

        // Step 4: flush LAST, after this pass's stream work, so the credit that
        // `stream_read` just released actually reaches the peer.
        client.flush(now);
        server.flush(now);

        if done {
            println!(
                "server received {} bytes after {pass} passes: {:?}",
                received.len(),
                String::from_utf8_lossy(&received)
            );
            assert_eq!(received, PAYLOAD, "payload must round-trip intact");
            assert!(
                client_stream.is_some(),
                "client should have opened a stream"
            );
            println!("poll_loop: OK — no runtime, no threads, nothing blocked");
            return Ok(());
        }

        // ...and here is where a real program does its OTHER work. Nothing above
        // blocked, so the thread is yours. If you have genuinely nothing to do,
        // sleep until `endpoint.next_timeout()` (read only now, after the flush)
        // rather than spinning.
    }

    Err("poll_loop: did not complete within MAX_PASSES".into())
}
