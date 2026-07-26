// SPDX-License-Identifier: 0BSD
//! End-to-end proof of the positive-admission path over real UDP sockets.
//!
//! A real [`Server`] binds a UDP socket; a real [`Client`] dials it with the
//! SAME PSK, embedding `build_dcid(psk, nonce, freshness)` in its Initial DCID
//! and re-keying the Initial packet from the PSK. The handshake must complete
//! end-to-end: `server.accept()` yields a `Connection` AND `Client::connect`
//! returns `Ok`.
//!
//! This exercises the server's positive-admission path (pre-filter PASS →
//! `Endpoint::handle` → `Connected` → `accept`) over the network, which was
//! previously only proven in-memory in `tests/spike_silence.rs`.
//!
//! Task 9 extends this with a full STREAM ECHO end-to-end over real UDP: the
//! client opens a bidirectional stream, writes + finishes, the server accepts
//! the stream, reads it to end, and echoes it back; the client reads the echo.
//! This is the project's first end-to-end data-flow proof. It also asserts the
//! `quinn_connection()` forward-compat escape hatch is reachable.

use silentquic::client::Client;
use silentquic::config::{ClientConfigFile, ServerSecrets};
use silentquic::server::Server;

#[tokio::test]
async fn authorized_client_completes_handshake_over_udp() {
    let psk_hex = "0000000000000000000000000000000000000000000000000000000000000005";

    let secrets: ServerSecrets = toml::from_str(&format!(
        "listen = \"127.0.0.1:0\"\n[[clients]]\nclient_id=\"a\"\npsk=\"{psk_hex}\"\n"
    ))
    .unwrap();

    let mut server = Server::bind(secrets).await.unwrap();
    let addr = server.local_addr();

    // The server side of the proof: accept() must yield a Connection, which the
    // driver only surfaces once the QUIC handshake for an admitted peer reaches
    // `Connected` (positive-admission path end-to-end).
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("server should accept an authorized peer");
        conn.remote_address()
    });

    let cfg: ClientConfigFile = toml::from_str(&format!(
        "client_id=\"a\"\npsk=\"{psk_hex}\"\nserver=\"{addr}\"\n"
    ))
    .unwrap();

    // The client side of the proof: connect() returns Ok only once its own
    // handshake reaches `Connected`.
    let conn = tokio::time::timeout(std::time::Duration::from_secs(10), Client::connect(cfg))
        .await
        .expect("client connect should not time out")
        .expect("client should complete the handshake");

    assert_eq!(conn.remote_address(), addr, "client is connected to the server");

    let server_remote = tokio::time::timeout(std::time::Duration::from_secs(10), server_task)
        .await
        .expect("server accept should not time out")
        .expect("server task should not panic");

    // Sanity: the server saw the client's real source address.
    assert_eq!(
        server_remote.ip(),
        std::net::Ipv4Addr::LOCALHOST,
        "server accepted a loopback peer"
    );
}

/// The end-to-end data-flow proof: a real stream echo over real UDP through the
/// real `Server` + `Client`. Client opens a bidi stream, writes `b"ping"`, and
/// finishes; the server accepts the stream, reads it to end, and echoes it back;
/// the client reads the echo and it matches. This exercises the Task 9
/// connection-ownership restructure (the driver keeps pumping accepted
/// connections so post-handshake stream data flows).
#[tokio::test]
async fn stream_echo_roundtrips_over_udp() {
    let psk_hex = "0000000000000000000000000000000000000000000000000000000000000006";

    let secrets: ServerSecrets = toml::from_str(&format!(
        "listen = \"127.0.0.1:0\"\n[[clients]]\nclient_id=\"a\"\npsk=\"{psk_hex}\"\n"
    ))
    .unwrap();

    let mut server = Server::bind(secrets).await.unwrap();
    let addr = server.local_addr();

    // Server: accept the connection, then accept a stream, read it, echo it back.
    let server_task = tokio::spawn(async move {
        let conn = server
            .accept()
            .await
            .expect("server should accept an authorized peer");
        let mut stream = conn
            .accept_stream()
            .await
            .expect("server should accept a bidirectional stream");
        let got = stream
            .read_to_end()
            .await
            .expect("server should read the stream to end");
        // Echo back what we received.
        stream
            .write_all(&got)
            .await
            .expect("server should write the echo");
        stream.finish().await.expect("server should finish the echo");
        got
    });

    let cfg: ClientConfigFile = toml::from_str(&format!(
        "client_id=\"a\"\npsk=\"{psk_hex}\"\nserver=\"{addr}\"\n"
    ))
    .unwrap();

    let conn = tokio::time::timeout(std::time::Duration::from_secs(10), Client::connect(cfg))
        .await
        .expect("client connect should not time out")
        .expect("client should complete the handshake");

    // Forward-compat escape hatch: reachable after connect (compile + runtime
    // guarantee that h3 can be layered later without touching the cloaking layer).
    let _quinn = conn.quinn_connection();

    // Client: open a stream, write "ping", finish, then read the echo back.
    let mut stream = conn.open_stream().await.expect("client should open a stream");
    stream
        .write_all(b"ping")
        .await
        .expect("client should write ping");
    stream.finish().await.expect("client should finish its send");

    let echo = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read_to_end())
        .await
        .expect("client read should not time out")
        .expect("client should read the echo");
    assert_eq!(&echo, b"ping", "client must receive the echoed bytes");

    let server_got = tokio::time::timeout(std::time::Duration::from_secs(10), server_task)
        .await
        .expect("server task should not time out")
        .expect("server task should not panic");
    assert_eq!(&server_got, b"ping", "server must have received the ping");
}

#[tokio::test]
async fn split_stream_reads_incrementally_before_fin() {
    let psk_hex = "0000000000000000000000000000000000000000000000000000000000000009";
    let secrets: ServerSecrets = toml::from_str(&format!(
        "listen = \"127.0.0.1:0\"\n[[clients]]\nclient_id=\"a\"\npsk=\"{psk_hex}\"\n"
    ))
    .unwrap();
    let mut server = Server::bind(secrets).await.unwrap();
    let addr = server.local_addr();

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("server accepts");
        let stream = conn.accept_stream().await.expect("server accepts stream");
        let (mut recv, mut send) = stream.split();
        let first = recv.read(3).await.expect("incremental read");
        assert_eq!(first, b"abc");
        send.write_all(b"seen").await.expect("concurrent response");
        send.finish().await.expect("finish response");
        let second = recv.read(3).await.expect("read after response");
        assert_eq!(second, b"def");
        assert!(recv.read(3).await.expect("read FIN").is_empty());
    });

    let cfg: ClientConfigFile = toml::from_str(&format!(
        "client_id=\"a\"\npsk=\"{psk_hex}\"\nserver=\"{addr}\"\n"
    ))
    .unwrap();
    let conn = Client::connect(cfg).await.unwrap();
    let stream = conn.open_stream().await.unwrap();
    let (mut recv, mut send) = stream.split();
    send.write_all(b"abc").await.unwrap();
    let response = recv.read(16).await.unwrap();
    assert_eq!(response, b"seen");
    send.write_all(b"def").await.unwrap();
    send.finish().await.unwrap();
    assert!(recv.read(16).await.unwrap().is_empty());
    server_task.await.unwrap();
}

/// The client can pin its local source address/port.
///
/// Default is an ephemeral port on any interface (what ordinary QUIC clients
/// do); this proves the override actually takes effect, by asserting the SERVER
/// observes the client's source port as the one we pinned. Motivated by egress
/// firewalls that only permit UDP from an allowlisted source port, and by
/// multi-homed hosts that must leave via a specific interface.
#[tokio::test]
async fn client_can_pin_its_local_source_port() {
    let psk_hex = "0000000000000000000000000000000000000000000000000000000000000007";

    let secrets: ServerSecrets = toml::from_str(&format!(
        "listen = \"127.0.0.1:0\"\n[[clients]]\nclient_id=\"a\"\npsk=\"{psk_hex}\"\n"
    ))
    .unwrap();
    let mut server = Server::bind(secrets).await.unwrap();
    let addr = server.local_addr();

    // Grab a free UDP port, then release it for the client to claim.
    let pinned = {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("server should accept");
        conn.remote_address()
    });

    let cfg: ClientConfigFile = toml::from_str(&format!(
        "client_id=\"a\"\npsk=\"{psk_hex}\"\nserver=\"{addr}\"\nbind=\"127.0.0.1:{pinned}\"\n"
    ))
    .unwrap();
    let conn = tokio::time::timeout(std::time::Duration::from_secs(10), Client::connect(cfg))
        .await
        .expect("connect should not time out")
        .expect("handshake should complete from the pinned port");

    let seen = tokio::time::timeout(std::time::Duration::from_secs(10), server_task)
        .await
        .expect("server should not time out")
        .expect("server task should not panic");

    assert_eq!(
        seen.port(),
        pinned,
        "server must observe the client's pinned source port"
    );
    conn.close().await;
}

/// A bind address whose IP version differs from the server's is rejected up
/// front with a clear message, rather than failing opaquely in the OS.
#[tokio::test]
async fn mismatched_bind_family_is_rejected() {
    let psk_hex = "0000000000000000000000000000000000000000000000000000000000000008";
    let cfg: ClientConfigFile = toml::from_str(&format!(
        "client_id=\"a\"\npsk=\"{psk_hex}\"\nserver=\"127.0.0.1:4433\"\nbind=\"[::]:0\"\n"
    ))
    .unwrap();

    let err = Client::connect(cfg).await.expect_err("must reject v6 bind for a v4 server");
    let msg = err.to_string();
    assert!(
        msg.contains("different IP versions"),
        "error should name the family mismatch, got: {msg}"
    );
}
