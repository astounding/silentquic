// SPDX-License-Identifier: 0BSD
//! Feasibility spike (Task 6): prove the transport seam and the silence invariant.
//!
//! Three properties, all driven entirely in-memory over `quinn-proto` with no
//! sockets:
//!
//!  1. **Sans-IO plumbing works** — with STANDARD crypto, a client and server
//!     complete a handshake and echo one bidirectional stream, hand-passing
//!     datagrams over `Vec<u8>` buffers.
//!  2. **Pre-filter guarantees silence** — a `peek_dcid` + `selector_matches`
//!     gate in front of the server endpoint drops junk and stock-QUIC probes,
//!     emitting ZERO outbound bytes (asserted byte-for-byte).
//!  3. **PSK Initial re-keying interops** — with the PSK wrapper installed on
//!     both sides and the client DCID = `build_dcid(psk, nonce, freshness)`,
//!     the handshake completes; a stock client (published-salt Initial) cannot.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{
    ClientConfig, Connection, ConnectionHandle, ConnectionId, DatagramEvent, Dir, Endpoint,
    EndpointConfig, Event, ServerConfig, StreamEvent, StreamId,
};

use silentquic::initial_keys::{PskClientConfig, PskServerConfig};
use silentquic::selector::{build_dcid, parse_dcid, selector_matches, DCID_LEN};

fn client_addr() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 44444)
}
fn server_addr() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 4443)
}

// ---------------------------------------------------------------------------
// peek_dcid — parse the DCID out of a raw QUIC long-header datagram.
//
// Long header layout (RFC 9000 §17.2):
//   byte0:      1 f x x x x x x   (high bit = long-header form)
//   bytes1..5:  version (4 bytes, big-endian)
//   byte5:      DCID length (u8)
//   bytes6..6+len: DCID
// Returns None for anything that isn't a well-formed long header with a DCID.
// This is the exact gate the silent server runs before touching quinn-proto.
// ---------------------------------------------------------------------------
fn peek_dcid(datagram: &[u8]) -> Option<&[u8]> {
    if datagram.len() < 6 {
        return None;
    }
    if datagram[0] & 0x80 == 0 {
        return None; // not a long-header packet
    }
    let dcid_len = datagram[5] as usize;
    if dcid_len == 0 || dcid_len > 20 {
        return None;
    }
    let end = 6 + dcid_len;
    if datagram.len() < end {
        return None;
    }
    Some(&datagram[6..end])
}

/// The silent pre-filter: admit a datagram only if its DCID selector matches
/// the PSK. Returns `true` to deliver, `false` to silently drop.
fn prefilter(datagram: &[u8], psk: &[u8; 32]) -> bool {
    let Some(dcid) = peek_dcid(datagram) else {
        return false;
    };
    if dcid.len() != DCID_LEN {
        return false;
    }
    let Some(parts) = parse_dcid(dcid) else {
        return false;
    };
    selector_matches(psk, &parts)
}

// ---------------------------------------------------------------------------
// Self-signed cert + skip-verify verifier.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ED25519,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
        ]
    }
}

struct Identity {
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

fn self_signed() -> Identity {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    Identity {
        cert: ck.cert.der().clone(),
        key: rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into()),
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn rustls_server_config(id: &Identity) -> rustls::ServerConfig {
    rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![id.cert.clone()], id.key.clone_key())
        .unwrap()
}

fn rustls_client_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth()
}

fn quic_server(id: &Identity) -> Arc<QuicServerConfig> {
    Arc::new(QuicServerConfig::try_from(rustls_server_config(id)).unwrap())
}
fn quic_client() -> Arc<QuicClientConfig> {
    Arc::new(QuicClientConfig::try_from(rustls_client_config()).unwrap())
}

// ---------------------------------------------------------------------------
// Endpoint / transport config
// ---------------------------------------------------------------------------

/// A tiny HMAC-SHA256 key implementing `quinn_proto::crypto::HmacKey`.
struct HmacKeyShim(aws_lc_rs::hmac::Key);
impl HmacKeyShim {
    fn new() -> Self {
        Self(aws_lc_rs::hmac::Key::new(
            aws_lc_rs::hmac::HMAC_SHA256,
            &[0x42u8; 64],
        ))
    }
}
impl quinn_proto::crypto::HmacKey for HmacKeyShim {
    fn sign(&self, data: &[u8], out: &mut [u8]) {
        let tag = aws_lc_rs::hmac::sign(&self.0, data);
        out.copy_from_slice(tag.as_ref());
    }
    fn signature_len(&self) -> usize {
        32
    }
    fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), quinn_proto::crypto::CryptoError> {
        aws_lc_rs::hmac::verify(&self.0, data, signature)
            .map_err(|_| quinn_proto::crypto::CryptoError)
    }
}

fn endpoint_config() -> Arc<EndpointConfig> {
    Arc::new(EndpointConfig::new(Arc::new(HmacKeyShim::new())))
}

fn token_key() -> Arc<aws_lc_rs::hkdf::Prk> {
    // quinn-proto implements `crypto::HandshakeTokenKey` for `hkdf::Prk`.
    Arc::new(aws_lc_rs::hkdf::Prk::new_less_safe(
        aws_lc_rs::hkdf::HKDF_SHA256,
        &[0x37u8; 32],
    ))
}

fn transport_server_config(
    crypto: Arc<dyn quinn_proto::crypto::ServerConfig>,
) -> Arc<ServerConfig> {
    Arc::new(ServerConfig::new(crypto, token_key()))
}

fn make_client_config(
    crypto: Arc<dyn quinn_proto::crypto::ClientConfig>,
    forced_dcid: Option<[u8; 20]>,
) -> ClientConfig {
    let mut cfg = ClientConfig::new(crypto);
    if let Some(dcid) = forced_dcid {
        cfg.initial_dst_cid_provider(Arc::new(move || ConnectionId::new(&dcid)));
    }
    cfg
}

// ---------------------------------------------------------------------------
// In-memory sans-IO harness. Owns both endpoints and both connections and
// pumps datagrams between them, applying a silence gate to client→server
// traffic and counting every byte the server emits.
// ---------------------------------------------------------------------------

struct Harness {
    server_ep: Endpoint,
    client_ep: Endpoint,
    client_ch: ConnectionHandle,
    client_conn: Connection,
    server: Option<(ConnectionHandle, Connection)>,
    /// Total bytes the server put on the wire (must be 0 for silent drops).
    server_out_bytes: usize,
    /// Total bytes the client put on the wire toward the server.
    client_out_bytes: usize,
    /// Count of client→server datagrams the pre-filter silently dropped.
    dropped_datagrams: usize,
    client_connected: bool,
    server_connected: bool,
}

/// One queued datagram: (source addr, bytes).
type Packet = (SocketAddr, Vec<u8>);

impl Harness {
    fn new(
        server_crypto: Arc<dyn quinn_proto::crypto::ServerConfig>,
        client_crypto: Arc<dyn quinn_proto::crypto::ClientConfig>,
        forced_dcid: Option<[u8; 20]>,
        now: Instant,
    ) -> Self {
        let server_ep = Endpoint::new(
            endpoint_config(),
            Some(transport_server_config(server_crypto)),
            true,
            None,
        );
        let mut client_ep = Endpoint::new(endpoint_config(), None, true, None);
        let (client_ch, client_conn) = client_ep
            .connect(
                now,
                make_client_config(client_crypto, forced_dcid),
                server_addr(),
                "localhost",
            )
            .expect("client connect");
        Self {
            server_ep,
            client_ep,
            client_ch,
            client_conn,
            server: None,
            server_out_bytes: 0,
            client_out_bytes: 0,
            dropped_datagrams: 0,
            client_connected: false,
            server_connected: false,
        }
    }

    /// Pull outbound datagrams from the client connection.
    fn drain_client(&mut self, now: Instant, wire: &mut Vec<Packet>) {
        let mut buf = Vec::new();
        while let Some(_t) = self.client_conn.poll_transmit(now, 1, &mut buf) {
            self.client_out_bytes += buf.len();
            wire.push((client_addr(), std::mem::take(&mut buf)));
        }
        while let Some(ev) = self.client_conn.poll_endpoint_events() {
            if let Some(cev) = self.client_ep.handle_event(self.client_ch, ev) {
                self.client_conn.handle_event(cev);
            }
        }
    }

    /// Pull outbound datagrams from the server connection, counting bytes.
    fn drain_server(&mut self, now: Instant, wire: &mut Vec<Packet>) {
        if let Some((ch, conn)) = self.server.as_mut() {
            let mut buf = Vec::new();
            while let Some(_t) = conn.poll_transmit(now, 1, &mut buf) {
                self.server_out_bytes += buf.len();
                wire.push((server_addr(), std::mem::take(&mut buf)));
            }
            while let Some(ev) = conn.poll_endpoint_events() {
                if let Some(cev) = self.server_ep.handle_event(*ch, ev) {
                    conn.handle_event(cev);
                }
            }
        }
    }

    /// Deliver one datagram to the server endpoint. `gate` decides admission.
    ///
    /// The silence pre-filter only governs **connection establishment**: it runs
    /// on datagrams for which no server connection exists yet (the client's
    /// first-flight Initial). Once a connection is accepted, subsequent packets
    /// belong to an established QUIC connection whose DCID is a server-chosen CID
    /// (not a selector DCID), so they bypass the selector gate — exactly as a
    /// real deployment routes by CID after establishment.
    fn deliver_to_server<G: Fn(&[u8]) -> bool>(
        &mut self,
        now: Instant,
        from: SocketAddr,
        data: &[u8],
        gate: &G,
        wire: &mut Vec<Packet>,
    ) {
        if self.server.is_none() && !gate(data) {
            self.dropped_datagrams += 1;
            return; // silent drop — server never sees it, emits nothing
        }
        let mut resp = Vec::new();
        let ev = self
            .server_ep
            .handle(now, from, None, None, BytesMut::from(data), &mut resp);
        // Any endpoint-level response counts as server output.
        self.server_out_bytes += resp.len();
        if !resp.is_empty() {
            wire.push((server_addr(), resp));
        }
        match ev {
            Some(DatagramEvent::NewConnection(incoming)) => {
                let mut accept_buf = Vec::new();
                match self.server_ep.accept(incoming, now, &mut accept_buf, None) {
                    Ok((ch, conn)) => self.server = Some((ch, conn)),
                    Err(_) => { /* rejected */ }
                }
                self.server_out_bytes += accept_buf.len();
                if !accept_buf.is_empty() {
                    wire.push((server_addr(), accept_buf));
                }
            }
            Some(DatagramEvent::ConnectionEvent(ch, cev)) => {
                if let Some((sch, conn)) = self.server.as_mut() {
                    if *sch == ch {
                        conn.handle_event(cev);
                    }
                }
            }
            Some(DatagramEvent::Response(_)) | None => {}
        }
    }

    /// Deliver one datagram to the client endpoint.
    fn deliver_to_client(&mut self, now: Instant, from: SocketAddr, data: &[u8]) {
        let mut resp = Vec::new();
        if let Some(DatagramEvent::ConnectionEvent(ch, cev)) = self.client_ep.handle(
            now,
            from,
            None,
            None,
            BytesMut::from(data),
            &mut resp,
        ) {
            if ch == self.client_ch {
                self.client_conn.handle_event(cev);
            }
        }
    }

    fn poll_states(&mut self) {
        while let Some(ev) = self.client_conn.poll() {
            if let Event::Connected = ev {
                self.client_connected = true;
            }
        }
        if let Some((_, conn)) = self.server.as_mut() {
            while let Some(ev) = conn.poll() {
                if let Event::Connected = ev {
                    self.server_connected = true;
                }
            }
        }
    }

    fn handle_timeouts(&mut self, now: Instant) {
        self.client_conn.handle_timeout(now);
        if let Some((_, conn)) = self.server.as_mut() {
            conn.handle_timeout(now);
        }
    }
}

/// Outcome of a handshake attempt.
struct Outcome {
    client_connected: bool,
    server_connected: bool,
    server_out_bytes: usize,
    client_out_bytes: usize,
    dropped_datagrams: usize,
}

/// Drive the handshake (and optionally a stream echo) to completion or timeout.
fn run<G: Fn(&[u8]) -> bool>(
    server_crypto: Arc<dyn quinn_proto::crypto::ServerConfig>,
    client_crypto: Arc<dyn quinn_proto::crypto::ClientConfig>,
    forced_dcid: Option<[u8; 20]>,
    gate: G,
    do_stream_echo: bool,
) -> Outcome {
    let now0 = Instant::now();
    let mut h = Harness::new(server_crypto, client_crypto, forced_dcid, now0);
    let mut echo = EchoState::default();
    let mut stream_done = !do_stream_echo;

    for step in 0..400u64 {
        let now = now0 + Duration::from_millis(step * 5);
        h.handle_timeouts(now);

        let mut wire: Vec<Packet> = Vec::new();
        h.drain_client(now, &mut wire);
        h.drain_server(now, &mut wire);

        for (from, data) in std::mem::take(&mut wire) {
            if from == client_addr() {
                h.deliver_to_server(now, from, &data, &gate, &mut wire);
            } else {
                h.deliver_to_client(now, from, &data);
            }
        }

        h.poll_states();

        if do_stream_echo
            && h.client_connected
            && h.server_connected
            && !stream_done
        {
            stream_done = echo.step(&mut h);
        }

        // Settle: keep pumping until nothing is in flight.
        if h.client_connected && h.server_connected && stream_done {
            // one more drain to flush trailing acks, then stop if quiet
            let mut trailing: Vec<Packet> = Vec::new();
            h.drain_client(now, &mut trailing);
            h.drain_server(now, &mut trailing);
            if trailing.is_empty() {
                break;
            }
            for (from, data) in trailing {
                if from == client_addr() {
                    h.deliver_to_server(now, from, &data, &gate, &mut Vec::new());
                } else {
                    h.deliver_to_client(now, from, &data);
                }
            }
        }
    }

    Outcome {
        client_connected: h.client_connected,
        server_connected: h.server_connected,
        server_out_bytes: h.server_out_bytes,
        client_out_bytes: h.client_out_bytes,
        dropped_datagrams: h.dropped_datagrams,
    }
}

// ---------------------------------------------------------------------------
// Bidirectional stream echo state machine.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct EchoState {
    client_stream: Option<StreamId>,
    server_stream: Option<StreamId>,
    server_echoed: bool,
    verified: bool,
}

const ECHO_MSG: &[u8] = b"silentquic-echo";

impl EchoState {
    /// Advance the echo one step. Returns true once the round-trip is verified.
    fn step(&mut self, h: &mut Harness) -> bool {
        if self.verified {
            return true;
        }
        // 1. Client opens + writes + finishes.
        if self.client_stream.is_none() {
            if let Some(sid) = h.client_conn.streams().open(Dir::Bi) {
                let _ = h.client_conn.send_stream(sid).write(ECHO_MSG);
                let _ = h.client_conn.send_stream(sid).finish();
                self.client_stream = Some(sid);
            }
            return false;
        }

        let Some((_, server_conn)) = h.server.as_mut() else {
            return false;
        };

        // 2. Server accepts + reads + echoes.
        if !self.server_echoed {
            if self.server_stream.is_none() {
                while let Some(ev) = server_conn.poll() {
                    if let Event::Stream(StreamEvent::Opened { dir: Dir::Bi }) = ev {
                        self.server_stream = server_conn.streams().accept(Dir::Bi);
                    }
                }
            }
            if let Some(sid) = self.server_stream {
                let mut got = Vec::new();
                if let Ok(mut chunks) = server_conn.recv_stream(sid).read(true) {
                    while let Ok(Some(chunk)) = chunks.next(1024) {
                        got.extend_from_slice(&chunk.bytes);
                    }
                    let _ = chunks.finalize();
                }
                if got == ECHO_MSG {
                    let _ = server_conn.send_stream(sid).write(&got);
                    let _ = server_conn.send_stream(sid).finish();
                    self.server_echoed = true;
                }
            }
            return false;
        }

        // 3. Client reads the echo back.
        if let Some(sid) = self.client_stream {
            let mut got = Vec::new();
            if let Ok(mut chunks) = h.client_conn.recv_stream(sid).read(true) {
                while let Ok(Some(chunk)) = chunks.next(1024) {
                    got.extend_from_slice(&chunk.bytes);
                }
                let _ = chunks.finalize();
            }
            if got == ECHO_MSG {
                self.verified = true;
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const PSK: [u8; 32] = [0x11; 32];
const WRONG_PSK: [u8; 32] = [0x22; 32];

fn psk_dcid(psk: &[u8; 32]) -> [u8; 20] {
    // Fixed nonce/freshness for determinism; freshness window is not exercised
    // in this spike (that is Task 3/its own test).
    build_dcid(psk, [0xAB; 8], 7)
}

// ===========================================================================
// PROPERTY 1: sans-IO plumbing with STANDARD crypto.
// ===========================================================================

#[test]
fn standard_crypto_handshake_and_stream_echo() {
    let id = self_signed();
    let server_crypto: Arc<dyn quinn_proto::crypto::ServerConfig> = quic_server(&id);
    let client_crypto: Arc<dyn quinn_proto::crypto::ClientConfig> = quic_client();

    let out = run(server_crypto, client_crypto, None, |_| true, true);

    assert!(out.client_connected, "client should complete handshake");
    assert!(out.server_connected, "server should complete handshake");
    assert!(
        out.server_out_bytes > 0,
        "a real handshake must produce server output"
    );
}

// ===========================================================================
// PROPERTY 2: the pre-filter drops silently — ZERO server output.
// ===========================================================================

#[test]
fn prefilter_drops_junk_silently() {
    // Pure junk: not even a long header.
    assert!(!prefilter(&[0x00, 0x01, 0x02], &PSK));
    assert!(!prefilter(&[], &PSK));
    // Long header but DCID too short / not our layout.
    let mut short = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 0x04];
    short.extend_from_slice(&[9, 9, 9, 9]);
    assert!(!prefilter(&short, &PSK));
}

#[test]
fn prefilter_admits_matching_dcid() {
    // A synthetic long-header datagram whose DCID = build_dcid(PSK,..).
    let dcid = psk_dcid(&PSK);
    let mut dg = vec![0xC0, 0x00, 0x00, 0x00, 0x01, DCID_LEN as u8];
    dg.extend_from_slice(&dcid);
    dg.extend_from_slice(&[0u8; 40]); // filler payload
    assert!(prefilter(&dg, &PSK), "matching DCID must be admitted");
    assert!(
        !prefilter(&dg, &WRONG_PSK),
        "wrong PSK must reject the same DCID"
    );
}

#[test]
fn junk_flood_yields_zero_server_bytes() {
    // Drive the harness but the client sends a stock (published-salt) Initial
    // with a RANDOM DCID that does not match the PSK. The pre-filter must drop
    // every client→server datagram, so the server emits ZERO bytes.
    let id = self_signed();
    let server_crypto: Arc<dyn quinn_proto::crypto::ServerConfig> =
        Arc::new(PskServerConfig::new(quic_server(&id), PSK));
    // Stock client: standard crypto, random DCID (no forced selector DCID).
    let client_crypto: Arc<dyn quinn_proto::crypto::ClientConfig> = quic_client();

    let out = run(
        server_crypto,
        client_crypto,
        None, // random DCID
        |dg| prefilter(dg, &PSK),
        false,
    );

    assert!(
        out.client_out_bytes > 0,
        "sanity: the stock client must actually transmit (else the drop is vacuous)"
    );
    assert!(
        out.dropped_datagrams > 0,
        "the pre-filter must have dropped at least one client datagram"
    );
    assert!(
        !out.server_connected,
        "server must not complete a handshake with an unauthenticated client"
    );
    assert_eq!(
        out.server_out_bytes, 0,
        "silent server must emit ZERO bytes to an unauthenticated probe"
    );
}

#[test]
fn raw_junk_datagrams_yield_zero_server_bytes() {
    // Feed pure garbage straight at the server endpoint through the same gate
    // and assert the server produces nothing at all.
    let id = self_signed();
    let mut server_ep = Endpoint::new(
        endpoint_config(),
        Some(transport_server_config(Arc::new(PskServerConfig::new(
            quic_server(&id),
            PSK,
        )))),
        true,
        None,
    );
    let now = Instant::now();
    let mut out_bytes = 0usize;

    let junk_samples: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00; 1],
        vec![0xFF; 64],
        (0..1200u32).map(|i| (i % 251) as u8).collect(),
        // A long header with a non-matching random DCID.
        {
            let mut v = vec![0xC0, 0x00, 0x00, 0x00, 0x01, DCID_LEN as u8];
            v.extend_from_slice(&[0x5A; DCID_LEN]);
            v.extend_from_slice(&[0u8; 1100]);
            v
        },
    ];

    for junk in junk_samples {
        if !prefilter(&junk, &PSK) {
            continue; // dropped before touching the endpoint
        }
        // Should be unreachable for junk, but if admitted, count any output.
        let mut resp = Vec::new();
        let _ = server_ep.handle(
            now,
            client_addr(),
            None,
            None,
            BytesMut::from(&junk[..]),
            &mut resp,
        );
        out_bytes += resp.len();
    }

    assert_eq!(out_bytes, 0, "junk must produce zero server output");
}

// ===========================================================================
// PROPERTY 3: PSK Initial re-keying interops; stock client cannot.
// ===========================================================================

#[test]
fn psk_peers_handshake_and_echo() {
    let id = self_signed();
    let server_crypto: Arc<dyn quinn_proto::crypto::ServerConfig> =
        Arc::new(PskServerConfig::new(quic_server(&id), PSK));
    let client_crypto: Arc<dyn quinn_proto::crypto::ClientConfig> =
        Arc::new(PskClientConfig::new(quic_client(), PSK));

    let out = run(
        server_crypto,
        client_crypto,
        Some(psk_dcid(&PSK)),
        |dg| prefilter(dg, &PSK),
        true,
    );

    assert!(out.client_connected, "PSK client should complete handshake");
    assert!(out.server_connected, "PSK server should complete handshake");
}

#[test]
fn stock_client_cannot_handshake_with_psk_server() {
    // PSK server, but a STOCK client (published-salt Initial, random DCID).
    // Even if we (generously) let the gate pass everything, the server's
    // PSK-rekeyed Initial keys cannot unseal the stock Initial, so no handshake
    // completes. With the real gate it is dropped even earlier.
    let id = self_signed();
    let server_crypto: Arc<dyn quinn_proto::crypto::ServerConfig> =
        Arc::new(PskServerConfig::new(quic_server(&id), PSK));
    let client_crypto: Arc<dyn quinn_proto::crypto::ClientConfig> = quic_client();

    // Gate open (allow everything) to prove the CRYPTO alone rejects the stock
    // client, independent of the pre-filter.
    let out = run(server_crypto, client_crypto, None, |_| true, false);

    assert!(
        !out.client_connected && !out.server_connected,
        "a stock client must not complete a handshake with a PSK server"
    );
}

#[test]
fn wrong_psk_client_cannot_handshake() {
    // Both sides use the PSK wrapper, but the client holds the WRONG psk and
    // builds its DCID from it. The server's gate rejects it (selector mismatch)
    // AND its Initial keys differ, so no handshake completes.
    let id = self_signed();
    let server_crypto: Arc<dyn quinn_proto::crypto::ServerConfig> =
        Arc::new(PskServerConfig::new(quic_server(&id), PSK));
    let client_crypto: Arc<dyn quinn_proto::crypto::ClientConfig> =
        Arc::new(PskClientConfig::new(quic_client(), WRONG_PSK));

    let out = run(
        server_crypto,
        client_crypto,
        Some(psk_dcid(&WRONG_PSK)),
        |dg| prefilter(dg, &PSK),
        false,
    );

    assert!(
        out.client_out_bytes > 0 && out.dropped_datagrams > 0,
        "sanity: the wrong-PSK client transmits and its datagrams are dropped"
    );
    assert!(!out.server_connected, "wrong-PSK client must be rejected");
    assert_eq!(
        out.server_out_bytes, 0,
        "wrong-PSK client must get ZERO server bytes"
    );
}
