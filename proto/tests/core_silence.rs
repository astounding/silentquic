// SPDX-License-Identifier: 0BSD
//! The silence invariant, proved through the sans-IO core API with **no sockets**.
//!
//! Every case here asserts two things: the datagram is reported as
//! [`DatagramOutcome::Dropped`], AND `poll_transmit` yields nothing afterwards.
//! The second assertion is the one that matters — it is what guarantees an
//! embedder driving the core by hand cannot reply to an unauthorized peer.

use silentquic_proto::config::ServerSecrets;
use silentquic_proto::endpoint::Endpoint;
use silentquic_proto::outcome::DatagramOutcome;
use std::net::SocketAddr;
use std::time::Instant;

const PSK_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000009";

fn server() -> Endpoint {
    let secrets: ServerSecrets = toml::from_str(&format!(
        "listen = \"127.0.0.1:0\"\n[[clients]]\nclient_id=\"a\"\npsk=\"{PSK_HEX}\"\n"
    ))
    .expect("parse secrets");
    Endpoint::new_server(secrets).expect("core server endpoint")
}

fn peer() -> SocketAddr {
    "127.0.0.1:9999".parse().unwrap()
}

/// Assert the endpoint has nothing to send. This is the silence assertion.
fn assert_silent(ep: &mut Endpoint, now: Instant, case: &str) {
    assert!(
        ep.poll_transmit(now).is_none(),
        "SILENCE VIOLATION ({case}): the endpoint queued a transmit for a dropped datagram"
    );
}

#[test]
fn junk_datagram_is_dropped_and_queues_no_transmit() {
    let mut ep = server();
    let now = Instant::now();

    let outcome = ep.handle_datagram(now, peer(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(outcome, DatagramOutcome::Dropped, "junk must be dropped");
    assert_silent(&mut ep, now, "junk");
}

#[test]
fn empty_datagram_is_dropped_and_queues_no_transmit() {
    let mut ep = server();
    let now = Instant::now();

    assert_eq!(ep.handle_datagram(now, peer(), &[]), DatagramOutcome::Dropped);
    assert_silent(&mut ep, now, "empty");
}

#[test]
fn stock_quic_shaped_initial_is_dropped_and_queues_no_transmit() {
    let mut ep = server();
    let now = Instant::now();

    // A long-header QUIC v1 Initial carrying a random 20-byte DCID: correct
    // shape, no valid selector. This is what a stock QUIC client looks like.
    let mut pkt = vec![0xc0];
    pkt.extend_from_slice(&0x0000_0001u32.to_be_bytes());
    pkt.push(20);
    pkt.extend_from_slice(&[0x5a; 20]);
    pkt.push(0);
    pkt.extend_from_slice(&[0u8; 1200]);

    assert_eq!(
        ep.handle_datagram(now, peer(), &pkt),
        DatagramOutcome::Dropped,
        "an Initial without a valid selector must be dropped"
    );
    assert_silent(&mut ep, now, "stock-QUIC-shaped");
}

// ---------------------------------------------------------------------------
// The rest of the silence matrix. Each case asserts BOTH that the datagram is
// reported `Dropped` AND that nothing is queued to send.
// ---------------------------------------------------------------------------

use silentquic_proto::config::ClientConfigFile;
use silentquic_proto::freshness::now_minutes;
use silentquic_proto::selector::build_dcid;

/// A long-header QUIC v1 Initial carrying `dcid`, padded to a plausible size.
fn initial_with_dcid(dcid: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0xc0];
    pkt.extend_from_slice(&0x0000_0001u32.to_be_bytes());
    pkt.push(dcid.len() as u8);
    pkt.extend_from_slice(dcid);
    pkt.push(0); // empty SCID
    pkt.extend_from_slice(&[0u8; 1200]);
    pkt
}

fn psk_bytes(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

#[test]
fn wrong_psk_selector_is_dropped_and_queues_no_transmit() {
    let mut ep = server();
    let now = Instant::now();

    // Correctly *shaped* selector DCID — right length, fresh timestamp — but
    // computed with a PSK the server does not know.
    let wrong = psk_bytes("00000000000000000000000000000000000000000000000000000000000000ff");
    let dcid = build_dcid(&wrong, [7u8; 8], now_minutes());

    assert_eq!(
        ep.handle_datagram(now, peer(), &initial_with_dcid(&dcid)),
        DatagramOutcome::Dropped,
        "a selector computed with an unknown PSK must be dropped"
    );
    assert_silent(&mut ep, now, "wrong PSK");
}

#[test]
fn stale_freshness_is_dropped_and_queues_no_transmit() {
    let mut ep = server();
    let now = Instant::now();

    // Correct PSK, but a timestamp far outside the acceptance window.
    let psk = psk_bytes(PSK_HEX);
    let dcid = build_dcid(&psk, [8u8; 8], now_minutes().wrapping_sub(10));

    assert_eq!(
        ep.handle_datagram(now, peer(), &initial_with_dcid(&dcid)),
        DatagramOutcome::Dropped,
        "a stale freshness stamp must be dropped"
    );
    assert_silent(&mut ep, now, "stale freshness");
}

/// Replay, discriminated properly.
///
/// A crafted packet cannot prove replay detection: it would be dropped either
/// way. So this uses a **genuine** client `Initial` — which the server accepts,
/// creating a connection — and then feeds the identical bytes again. The only
/// state that changed between the two calls is the replay guard, so the second
/// call's `Dropped` isolates it.
#[test]
fn replaying_a_genuine_initial_is_dropped() {
    let mut ep = server();
    let now = Instant::now();
    let client_addr: SocketAddr = "127.0.0.1:41000".parse().unwrap();

    let cfg: ClientConfigFile = toml::from_str(&format!(
        "client_id=\"a\"\npsk=\"{PSK_HEX}\"\nserver=\"127.0.0.1:4433\"\n"
    ))
    .expect("parse client config");
    let (mut client, _ch) =
        silentquic_proto::endpoint::Endpoint::new_client(now, now_minutes(), cfg)
            .expect("client endpoint");
    let initial = client
        .poll_transmit(now)
        .expect("client should have an Initial to send");

    // First sighting: a real, authorized Initial — the server admits it.
    let first = ep.handle_datagram(now, client_addr, &initial.contents);
    assert!(
        matches!(first, DatagramOutcome::Accepted(_)),
        "a genuine Initial must be admitted, got {first:?}"
    );

    // Byte-identical replay: only the replay guard has changed.
    assert_eq!(
        ep.handle_datagram(now, client_addr, &initial.contents),
        DatagramOutcome::Dropped,
        "a replayed Initial must be dropped by the anti-replay guard"
    );
}
