# quietquic — Transport Seam & Silence Decision (Task 6 spike)

**Date:** 2026-07-03
**Status:** Spike complete — GREEN. Decision governs Tasks 7–9.
**Test:** `tests/spike_silence.rs` (8 tests, all pass). Run: `cargo test --test spike_silence`.

---

## TL;DR

- **Use sans-IO `quinn-proto`, not high-level `quinn`.** We own the UDP socket and
  run a `peek_dcid` + selector pre-filter *before* handing any datagram to
  `Endpoint::handle`. This is the layer at which silence is guaranteed.
- **PSK Initial re-keying works** via a thin wrapper around the rustls-backed
  `QuicServerConfig`/`QuicClientConfig` that overrides only `initial_keys`. rustls
  still runs the entire TLS 1.3 handshake; only the Initial packet protection
  changes.
- **The client's first-flight DCID is fully controllable** in sans-IO via
  `ClientConfig::initial_dst_cid_provider`. That is where our `build_dcid(...)`
  selector goes.
- We had to **implement quinn-proto's `crypto::PacketKey`/`HeaderKey` traits
  ourselves** (over `aws-lc-rs`) rather than reuse `rustls::quic::Keys::initial`,
  because the rustls path hard-codes the published salt and its `AeadKey`
  constructor is `pub(crate)`. See "API gap" below.

---

## (a) Silence guarantee: owned socket + pre-filter — CONFIRMED

The silence invariant is enforced at a layer we fully control, above quinn-proto:

1. We own the UDP socket (Task 7). For each inbound datagram we run
   `peek_dcid(&[u8]) -> Option<&[u8]>` — a pure long-header parser — then
   `selector_matches(psk, parse_dcid(dcid))`.
2. **If no PSK matches, we never call `Endpoint::handle` at all.** No connection
   state is allocated, and — critically — the endpoint never gets the chance to
   emit a Version Negotiation packet, a Retry, or a stateless reset. Nothing is
   written to the socket. The scanner sees a closed/filtered UDP port.
3. Only admitted datagrams reach `Endpoint::handle` → `Endpoint::accept`.

The spike proves this in-memory: `junk_flood_yields_zero_server_bytes`,
`raw_junk_datagrams_yield_zero_server_bytes`, and `wrong_psk_client_cannot_handshake`
each assert **`server_out_bytes == 0`** while also asserting the client actually
transmitted (`client_out_bytes > 0`) and at least one datagram was dropped
(`dropped_datagrams > 0`) — so the zero is a real silent-drop, not a vacuous pass.

The pre-filter is applied **only to connection establishment** (datagrams for which
no connection yet exists). Once a connection is accepted, subsequent packets are
routed by the server-chosen CID like any QUIC connection — their DCID is *not* a
selector DCID, so they must bypass the selector gate. Task 7's real router must key
off "is this DCID a known/active connection CID?" and only run the selector gate on
would-be-new connections.

## (b) Exact quinn-proto / rustls APIs used (Tasks 7–9 depend on these)

All verified against the **installed** versions: `quinn-proto 0.11.15`,
`rustls 0.23.41`, `aws-lc-rs 1.17.1`.

### Backend selection (Cargo.toml)

quinn-proto's default backend is `ring`. We switched it to `aws-lc-rs` so its
`HmacKey`/`HandshakeTokenKey` impls line up with our `aws-lc-rs` primitives and the
whole stack shares one backend:

```toml
quinn-proto = { version = "0.11", default-features = false,
                features = ["rustls-aws-lc-rs", "log", "bloom"] }
```

### Crypto hooks (the seam)

```rust
// quinn_proto::crypto::ServerConfig  — the server endpoint's first Initial unseal
fn initial_keys(&self, version: u32, dst_cid: &ConnectionId)
    -> Result<Keys, UnsupportedVersion>;
fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16];
fn start_session(self: Arc<Self>, version: u32, params: &TransportParameters)
    -> Box<dyn Session>;

// quinn_proto::crypto::ClientConfig
fn start_session(self: Arc<Self>, version: u32, server_name: &str,
                 params: &TransportParameters)
    -> Result<Box<dyn Session>, ConnectError>;

// quinn_proto::crypto::Session  — MUST also override initial_keys (both sides use
// this per-connection at connection/mod.rs:265, keyed on the client's initial DCID)
fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys;
// ...plus 13 delegated methods (handshake_data, read_handshake, write_handshake,
//    transport_parameters, next_1rtt_keys, is_valid_retry, export_keying_material,
//    peer_identity, early_crypto, early_data_accepted, is_handshaking).

// quinn_proto::crypto::Keys  { header: KeyPair<Box<dyn HeaderKey>>,
//                              packet: KeyPair<Box<dyn PacketKey>> }
// quinn_proto::crypto::PacketKey { encrypt(packet:u64, buf:&mut[u8], header_len:usize);
//    decrypt(packet:u64, header:&[u8], payload:&mut BytesMut) -> Result<(),CryptoError>;
//    tag_len; confidentiality_limit; integrity_limit }
// quinn_proto::crypto::HeaderKey { decrypt(pn_offset:usize, packet:&mut[u8]);
//    encrypt(pn_offset:usize, packet:&mut[u8]); sample_size() -> usize }
```

Both wrappers build their inner config from rustls via
`QuicServerConfig::try_from(rustls::ServerConfig)` /
`QuicClientConfig::try_from(rustls::ClientConfig)` (requires TLS13 +
`TLS13_AES_128_GCM_SHA256`, which is the QUIC-mandated Initial suite).

### Endpoint / connection driving (sans-IO)

```rust
Endpoint::new(config: Arc<EndpointConfig>, server_config: Option<Arc<ServerConfig>>,
              allow_mtud: bool, rng_seed: Option<[u8;32]>) -> Self
EndpointConfig::new(reset_key: Arc<dyn HmacKey>) -> Self
ServerConfig::new(crypto: Arc<dyn crypto::ServerConfig>,
                  token_key: Arc<dyn HandshakeTokenKey>) -> Self
ClientConfig::new(crypto: Arc<dyn crypto::ClientConfig>) -> Self
ClientConfig::initial_dst_cid_provider(
    &mut self, Arc<dyn Fn() -> ConnectionId + Send + Sync>) -> &mut Self  // ← selector DCID

Endpoint::handle(now, remote: SocketAddr, local_ip: Option<IpAddr>,
                 ecn: Option<EcnCodepoint>, data: BytesMut, buf: &mut Vec<u8>)
    -> Option<DatagramEvent>
// DatagramEvent = ConnectionEvent(ConnectionHandle, ConnectionEvent)
//               | NewConnection(Incoming) | Response(Transmit)
Endpoint::accept(incoming: Incoming, now, buf: &mut Vec<u8>,
                 server_config: Option<Arc<ServerConfig>>)
    -> Result<(ConnectionHandle, Connection), AcceptError>
Endpoint::connect(now, config: ClientConfig, remote: SocketAddr, server_name: &str)
    -> Result<(ConnectionHandle, Connection), ConnectError>
Endpoint::handle_event(ch: ConnectionHandle, EndpointEvent) -> Option<ConnectionEvent>

Connection::poll_transmit(now, max_datagrams: usize, buf: &mut Vec<u8>) -> Option<Transmit>
Connection::handle_event(ConnectionEvent)
Connection::poll_endpoint_events() -> Option<EndpointEvent>   // route back to Endpoint
Connection::handle_timeout(now); Connection::poll_timeout() -> Option<Instant>
Connection::poll() -> Option<Event>   // Event::Connected, Event::Stream(StreamEvent), ...
Connection::streams().open(Dir::Bi) / .accept(Dir::Bi) -> Option<StreamId>
Connection::send_stream(id).write(&[u8]) / .finish()
Connection::recv_stream(id).read(ordered:bool) -> Chunks; Chunks::next(max) -> Option<Chunk>
```

`buf` is a caller-owned `Vec<u8>`; after `poll_transmit`/`handle` returns a
`Transmit`, the datagram bytes are in `buf` (length = `buf.len()`; `Transmit.size`
equals it when there's no GSO). We take `buf[..]` as the datagram and clear it.

`HandshakeTokenKey` is implemented (in the aws-lc-rs backend) for
`aws_lc_rs::hkdf::Prk`; `HmacKey` for `aws_lc_rs::hmac::Key`. The spike builds both
from fixed secrets.

## (c) Can high-level `quinn` be used instead? — NO (evidence)

- `quinn::Endpoint` owns the UDP socket and its internal receive loop feeds every
  inbound datagram straight into `quinn_proto::Endpoint::handle`. There is no seam
  to run the selector pre-filter *before* the datagram reaches the state machine, so
  the endpoint can emit Version Negotiation / Retry / stateless-reset packets in
  response to unauthenticated junk — breaking the zero-bytes invariant.
- The re-keying hook we need (`crypto::ServerConfig::initial_keys` /
  `crypto::Session::initial_keys`) lives at the quinn-proto layer either way, so
  quinn buys us nothing there.
- **Decision:** Tasks 7–9 own the socket and drive `quinn-proto` directly. We keep
  the underlying `quinn_proto::Connection` reachable so `h3` can be layered later
  (design §6). We do *not* depend on the `quinn` crate.

## (d) Deviation from the target `initial_keys_from_psk` signature

Target: `pub fn initial_keys_from_psk(psk:&[u8;32], dcid:&[u8], side:Side, version:u32)
-> quinn_proto::crypto::Keys`. **Implemented exactly as specified** — no signature
deviation. `version` is asserted `== 1` in debug builds (the wire image is standard
QUIC v1) but is otherwise unused, since the QUIC v1 key-schedule labels are
version-independent.

### API gap that shaped the implementation

We could **not** reuse rustls's `quic::Keys::initial`/`Suite::keys` to re-key the
Initial, because:

- `rustls::quic::Keys::initial(version, suite, quic, dcid, side)` derives the extract
  salt internally as `version.initial_salt()` (the published QUIC v1 salt). There is
  **no parameter** to substitute the PSK.
- The lower-level pieces that would let us rebuild the keys by hand
  (`hkdf_expand_label*`, `DirectionalKeys::new`) are `pub(crate)`, and rustls's
  `AeadKey` only exposes `From<[u8; 32]>` (its length-aware constructors are
  `pub(crate)`), so we cannot hand `rustls::quic::Algorithm::packet_key` a correctly
  sized 16-byte AES-128 key through the public API.

**Resolution (surgical, fully public API):** implement quinn-proto's
`crypto::PacketKey` (AES-128-GCM via `aws_lc_rs::aead::LessSafeKey`, QUIC nonce =
IV XOR packet number) and `crypto::HeaderKey` (AES-128 header protection via
`aws_lc_rs::aead::quic::HeaderProtectionKey::new_mask`) directly, and derive the
Initial secrets with `aws_lc_rs::hkdf` using the PSK as the HKDF-Extract salt. The
header-protection XOR mirrors rustls's `xor_in_place` byte-for-byte (form-bit-aware
mask width, `masked` flag distinguishing encrypt vs decrypt). rustls still performs
the entire TLS 1.3 handshake and all non-Initial packet protection; only the Initial
keying is ours. This keeps the "mangle" as thin as the design demands (§8).

## What the spike proved (all in-memory, no sockets)

| Property | Test | Result |
|---|---|---|
| Sans-IO plumbing (standard crypto): handshake + bidi stream echo | `standard_crypto_handshake_and_stream_echo` | PASS |
| `peek_dcid`/selector gate admits matching, rejects junk & wrong PSK | `prefilter_*` | PASS |
| Stock client (published-salt Initial, random DCID) → **0 server bytes** | `junk_flood_yields_zero_server_bytes` | PASS |
| Pure junk datagrams → **0 server bytes** | `raw_junk_datagrams_yield_zero_server_bytes` | PASS |
| PSK peers (client DCID = `build_dcid`) handshake **and echo a stream** | `psk_peers_handshake_and_echo` | PASS |
| Stock client cannot handshake with PSK server (crypto alone, gate open) | `stock_client_cannot_handshake_with_psk_server` | PASS |
| Wrong-PSK client rejected → **0 server bytes** | `wrong_psk_client_cannot_handshake` | PASS |

## Notes / caveats for Tasks 7–9

- **Router keying:** run the selector gate only for datagrams that do not match an
  active connection CID. Established-connection packets must bypass it (their DCID is
  a server CID). The spike models this by applying the gate only while no server
  connection exists.
- **Freshness/replay** (design §4) are **not** exercised here — they are Task 3's
  `freshness.rs`/`replay.rs`, layered into the gate in Task 7. The spike uses a fixed
  nonce/freshness.
- **Retry:** the silent server must never issue a Retry (it would be an emitted byte
  to an unauthenticated peer). We keep `retry_tag` delegated for trait completeness
  but the router simply never calls the Retry path for unauthenticated traffic.
- **TLS cert:** a self-signed cert + skip-verify client verifier is used, per design:
  PSK is the authentication mechanism, not the TLS cert. Real deployments keep the
  same posture (private PSK-gated channel).
