// SPDX-License-Identifier: 0BSD
//! PSK-derived QUIC Initial packet protection keys.
//!
//! Stock QUIC v1 derives the Initial packet's AEAD and header-protection keys
//! from the *published* version salt (`0x38762cf7…`) and the client's on-wire
//! Destination Connection ID (RFC 9001 §5.2). Any observer can reproduce this
//! derivation and unseal the Initial to read the TLS ClientHello.
//!
//! silentquic keeps the identical RFC 9001 key schedule but substitutes the
//! **PSK** for the published salt in the initial `HKDF-Extract`:
//!
//! ```text
//! initial_secret        = HKDF-Extract(salt = psk, ikm = client_dcid)
//! client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
//! server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
//! key = HKDF-Expand-Label(secret, "quic key", "", 16)   // AES-128-GCM
//! iv  = HKDF-Expand-Label(secret, "quic iv",  "", 12)
//! hp  = HKDF-Expand-Label(secret, "quic hp",  "", 16)   // AES-128 header protection
//! ```
//!
//! An observer without the PSK cannot reproduce `initial_secret`, so their
//! unseal attempt yields garbage — the Initial appears to be an unknown QUIC
//! variant. Everything after the Initial packet is ordinary QUIC (rustls drives
//! the real TLS 1.3 handshake; only the Initial *protection keying* changes).
//!
//! This module implements quinn-proto's `crypto::PacketKey` / `crypto::HeaderKey`
//! traits directly on top of `aws-lc-rs` primitives. We do **not** use
//! `rustls::quic::Keys::initial`, because that function hard-codes the published
//! salt (`version.initial_salt()`) with no seam to override it, and rustls's
//! `AeadKey` constructor that would let us rebuild the keys by hand is
//! `pub(crate)`. Implementing the two quinn-proto traits ourselves is the
//! smallest fully-public-API surface that changes *only* the Initial keying.

use std::any::Any;
use std::sync::Arc;

use aws_lc_rs::{aead, hkdf};
use bytes::BytesMut;
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::crypto::{
    self, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey,
    ServerConfig, Session, UnsupportedVersion,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError};

/// AES-128-GCM: 16-byte key, 12-byte nonce/IV, 16-byte tag.
const AEAD_KEY_LEN: usize = 16;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Header-protection sample size for AES-based HP (RFC 9001 §5.4.1).
const HP_SAMPLE_LEN: usize = 16;
/// Per-direction TLS 1.3 traffic secret length for SHA-256.
const SECRET_LEN: usize = 32;

/// Confidentiality/integrity limits for AES-128-GCM (RFC 9001 §6.6). These are
/// astronomically high for an Initial packet space (which sends only a handful
/// of packets), but quinn-proto requires the trait to report them.
const CONFIDENTIALITY_LIMIT: u64 = 1 << 23;
const INTEGRITY_LIMIT: u64 = 1 << 52;

/// A `KeyType` for `hkdf::Prk::expand` that expands to an arbitrary byte length.
struct OkmLen(usize);
impl hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Build the RFC 8446 `HkdfLabel` `info` for HKDF-Expand-Label.
///
/// ```text
/// struct {
///   uint16 length;            // requested output length
///   opaque label<7..255>;     // "tls13 " ‖ label
///   opaque context<0..255>;   // empty for QUIC initial derivation
/// } HkdfLabel;
/// ```
fn hkdf_label_info(out_len: usize, label: &[u8]) -> Vec<u8> {
    const PREFIX: &[u8] = b"tls13 ";
    let mut info = Vec::with_capacity(2 + 1 + PREFIX.len() + label.len() + 1);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push((PREFIX.len() + label.len()) as u8);
    info.extend_from_slice(PREFIX);
    info.extend_from_slice(label);
    info.push(0); // zero-length context
    info
}

/// `HKDF-Expand-Label(prk, label, "", out_len)`.
fn expand_label(prk: &hkdf::Prk, label: &[u8], out: &mut [u8]) {
    let info = hkdf_label_info(out.len(), label);
    let info_refs: [&[u8]; 1] = [&info];
    prk.expand(&info_refs, OkmLen(out.len()))
        .expect("hkdf expand length within bounds")
        .fill(out)
        .expect("hkdf fill length within bounds");
}

/// One direction's Initial keys: AEAD (packet) + header protection.
struct DirectionalKeys {
    packet: InitialPacketKey,
    header: InitialHeaderKey,
}

/// Derive the AEAD/IV/HP material for one direction from a traffic secret.
fn directional_keys(secret: &[u8; SECRET_LEN]) -> DirectionalKeys {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);

    let mut key = [0u8; AEAD_KEY_LEN];
    let mut iv = [0u8; IV_LEN];
    let mut hp = [0u8; AEAD_KEY_LEN];
    expand_label(&prk, b"quic key", &mut key);
    expand_label(&prk, b"quic iv", &mut iv);
    expand_label(&prk, b"quic hp", &mut hp);

    DirectionalKeys {
        packet: InitialPacketKey::new(&key, iv),
        header: InitialHeaderKey::new(&hp),
    }
}

/// Derive the full set of Initial keys from a PSK and the client's DCID.
///
/// `side` is the local endpoint's role; `version` is the QUIC version (only
/// QUIC v1, `0x00000001`, is supported — the wire image is standard QUIC v1).
///
/// Panics only on internal invariant violations (fixed-length HKDF that cannot
/// fail); it takes a `&[u8]` dcid to match how quinn-proto hands us the raw
/// connection ID.
pub fn initial_keys_from_psk(psk: &[u8; 32], dcid: &[u8], side: Side, version: u32) -> Keys {
    // We only produce standard QUIC v1 on the wire. The derivation itself is
    // version-independent (the labels are the same across QUIC v1); `version`
    // is accepted for signature symmetry with quinn-proto's hooks and asserted
    // in debug builds.
    debug_assert_eq!(version, 0x0000_0001, "silentquic only speaks QUIC v1");

    // initial_secret = HKDF-Extract(salt = psk, ikm = dcid)
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, psk);
    let initial_prk = salt.extract(dcid);

    let mut client_secret = [0u8; SECRET_LEN];
    let mut server_secret = [0u8; SECRET_LEN];
    expand_label(&initial_prk, b"client in", &mut client_secret);
    expand_label(&initial_prk, b"server in", &mut server_secret);

    let client = directional_keys(&client_secret);
    let server = directional_keys(&server_secret);

    // local = keys we encrypt with; remote = keys we decrypt with.
    let (local, remote) = match side {
        Side::Client => (client, server),
        Side::Server => (server, client),
    };

    Keys {
        header: KeyPair {
            local: Box::new(local.header) as Box<dyn HeaderKey>,
            remote: Box::new(remote.header) as Box<dyn HeaderKey>,
        },
        packet: KeyPair {
            local: Box::new(local.packet) as Box<dyn PacketKey>,
            remote: Box::new(remote.packet) as Box<dyn PacketKey>,
        },
    }
}

/// AES-128-GCM packet protection implementing quinn-proto's `PacketKey`.
struct InitialPacketKey {
    key: aead::LessSafeKey,
    iv: [u8; IV_LEN],
}

impl InitialPacketKey {
    fn new(key: &[u8; AEAD_KEY_LEN], iv: [u8; IV_LEN]) -> Self {
        let unbound =
            aead::UnboundKey::new(&aead::AES_128_GCM, key).expect("AES-128-GCM key is 16 bytes");
        Self {
            key: aead::LessSafeKey::new(unbound),
            iv,
        }
    }

    /// QUIC nonce = IV XOR left-padded packet number (RFC 9001 §5.3).
    fn nonce(&self, packet: u64) -> [u8; IV_LEN] {
        let mut nonce = self.iv;
        let pn = packet.to_be_bytes();
        for (n, p) in nonce[IV_LEN - 8..].iter_mut().zip(pn.iter()) {
            *n ^= *p;
        }
        nonce
    }
}

impl PacketKey for InitialPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let nonce = aead::Nonce::assume_unique_for_key(self.nonce(packet));
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let payload_len = payload_tag.len() - TAG_LEN;
        let (payload, tag_out) = payload_tag.split_at_mut(payload_len);
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(&*header), payload)
            .expect("AEAD seal");
        tag_out.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let nonce = aead::Nonce::assume_unique_for_key(self.nonce(packet));
        let plain = self
            .key
            .open_in_place(nonce, aead::Aad::from(header), payload.as_mut())
            .map_err(|_| CryptoError)?;
        let plain_len = plain.len();
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        CONFIDENTIALITY_LIMIT
    }

    fn integrity_limit(&self) -> u64 {
        INTEGRITY_LIMIT
    }
}

/// AES-128 header protection implementing quinn-proto's `HeaderKey`.
struct InitialHeaderKey(aead::quic::HeaderProtectionKey);

impl InitialHeaderKey {
    fn new(key: &[u8; AEAD_KEY_LEN]) -> Self {
        Self(
            aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, key)
                .expect("AES-128 HP key is 16 bytes"),
        )
    }

    /// Apply header protection (RFC 9001 §5.4.1), mirroring rustls's
    /// `xor_in_place` exactly. `pn_offset` is the byte offset of the
    /// packet-number field; the mask sample starts 4 bytes after it.
    ///
    /// `masked` is `true` when *decrypting* (the first byte still carries the
    /// protection mask, so the true PN length is only known after unmasking it)
    /// and `false` when *encrypting* (the first byte is plaintext, so the PN
    /// length is read directly). This distinction is what makes encrypt/decrypt
    /// a correct inverse pair.
    fn apply(&self, pn_offset: usize, packet: &mut [u8], masked: bool) {
        const LONG_HEADER_FORM: u8 = 0x80;

        let sample_offset = pn_offset + 4;
        let sample: [u8; HP_SAMPLE_LEN] = packet[sample_offset..sample_offset + HP_SAMPLE_LEN]
            .try_into()
            .expect("sample is 16 bytes");
        let mask = self.0.new_mask(&sample).expect("valid sample length");

        // Long headers mask the low 4 bits of the first byte, short headers the
        // low 5. Initial packets are always long headers, but we read the form
        // bit rather than assume, matching the reference implementation.
        let bits = if packet[0] & LONG_HEADER_FORM == LONG_HEADER_FORM {
            0x0f
        } else {
            0x1f
        };

        // Determine PN length from the *plaintext* first byte.
        let first_plain = if masked {
            packet[0] ^ (mask[0] & bits)
        } else {
            packet[0]
        };
        let pn_len = ((first_plain & 0x03) + 1) as usize;

        packet[0] ^= mask[0] & bits;
        for (i, m) in mask[1..1 + pn_len].iter().enumerate() {
            packet[pn_offset + i] ^= *m;
        }
    }
}

impl HeaderKey for InitialHeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(pn_offset, packet, true);
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(pn_offset, packet, false);
    }

    fn sample_size(&self) -> usize {
        HP_SAMPLE_LEN
    }
}

// ---------------------------------------------------------------------------
// Wrapper crypto configs / session
//
// These wrap the stock rustls-backed quinn-proto crypto configs and delegate
// every method to the inner rustls implementation EXCEPT `initial_keys`, which
// is re-keyed from the PSK. rustls still runs the full TLS 1.3 handshake; only
// the Initial packet protection changes.
//
// Two seams override Initial keying:
//   * `crypto::ServerConfig::initial_keys` — the server endpoint's first
//     unseal of the client's Initial (endpoint.rs:448).
//   * `crypto::Session::initial_keys` — each connection's Initial packet space
//     on both sides (connection/mod.rs:265). Both use the client's initial
//     DCID, which the client sets to `build_dcid(psk, nonce, freshness)`.
// ---------------------------------------------------------------------------

/// QUIC v1 wire version. silentquic only ever produces standard QUIC v1.
const QUIC_V1: u32 = 0x0000_0001;

/// Server-side crypto config that re-keys the Initial packet from a PSK.
pub struct PskServerConfig {
    inner: Arc<QuicServerConfig>,
    psk: [u8; 32],
}

impl PskServerConfig {
    pub fn new(inner: Arc<QuicServerConfig>, psk: [u8; 32]) -> Self {
        Self { inner, psk }
    }
}

impl ServerConfig for PskServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        if version != QUIC_V1 {
            return Err(UnsupportedVersion);
        }
        Ok(initial_keys_from_psk(
            &self.psk,
            dst_cid,
            Side::Server,
            version,
        ))
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        // Delegated: the silent server never actually issues a Retry, but the
        // trait requires it. Using the stock tag is harmless.
        self.inner.retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session> {
        let inner = self.inner.clone().start_session(version, params);
        Box::new(PskSession {
            inner,
            psk: self.psk,
        })
    }
}

/// Client-side crypto config that re-keys the Initial packet from a PSK.
pub struct PskClientConfig {
    inner: Arc<QuicClientConfig>,
    psk: [u8; 32],
}

impl PskClientConfig {
    pub fn new(inner: Arc<QuicClientConfig>, psk: [u8; 32]) -> Self {
        Self { inner, psk }
    }
}

impl crypto::ClientConfig for PskClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        let inner = self
            .inner
            .clone()
            .start_session(version, server_name, params)?;
        Ok(Box::new(PskSession {
            inner,
            psk: self.psk,
        }))
    }
}

/// A TLS session wrapper that overrides only Initial keying.
struct PskSession {
    inner: Box<dyn Session>,
    psk: [u8; 32],
}

impl Session for PskSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        initial_keys_from_psk(&self.psk, dst_cid, side, QUIC_V1)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        self.inner.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_handshake(buf)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        self.inner.write_handshake(buf)
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.inner.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer vector for `initial_keys_from_psk`.
    ///
    /// The derived `Keys` are boxed `dyn PacketKey`/`dyn HeaderKey` trait
    /// objects whose key/IV bytes are not directly readable through the public
    /// quinn-proto API. So instead of pinning the raw key material, we pin a
    /// *deterministic observable* of the derivation: the AEAD sealing of a fixed
    /// header + plaintext at a fixed packet number under the client's local
    /// (encrypt) Initial packet key. `PacketKey::encrypt` is fully
    /// deterministic (AES-128-GCM with a fixed nonce = iv ^ packet number), so
    /// the resulting ciphertext-plus-tag is a stable fingerprint of the entire
    /// PSK → initial_secret → "client in" → "quic key"/"quic iv" schedule.
    ///
    /// If this vector breaks, the Initial key derivation changed — a breaking
    /// protocol change (the on-wire Initial ciphertext moves), NOT a test to
    /// bump blindly. The client↔server round-trip tests elsewhere would stay
    /// green under a symmetric change to the derivation; this KAT is what pins
    /// the absolute output.
    #[test]
    fn initial_keys_known_answer_vector() {
        let psk = [7u8; 32];
        let dcid = [1u8; 20];
        let keys = initial_keys_from_psk(&psk, &dcid, Side::Client, QUIC_V1);

        // Fixed header + plaintext, sealed at a fixed packet number. `encrypt`
        // seals in place: buf = header ‖ plaintext ‖ (space for TAG_LEN tag).
        const HEADER: &[u8] = &[0xc3, 0x00, 0x00, 0x00, 0x01];
        const PLAINTEXT: &[u8] = b"silentquic-kat";
        let packet_number: u64 = 0;

        let mut buf = Vec::new();
        buf.extend_from_slice(HEADER);
        buf.extend_from_slice(PLAINTEXT);
        buf.extend_from_slice(&[0u8; TAG_LEN]);
        keys.packet
            .local
            .encrypt(packet_number, &mut buf, HEADER.len());

        // The ciphertext-plus-tag (everything after the header) is the pinned
        // observable. Header bytes are AAD and pass through unchanged.
        assert_eq!(
            &buf[..HEADER.len()],
            HEADER,
            "header is AAD, must be unchanged"
        );
        const EXPECTED_CIPHERTEXT_AND_TAG: [u8; 30] = [
            198, 61, 185, 123, 150, 238, 166, 92, 206, 201, 222, 182, 234, 1, 23, 173, 206, 213,
            38, 157, 83, 65, 52, 141, 167, 192, 156, 193, 3, 183,
        ];
        assert_eq!(&buf[HEADER.len()..], &EXPECTED_CIPHERTEXT_AND_TAG);
    }
}
