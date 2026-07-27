// SPDX-License-Identifier: 0BSD
//! Endpoint keying material and connection-ID generation.
//!
//! Everything here is pure construction of crypto objects — no I/O, no runtime.
//!
//! The reset key and handshake-token key are random per-process secrets, so
//! stateless-reset and address-validation tokens are unpredictable. Note that a
//! silent silentquic server never emits resets or Retries to unauthenticated
//! peers, so these gate nothing observable by a scanner; they exist because
//! quinn-proto requires them.
//!
//! The TLS identity is a throwaway self-signed certificate: the **PSK**, not the
//! certificate, authenticates the peer, and the client skips certificate
//! verification. See the design spec's threat model.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{ConnectionId, ConnectionIdGenerator, RandomConnectionIdGenerator};

// ---------------------------------------------------------------------------
// Connection-ID generation
// ---------------------------------------------------------------------------

/// A [`ConnectionIdGenerator`] that records every CID it mints.
///
/// The endpoint needs to know which connection IDs it has issued, for two
/// reasons: to route inbound short-header packets to already-authenticated
/// connections without re-running the cloaking pre-filter, and to attribute
/// freshly minted CIDs to the connection being serviced so they can be pruned
/// when that connection is lost.
pub struct RecordingCidGenerator {
    inner: RandomConnectionIdGenerator,
    issued: Arc<Mutex<HashSet<ConnectionId>>>,
    pending: Arc<Mutex<Vec<ConnectionId>>>,
}

impl RecordingCidGenerator {
    pub fn new(
        cid_len: usize,
        issued: Arc<Mutex<HashSet<ConnectionId>>>,
        pending: Arc<Mutex<Vec<ConnectionId>>>,
    ) -> Self {
        Self {
            inner: RandomConnectionIdGenerator::new(cid_len),
            issued,
            pending,
        }
    }
}

impl ConnectionIdGenerator for RecordingCidGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        let cid = self.inner.generate_cid();
        self.issued
            .lock()
            .expect("issued_cids poisoned")
            .insert(cid);
        // Record mint order so the caller can attribute this CID to the
        // connection it is currently servicing.
        self.pending
            .lock()
            .expect("pending_cids poisoned")
            .push(cid);
        cid
    }

    fn cid_len(&self) -> usize {
        self.inner.cid_len()
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        self.inner.cid_lifetime()
    }
}

// ---------------------------------------------------------------------------
// Endpoint keying material
// ---------------------------------------------------------------------------

pub struct HmacResetKey(aws_lc_rs::hmac::Key);

pub fn random_bytes<const N: usize>() -> [u8; N] {
    use aws_lc_rs::rand::SecureRandom;
    let mut out = [0u8; N];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut out)
        .expect("system rng");
    out
}

pub fn reset_key() -> HmacResetKey {
    let secret = random_bytes::<64>();
    HmacResetKey(aws_lc_rs::hmac::Key::new(
        aws_lc_rs::hmac::HMAC_SHA256,
        &secret,
    ))
}

impl quinn_proto::crypto::HmacKey for HmacResetKey {
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

pub fn token_key() -> Arc<aws_lc_rs::hkdf::Prk> {
    let secret = random_bytes::<32>();
    Arc::new(aws_lc_rs::hkdf::Prk::new_less_safe(
        aws_lc_rs::hkdf::HKDF_SHA256,
        &secret,
    ))
}

// ---------------------------------------------------------------------------
// Self-signed TLS identity
// ---------------------------------------------------------------------------

/// A throwaway self-signed certificate and key.
///
/// The PSK — not this certificate — authenticates the peer, so a self-signed
/// identity is sufficient and the client skips verification.
pub struct SelfSigned {
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

impl SelfSigned {
    pub fn generate() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        Ok(Self {
            cert: ck.cert.der().clone(),
            key: rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into()),
        })
    }

    pub fn quic_server_config(
        &self,
    ) -> Result<Arc<QuicServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let rustls_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![self.cert.clone()], self.key.clone_key())?;
        Ok(Arc::new(QuicServerConfig::try_from(rustls_config)?))
    }
}

// ---------------------------------------------------------------------------
// Client-side TLS
// ---------------------------------------------------------------------------

/// Stock rustls TLS 1.3 client crypto, with server-certificate verification
/// **skipped**.
///
/// This is deliberate and is not a weakening: in silentquic the **PSK**
/// authenticates the peer, both at the outer layer (only a server holding the
/// PSK can derive the Initial keys that unseal our ClientHello, so a wrong
/// server cannot even reply intelligibly) and by construction of the selector
/// DCID. The self-signed certificate the server presents carries no trust and
/// verifying it would prove nothing. See the design spec's threat model.
///
/// [`crate::initial_keys::PskClientConfig`] wraps the returned config to
/// override *only* the Initial packet keys; everything after the Initial is
/// ordinary TLS 1.3.
pub fn quic_client_config(
) -> Result<Arc<QuicClientConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let rustls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    Ok(Arc::new(QuicClientConfig::try_from(rustls_config)?))
}

/// Skip server-certificate verification: the PSK authenticates the peer, so the
/// TLS certificate is decorative. Private on purpose — it is reachable only
/// through [`quic_client_config`], where the rationale lives.
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
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
