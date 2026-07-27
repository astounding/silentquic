// SPDX-License-Identifier: 0BSD
//! Configuration types and their parsing.
//!
//! This module contains **no filesystem access** — parsing happens from strings
//! only, so the sans-IO core performs no I/O. To load secrets from a file, see
//! `silentquic::config::FileSource`, which reads the file (and warns about
//! group/world-readable permissions) before handing the text here.

use serde::Deserialize;
use std::net::SocketAddr;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 32-byte pre-shared key. Zeroized on drop; `Debug` never prints the bytes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Psk([u8; 32]);

impl Psk {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Psk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Psk(***)")
    }
}

impl<'de> Deserialize<'de> for Psk {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("psk must be 32 bytes (64 hex chars)"))?;
        Ok(Psk(arr))
    }
}

/// A single client's identity and PSK, as listed in the server's secrets file.
#[derive(Clone, Deserialize)]
pub struct ClientEntry {
    pub client_id: String,
    pub psk: Psk,
}

/// Server-side secrets: the listen address plus all authorized clients.
#[derive(Clone, Deserialize)]
pub struct ServerSecrets {
    pub listen: SocketAddr,
    pub clients: Vec<ClientEntry>,
}

/// Client-side config: this client's identity, PSK, and the server to dial.
#[derive(Clone, Deserialize)]
pub struct ClientConfigFile {
    pub client_id: String,
    pub psk: Psk,
    pub server: SocketAddr,
    /// Local address to bind the outbound socket to. Optional.
    ///
    /// When omitted (the default) the client binds `0.0.0.0:0` / `[::]:0` — an
    /// ephemeral port on any interface, matching what ordinary QUIC clients do.
    /// **Leave it unset unless you have a reason:** a fixed source port is a
    /// mild fingerprint, and the whole point of this transport is to look
    /// unremarkable.
    ///
    /// Set it when the deployment demands it:
    /// * an egress firewall that only permits UDP from an allowlisted source
    ///   port, or needs a stable port for a stateful pinhole;
    /// * a multi-homed host where traffic must leave a *specific* interface
    ///   (e.g. back up over the VPN, never the metered WAN) — bind that
    ///   interface's address with port `0` to pin the interface but keep an
    ///   ephemeral port;
    /// * NAT traversal that wants a predictable source port.
    ///
    /// Address family must match `server`; mismatches are rejected up front
    /// rather than surfacing as an opaque OS error.
    #[serde(default)]
    pub bind: Option<SocketAddr>,
}

/// Errors that can occur while loading or parsing config/secrets.
///
/// The `Io` variant exists for consumers that load config from a file (see
/// `silentquic::config::FileSource`); this crate itself never performs I/O.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psk_parses_from_hex() {
        let toml = r#"
listen = "127.0.0.1:4443"
[[clients]]
client_id = "a"
psk = "0000000000000000000000000000000000000000000000000000000000000001"
"#;
        let s: ServerSecrets = toml::from_str(toml).unwrap();
        assert_eq!(s.clients.len(), 1);
        assert_eq!(s.clients[0].client_id, "a");
        assert_eq!(s.clients[0].psk.as_bytes()[31], 1);
    }

    #[test]
    fn psk_debug_is_redacted() {
        let p = Psk([1u8; 32]);
        assert_eq!(format!("{:?}", p), "Psk(***)");
    }

    #[test]
    fn bad_hex_rejected() {
        let toml = r#"
listen = "127.0.0.1:4443"
[[clients]]
client_id = "a"
psk = "xyz"
"#;
        assert!(toml::from_str::<ServerSecrets>(toml).is_err());
    }

    #[test]
    fn config_error_can_report_semantic_validation() {
        assert_eq!(
            ConfigError::Invalid("duplicate client_id".into()).to_string(),
            "invalid configuration: duplicate client_id"
        );
    }
}
