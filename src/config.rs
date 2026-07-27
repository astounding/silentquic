// SPDX-License-Identifier: 0BSD
//! Crate configuration: TOML-loaded server/client settings.
//!
//! The configuration **types** live in the sans-IO core
//! (`silentquic_proto::config`) and are re-exported here, so
//! `silentquic::config::ServerSecrets` and friends resolve unchanged. What
//! stays here is the part that touches the filesystem: the `SecretSource` seam
//! and its v1 implementation, `FileSource`.

use std::path::PathBuf;

// Re-exported so this module's public surface is unchanged; the core owns the
// types because they are pure parsing with no I/O.
pub use silentquic_proto::config::{
    ClientConfigFile, ClientEntry, ConfigError, Psk, ServerSecrets,
};

/// A source of server secrets. v1 ships only `FileSource`; this trait is the
/// seam for a future optional OS-keyring source.
pub trait SecretSource {
    fn load(&self) -> Result<ServerSecrets, ConfigError>;
}

/// Loads `ServerSecrets` from a plain-TOML file on disk.
pub struct FileSource {
    path: PathBuf,
}

impl FileSource {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl SecretSource for FileSource {
    fn load(&self) -> Result<ServerSecrets, ConfigError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&self.path) {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    tracing::warn!(
                        path = ?self.path,
                        mode = format!("{:o}", mode),
                        "secret file is group/world accessible; recommend chmod 600"
                    );
                }
            }
        }
        let text = std::fs::read_to_string(&self.path)?;
        Ok(toml::from_str(&text)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn file_source_loads() {
        let dir = std::env::temp_dir().join(format!("sq-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(
            br#"
listen = "127.0.0.1:4443"
[[clients]]
client_id = "a"
psk = "0000000000000000000000000000000000000000000000000000000000000002"
"#,
        )
        .unwrap();
        let secrets = FileSource::new(&path).load().unwrap();
        assert_eq!(secrets.clients[0].psk.as_bytes()[31], 2);
    }
}
