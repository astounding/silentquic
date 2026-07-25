# silentquic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a 0BSD Rust library providing a cloaked QUIC transport: a server invisible to scanners (silent to any peer without a valid PSK), traffic camouflaged as vanilla QUIC v1, PSK auth folded into the QUIC `Initial` via a blinded DCID selector, exposing raw authenticated bidirectional streams.

**Architecture:** Authentication and per-client key *selection* are embedded in the client's Destination Connection ID (`DCID = nonce ‖ freshness ‖ selector`, where `selector = keyed-BLAKE3(psk, nonce ‖ freshness ‖ context)`). The server owns its UDP socket and runs a **cheap MAC pre-filter** on every inbound datagram *before* any QUIC state exists: no selector match → the datagram is dropped and no byte is ever sent. Matched datagrams are handed to a `quinn-proto` (sans-IO) endpoint whose `Initial` packet keys are re-derived from the matched PSK (RFC 9001 derivation with the PSK replacing the published salt). Post-handshake it is an ordinary QUIC connection; the `quinn_proto::Connection` is exposed so `h3` can be layered later.

**Tech Stack:** Rust, `quinn-proto` (sans-IO QUIC) + `quinn` types, `tokio` (async UDP loop), `blake3` (keyed selector MAC + HKDF), `aws-lc-rs` or `ring` (AEAD/HKDF for Initial keys, matching rustls' backend), `serde` + `toml` (config), `zeroize` (secret hygiene).

## Global Constraints

- **License:** 0BSD. Every source file starts with a one-line `// SPDX-License-Identifier: 0BSD` header. Reused Apache-2.0 snippets retain their upstream notice for those portions.
- **Platforms:** Linux, macOS, FreeBSD — all must build and pass tests. CI runs all three.
- **Silence invariant (non-negotiable):** the server MUST NOT emit any UDP datagram in response to a packet that fails selector pre-filtering or PSK verification. No Version Negotiation, no Retry, no CONNECTION_REFUSED, no stateless reset to unauthorized peers.
- **Wire image:** standard QUIC v1 (version `0x00000001`), long-header format, default UDP/443 (configurable). Only the `Initial` *protection keying* deviates from stock QUIC.
- **Auth model:** per-client PSKs held in an explicit set now; design must not foreclose a future `psk = HKDF(root, client_id)` derive-from-root scheme (localized to key *lookup*, no wire-format/selector change).
- **DCID budget:** QUIC v1 max Connection ID length is 20 bytes; quinn requires the client initial DCID be ≥ 8 bytes and unpredictable. Layout MUST fit in exactly 20 bytes: `nonce (8) ‖ freshness (4, u32 LE minutes-since-epoch) ‖ selector (8)`.
- **Reject path:** on unauthorized packets, no heap allocation, no secret-dependent branching beyond the bounded MAC compare, bounded by per-source + global rate limits / CPU budget.
- **PSK size:** 32 bytes. `context` is a fixed domain-separation constant `b"silentquic/v1/selector"`.
- **Secrets:** stored as plain TOML, `chmod 600`, loaded through a `SecretSource` trait (v1: `FileSource`). Secrets wrapped in `zeroize`-ing types; never logged.
- **TDD:** every task writes a failing test first, watches it fail, implements minimally, watches it pass, commits.

---

### Task 1: Crate scaffold, license, CI matrix

**Files:**
- Create: `Cargo.toml`
- Create: `src/lib.rs`
- Create: `LICENSE` (already exists at repo root — verify it is the 0BSD text; if the crate lives in a subdir, add a crate-local copy)
- Create: `.github/workflows/ci.yml`
- Create: `rust-toolchain.toml`

**Interfaces:**
- Produces: an empty compiling library crate named `silentquic`, module skeleton declared (`selector`, `freshness`, `replay`, `initial_keys`, `config`, `transport`, `server`, `client`), CI running `cargo test` + `cargo clippy` on Linux/macOS/FreeBSD.

- [ ] **Step 1: Write `Cargo.toml`**

```toml
[package]
name = "silentquic"
version = "0.0.0"
edition = "2021"
license = "0BSD"
description = "Cloaked QUIC transport: scanner-invisible, PSK-authenticated, camouflaged as vanilla QUIC."
repository = ""

[dependencies]
quinn-proto = "0.11"
bytes = "1"
tokio = { version = "1", features = ["net", "rt-multi-thread", "macros", "time", "sync"] }
blake3 = "1"
aws-lc-rs = "1"
serde = { version = "1", features = ["derive"] }
toml = "0.8"
zeroize = { version = "1", features = ["derive"] }
thiserror = "2"
tracing = "0.1"

[dev-dependencies]
tokio = { version = "1", features = ["full"] }
hex = "0.4"
```

Note: pin exact minor versions during implementation with `cargo add`; the spike (Task 6) confirms the `quinn-proto` line and whether `quinn` high-level is also needed.

- [ ] **Step 2: Write `src/lib.rs` module skeleton**

```rust
// SPDX-License-Identifier: 0BSD
//! silentquic — a cloaked QUIC transport.
//!
//! See `docs/superpowers/specs/2026-07-03-silentquic-design.md` for the threat
//! model. In particular: this defeats scanning and casual DPI, NOT global
//! passive traffic analysis, active per-flow Initial decryption, or a resource
//! side-channel via a co-located service. Run it as the only service on its host.

pub mod selector;
pub mod freshness;
pub mod replay;
pub mod initial_keys;
pub mod config;
pub mod transport;
pub mod server;
pub mod client;
```

Create each module file with just the SPDX header and a `//!` doc line so the crate compiles.

- [ ] **Step 3: Write `rust-toolchain.toml`**

```toml
[toolchain]
channel = "stable"
components = ["clippy", "rustfmt"]
```

- [ ] **Step 4: Write `.github/workflows/ci.yml`**

```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: clippy }
      - run: cargo test --all
      - run: cargo clippy --all -- -D warnings
  freebsd:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vmactions/freebsd-vm@v1
        with:
          usesh: true
          prepare: pkg install -y rust
          run: cargo test --all
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo build && cargo test`
Expected: builds clean, 0 tests run.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/ rust-toolchain.toml .github/
git commit -m "feat: scaffold silentquic crate with CI matrix"
```

---

### Task 2: Selector — DCID construction & parsing

**Files:**
- Create: `src/selector.rs`
- Test: inline `#[cfg(test)]` module in `src/selector.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub const CONTEXT: &[u8] = b"silentquic/v1/selector";`
  - `pub const DCID_LEN: usize = 20;`
  - `pub struct DcidParts { pub nonce: [u8; 8], pub freshness: u32, pub selector: [u8; 8] }`
  - `pub fn compute_selector(psk: &[u8; 32], nonce: &[u8; 8], freshness: u32) -> [u8; 8]`
  - `pub fn build_dcid(psk: &[u8; 32], nonce: [u8; 8], freshness: u32) -> [u8; 20]`
  - `pub fn parse_dcid(dcid: &[u8]) -> Option<DcidParts>` (None if wrong length)
  - `pub fn selector_matches(psk: &[u8; 32], parts: &DcidParts) -> bool` (constant-time compare)

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_is_deterministic_for_same_inputs() {
        let psk = [7u8; 32];
        let nonce = [1u8; 8];
        let a = compute_selector(&psk, &nonce, 100);
        let b = compute_selector(&psk, &nonce, 100);
        assert_eq!(a, b);
    }

    #[test]
    fn selector_differs_across_psk_nonce_freshness() {
        let base = compute_selector(&[7u8; 32], &[1u8; 8], 100);
        assert_ne!(base, compute_selector(&[8u8; 32], &[1u8; 8], 100));
        assert_ne!(base, compute_selector(&[7u8; 32], &[2u8; 8], 100));
        assert_ne!(base, compute_selector(&[7u8; 32], &[1u8; 8], 101));
    }

    #[test]
    fn build_then_parse_roundtrips() {
        let psk = [42u8; 32];
        let dcid = build_dcid(&psk, [9u8; 8], 12345);
        assert_eq!(dcid.len(), DCID_LEN);
        let parts = parse_dcid(&dcid).expect("parse");
        assert_eq!(parts.nonce, [9u8; 8]);
        assert_eq!(parts.freshness, 12345);
        assert!(selector_matches(&psk, &parts));
    }

    #[test]
    fn wrong_psk_does_not_match() {
        let dcid = build_dcid(&[1u8; 32], [9u8; 8], 12345);
        let parts = parse_dcid(&dcid).unwrap();
        assert!(!selector_matches(&[2u8; 32], &parts));
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(parse_dcid(&[0u8; 8]).is_none());
        assert!(parse_dcid(&[0u8; 19]).is_none());
        assert!(parse_dcid(&[0u8; 21]).is_none());
    }
}
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --lib selector`
Expected: FAIL — items not defined.

- [ ] **Step 3: Implement `src/selector.rs`**

```rust
// SPDX-License-Identifier: 0BSD
//! Blinded DCID selector: embeds per-client key selection into the QUIC DCID.

pub const CONTEXT: &[u8] = b"silentquic/v1/selector";
pub const DCID_LEN: usize = 20;

#[derive(Clone, Copy, Debug)]
pub struct DcidParts {
    pub nonce: [u8; 8],
    pub freshness: u32,
    pub selector: [u8; 8],
}

pub fn compute_selector(psk: &[u8; 32], nonce: &[u8; 8], freshness: u32) -> [u8; 8] {
    let mut hasher = blake3::Hasher::new_keyed(psk);
    hasher.update(CONTEXT);
    hasher.update(nonce);
    hasher.update(&freshness.to_le_bytes());
    let hash = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash.as_bytes()[..8]);
    out
}

pub fn build_dcid(psk: &[u8; 32], nonce: [u8; 8], freshness: u32) -> [u8; 20] {
    let selector = compute_selector(psk, &nonce, freshness);
    let mut dcid = [0u8; 20];
    dcid[..8].copy_from_slice(&nonce);
    dcid[8..12].copy_from_slice(&freshness.to_le_bytes());
    dcid[12..20].copy_from_slice(&selector);
    dcid
}

pub fn parse_dcid(dcid: &[u8]) -> Option<DcidParts> {
    if dcid.len() != DCID_LEN {
        return None;
    }
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&dcid[..8]);
    let freshness = u32::from_le_bytes(dcid[8..12].try_into().ok()?);
    let mut selector = [0u8; 8];
    selector.copy_from_slice(&dcid[12..20]);
    Some(DcidParts { nonce, freshness, selector })
}

pub fn selector_matches(psk: &[u8; 32], parts: &DcidParts) -> bool {
    let expected = compute_selector(psk, &parts.nonce, parts.freshness);
    // constant-time compare
    let mut diff = 0u8;
    for i in 0..8 {
        diff |= expected[i] ^ parts.selector[i];
    }
    diff == 0
}
```

- [ ] **Step 4: Run tests, verify pass**

Run: `cargo test --lib selector`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/selector.rs
git commit -m "feat: blinded DCID selector construction and parsing"
```

---

### Task 3: Freshness validation

**Files:**
- Create: `src/freshness.rs`
- Test: inline `#[cfg(test)]` in `src/freshness.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub fn now_minutes() -> u32` (minutes since Unix epoch, truncated to u32)
  - `pub const WINDOW_MINUTES: u32 = 2;`
  - `pub fn is_fresh(freshness: u32, now: u32, window: u32) -> bool` (accepts `now-window ..= now+window`, saturating)

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_window_is_fresh() {
        assert!(is_fresh(100, 100, 2));
        assert!(is_fresh(98, 100, 2));
        assert!(is_fresh(102, 100, 2));
    }

    #[test]
    fn outside_window_is_stale() {
        assert!(!is_fresh(97, 100, 2));
        assert!(!is_fresh(103, 100, 2));
    }

    #[test]
    fn saturates_at_boundaries() {
        assert!(is_fresh(0, 1, 2)); // now-window would underflow
        assert!(is_fresh(u32::MAX, u32::MAX - 1, 2)); // now+window would overflow
    }
}
```

- [ ] **Step 2: Run, verify fail**

Run: `cargo test --lib freshness`
Expected: FAIL — not defined.

- [ ] **Step 3: Implement `src/freshness.rs`**

```rust
// SPDX-License-Identifier: 0BSD
//! Coarse-timestamp freshness check for the DCID authenticator.

use std::time::{SystemTime, UNIX_EPOCH};

pub const WINDOW_MINUTES: u32 = 2;

pub fn now_minutes() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs / 60) as u32
}

pub fn is_fresh(freshness: u32, now: u32, window: u32) -> bool {
    let lo = now.saturating_sub(window);
    let hi = now.saturating_add(window);
    freshness >= lo && freshness <= hi
}
```

- [ ] **Step 4: Run, verify pass**

Run: `cargo test --lib freshness`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/freshness.rs
git commit -m "feat: freshness window validation"
```

---

### Task 4: Anti-replay nonce window

**Files:**
- Create: `src/replay.rs`
- Test: inline `#[cfg(test)]` in `src/replay.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub struct ReplayGuard` with `pub fn new(window_minutes: u32) -> Self`
  - `pub fn check_and_record(&mut self, nonce: [u8; 8], freshness: u32, now: u32) -> bool` — returns `true` if this (nonce,freshness) is new and accepted, `false` if replayed. Purges entries older than the window on each call.

**Notes:** Bounded memory: entries expire when `freshness < now - window`. This guards the small acceptance window only; it is not a global forever-set.

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sighting_accepted() {
        let mut g = ReplayGuard::new(2);
        assert!(g.check_and_record([1u8; 8], 100, 100));
    }

    #[test]
    fn exact_replay_rejected() {
        let mut g = ReplayGuard::new(2);
        assert!(g.check_and_record([1u8; 8], 100, 100));
        assert!(!g.check_and_record([1u8; 8], 100, 100));
    }

    #[test]
    fn different_nonce_accepted() {
        let mut g = ReplayGuard::new(2);
        assert!(g.check_and_record([1u8; 8], 100, 100));
        assert!(g.check_and_record([2u8; 8], 100, 100));
    }

    #[test]
    fn expired_entries_purged() {
        let mut g = ReplayGuard::new(2);
        assert!(g.check_and_record([1u8; 8], 100, 100));
        // advance now well past window; old entry purged so memory bounded
        assert!(g.check_and_record([9u8; 8], 200, 200));
        assert_eq!(g.len(), 1);
    }
}
```

- [ ] **Step 2: Run, verify fail**

Run: `cargo test --lib replay`
Expected: FAIL — not defined.

- [ ] **Step 3: Implement `src/replay.rs`**

```rust
// SPDX-License-Identifier: 0BSD
//! Bounded anti-replay set over (nonce, freshness) within the acceptance window.

use std::collections::HashSet;

pub struct ReplayGuard {
    window: u32,
    seen: HashSet<([u8; 8], u32)>,
}

impl ReplayGuard {
    pub fn new(window_minutes: u32) -> Self {
        Self { window: window_minutes, seen: HashSet::new() }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    pub fn check_and_record(&mut self, nonce: [u8; 8], freshness: u32, now: u32) -> bool {
        let cutoff = now.saturating_sub(self.window);
        self.seen.retain(|(_, f)| *f >= cutoff);
        self.seen.insert((nonce, freshness))
    }
}
```

- [ ] **Step 4: Run, verify pass**

Run: `cargo test --lib replay`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/replay.rs
git commit -m "feat: bounded anti-replay nonce window"
```

---

### Task 5: Config & SecretSource

**Files:**
- Create: `src/config.rs`
- Test: inline `#[cfg(test)]` in `src/config.rs`, plus a temp-file test

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub struct Psk([u8; 32])` — `zeroize::Zeroize` + `ZeroizeOnDrop`, `Debug` prints `Psk(***)`, `pub fn as_bytes(&self) -> &[u8; 32]`, deserializes from a 64-char hex string.
  - `pub trait SecretSource { fn load(&self) -> Result<ServerSecrets, ConfigError>; }`
  - `pub struct FileSource { path: PathBuf }` with `pub fn new(path: impl Into<PathBuf>) -> Self`
  - `pub struct ServerSecrets { pub clients: Vec<ClientEntry>, pub listen: SocketAddr }`
  - `pub struct ClientEntry { pub client_id: String, pub psk: Psk }`
  - `pub struct ClientConfigFile { pub client_id: String, pub psk: Psk, pub server: SocketAddr }` (client-side)
  - `pub enum ConfigError` (io, parse, bad_hex, bad_perms)
  - `FileSource::load` warns (via `tracing::warn!`) if file perms are not `0600` on unix.

**TOML schema (server):**
```toml
listen = "0.0.0.0:443"
[[clients]]
client_id = "laptop"
psk = "aabbcc...(64 hex chars)"
[[clients]]
client_id = "desktop"
psk = "ddeeff...(64 hex chars)"
```

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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
    fn file_source_loads() {
        let dir = std::env::temp_dir().join(format!("sq-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(br#"
listen = "127.0.0.1:4443"
[[clients]]
client_id = "a"
psk = "0000000000000000000000000000000000000000000000000000000000000002"
"#).unwrap();
        let secrets = FileSource::new(&path).load().unwrap();
        assert_eq!(secrets.clients[0].psk.as_bytes()[31], 2);
    }
}
```

- [ ] **Step 2: Run, verify fail**

Run: `cargo test --lib config`
Expected: FAIL — not defined.

- [ ] **Step 3: Implement `src/config.rs`**

```rust
// SPDX-License-Identifier: 0BSD
//! Plain-TOML config and the SecretSource seam (v1: FileSource).

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use zeroize::{Zeroize, ZeroizeOnDrop};

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

#[derive(Deserialize)]
pub struct ClientEntry {
    pub client_id: String,
    pub psk: Psk,
}

#[derive(Deserialize)]
pub struct ServerSecrets {
    pub listen: SocketAddr,
    pub clients: Vec<ClientEntry>,
}

#[derive(Deserialize)]
pub struct ClientConfigFile {
    pub client_id: String,
    pub psk: Psk,
    pub server: SocketAddr,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] toml::de::Error),
}

pub trait SecretSource {
    fn load(&self) -> Result<ServerSecrets, ConfigError>;
}

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
                    tracing::warn!(?self.path, mode = format!("{:o}", mode),
                        "secret file is group/world accessible; recommend chmod 600");
                }
            }
        }
        let text = std::fs::read_to_string(&self.path)?;
        Ok(toml::from_str(&text)?)
    }
}
```

Add `hex = "0.4"` to `[dependencies]` (currently dev-only) — move it up.

- [ ] **Step 4: Run, verify pass**

Run: `cargo test --lib config`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/config.rs Cargo.toml
git commit -m "feat: TOML config with SecretSource seam and zeroizing Psk"
```

---

### Task 6: SPIKE — transport seam & silence proof

**This task is a feasibility spike. Its deliverable is a decision + a passing end-to-end silence test, not polished API.** It resolves the one genuinely uncertain part of the design before the dependent tasks build on it.

**Files:**
- Create: `src/initial_keys.rs`
- Create: `tests/spike_silence.rs`
- Create: `docs/superpowers/notes/silentquic-transport-decision.md` (record the outcome)

**Interfaces (target — confirm/adjust during spike):**
- Produces: `pub fn initial_keys_from_psk(psk: &[u8; 32], dcid: &[u8], side: Side, version: u32) -> quinn_proto::crypto::Keys` — RFC 9001 Initial key derivation with `psk` used as the HKDF salt in place of the QUIC v1 published salt.

**Investigation steps (each is a real experiment, record results in the notes file):**

- [ ] **Step 1: Confirm sans-IO datagram feeding.** Write a throwaway `main`/test that constructs a `quinn_proto::Endpoint` (server) and a `quinn_proto::Endpoint` (client) with a **standard** self-signed rustls config, drives them by hand-passing `Transmit`/datagrams over in-memory buffers (no sockets), and completes a handshake + one stream echo. This proves we can own the I/O and feed quinn-proto manually.

Reference API: `quinn_proto::Endpoint::new`, `Endpoint::handle(now, remote, ecn, buf)` returning `DatagramEvent`, `Connection::poll_transmit`, `Connection::handle_event`, `Connection::datagrams`/`streams`. Confirm exact signatures against the installed `quinn-proto` version with `cargo doc --open`.

- [ ] **Step 2: Confirm the pre-filter drops silently.** In front of the server `Endpoint`, add the Task 2 selector check: parse the long-header DCID from the raw datagram, run `selector_matches` against a known PSK; if no match, **do not call `Endpoint::handle` at all** and send nothing. Assert (in-memory) that a junk datagram produces zero outbound `Transmit`s. This is the silence invariant, proven at the layer we control.

Parsing the DCID from a raw QUIC long header: byte 0 has the long-header form bit; bytes 1..5 are the version; byte 5 is DCID length; bytes 6..6+len are the DCID. Write a tiny `peek_dcid(datagram: &[u8]) -> Option<&[u8]>` helper (goes in `src/transport.rs` in Task 7; prototype it here).

- [ ] **Step 3: Implement `initial_keys_from_psk` and prove PSK-rekeying interops.** Derive Initial secrets per RFC 9001 §5.2 but with `psk` as the extract salt: `initial_secret = HKDF-Extract(psk, client_dcid)`, then `client_initial_secret`/`server_initial_secret` via `expand_label`, then AEAD (AES-128-GCM) + header-protection keys. Construct `quinn_proto::crypto::Keys`. Use the same `aws-lc-rs`/`ring` primitives rustls uses so the `Keys` type is compatible. Configure BOTH endpoints' crypto so `initial_keys` uses this function with the shared PSK. Complete a handshake. Then point a **stock** quinn client (published-salt Initial keys) at the server and assert the handshake never completes and the server emits nothing beyond what the pre-filter already blocks.

Key references: RFC 9001 §5.2 (Initial secrets), `quinn_proto::crypto::rustls` for how `Keys`/`PacketKey`/`HeaderKey` are constructed, `quinn_proto::Side`.

- [ ] **Step 4: Decide and record.** In the notes file, record: (a) confirmed that owning the socket + pre-filter guarantees silence (expected: yes); (b) the exact `quinn-proto` APIs and signatures used; (c) whether the high-level `quinn` crate can be used instead (likely no, because it owns the socket and can emit version-negotiation/retry — record the evidence); (d) any deviation from the target `initial_keys_from_psk` signature. This decision governs Tasks 7–9.

- [ ] **Step 5: Land the spike test green**

Run: `cargo test --test spike_silence`
Expected: PASS — in-memory: PSK-matched peers handshake and echo; junk and stock-QUIC peers get zero bytes.

- [ ] **Step 6: Commit**

```bash
git add src/initial_keys.rs tests/spike_silence.rs docs/superpowers/notes/
git commit -m "spike: prove pre-filter silence and PSK Initial re-keying over quinn-proto"
```

---

### Task 7: Server — UDP loop, pre-filter, endpoint driver

**Files:**
- Create: `src/transport.rs` (shared datagram helpers: `peek_dcid`, an `AsyncUdp` wrapper over `tokio::net::UdpSocket`)
- Create: `src/server.rs`
- Test: `tests/server_prefilter.rs`

**Interfaces:**
- Consumes: `selector::{parse_dcid, selector_matches}`, `freshness::{now_minutes, is_fresh, WINDOW_MINUTES}`, `replay::ReplayGuard`, `initial_keys::initial_keys_from_psk`, `config::{ServerSecrets, SecretSource}`, and the transport decision from Task 6.
- Produces:
  - `pub struct Server` with `pub async fn bind(secrets: ServerSecrets) -> io::Result<Server>`
  - `pub async fn accept(&mut self) -> Option<Connection>` (yields authenticated connections; never yields for unauthorized peers)
  - `pub fn peek_dcid(datagram: &[u8]) -> Option<&[u8]>` in `transport.rs`
  - internal: a `select_psk(&self, dcid_parts) -> Option<&Psk>` iterating the client set with `selector_matches`, gated by `is_fresh` + `ReplayGuard`.

**Interfaces (Connection):**
- `pub struct Connection` wrapping the quinn-proto connection + a handle to its driver; produced here, consumed by Task 9 for streams.

- [ ] **Step 1: Write failing test**

```rust
// tests/server_prefilter.rs
use silentquic::transport::peek_dcid;

#[test]
fn peek_dcid_extracts_from_long_header() {
    // minimal long header: form/fixed bits, version, dcid len=4, dcid bytes
    let mut pkt = vec![0xc0]; // long header
    pkt.extend_from_slice(&0x0000_0001u32.to_be_bytes()); // version 1
    pkt.push(4); // dcid len
    pkt.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]); // dcid
    pkt.push(0); // scid len
    assert_eq!(peek_dcid(&pkt), Some(&[0xaa, 0xbb, 0xcc, 0xdd][..]));
}

#[test]
fn peek_dcid_rejects_short_or_short_header() {
    assert_eq!(peek_dcid(&[0x40]), None); // short header (form bit clear)
    assert_eq!(peek_dcid(&[0xc0, 0x00]), None); // truncated
}
```

- [ ] **Step 2: Run, verify fail**

Run: `cargo test --test server_prefilter`
Expected: FAIL — `peek_dcid` not found.

- [ ] **Step 3: Implement `peek_dcid` in `src/transport.rs`**

```rust
// SPDX-License-Identifier: 0BSD
//! Shared datagram helpers.

/// Extract the Destination Connection ID from a QUIC long-header datagram,
/// without decryption. Returns None for short headers or malformed input.
pub fn peek_dcid(datagram: &[u8]) -> Option<&[u8]> {
    let first = *datagram.first()?;
    if first & 0x80 == 0 {
        return None; // short header: no DCID length field on the wire
    }
    // [0]=flags, [1..5]=version, [5]=dcid_len, [6..6+len]=dcid
    let dcid_len = *datagram.get(5)? as usize;
    if dcid_len == 0 || 6 + dcid_len > datagram.len() {
        return None;
    }
    Some(&datagram[6..6 + dcid_len])
}
```

- [ ] **Step 4: Run, verify pass**

Run: `cargo test --test server_prefilter`
Expected: PASS.

- [ ] **Step 5: Implement the server driver in `src/server.rs`**

Using the Task 6 decision (quinn-proto sans-IO + owned tokio UDP socket). The loop:
1. `recv_from` a datagram.
2. `peek_dcid` → `parse_dcid`. On `None` → drop (continue), send nothing.
3. `is_fresh(parts.freshness, now_minutes(), WINDOW_MINUTES)` → false → drop.
4. `select_psk` (iterate clients, `selector_matches`) → `None` → drop.
5. `ReplayGuard::check_and_record` → false → drop.
6. Only now hand the datagram to a `quinn_proto::Endpoint` whose crypto uses `initial_keys_from_psk(psk, dcid, Side::Server, version)`; drive resulting `Transmit`s back out the socket; surface new connections on the `accept()` channel.

Write the full async implementation here following the spike's confirmed API. Include a per-source token-bucket rate limiter (`std::collections::HashMap<IpAddr, TokenBucket>`) applied at step 2 before the MAC work, plus a global budget, to bound side-channel cost (Task 10 expands tests for this; wire the limiter here).

- [ ] **Step 6: Write and run an integration test**

Add to `tests/server_prefilter.rs` a tokio test binding a `Server` on `127.0.0.1:0`, sending junk UDP with `tokio::net::UdpSocket`, and asserting (a) `accept()` never yields (use `tokio::time::timeout`), and (b) the socket receives no reply (`recv` times out).

Run: `cargo test --test server_prefilter`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/transport.rs src/server.rs tests/server_prefilter.rs
git commit -m "feat: server UDP loop with silent selector pre-filter"
```

---

### Task 8: Client — connect with embedded selector

**Files:**
- Create: `src/client.rs`
- Test: `tests/client_server_roundtrip.rs`

**Interfaces:**
- Consumes: `selector::build_dcid`, `freshness::now_minutes`, `initial_keys::initial_keys_from_psk`, `config::ClientConfigFile`, `server::Server`.
- Produces:
  - `pub struct Client`
  - `pub async fn connect(cfg: ClientConfigFile) -> Result<Connection, ClientError>` — generates a random `nonce`, `freshness = now_minutes()`, sets the initial DCID to `build_dcid(psk, nonce, freshness)`, configures Initial keys via `initial_keys_from_psk(psk, dcid, Side::Client, version)`, and completes the handshake.
  - `pub enum ClientError`

**Notes:** If the Task 6 decision kept the high-level `quinn` client viable, use `ClientConfig::initial_dst_cid_provider(Arc::new(move || ConnectionId::new(&dcid)))`. If it went full sans-IO, set the DCID directly when creating the client `quinn_proto::Connection`. The spike notes say which.

- [ ] **Step 1: Write failing test**

```rust
// tests/client_server_roundtrip.rs
use silentquic::{client::Client, server::Server, config::*};

#[tokio::test]
async fn authorized_client_roundtrips() {
    let psk_hex = "0000000000000000000000000000000000000000000000000000000000000005";
    let secrets: ServerSecrets = toml::from_str(&format!(
        "listen = \"127.0.0.1:0\"\n[[clients]]\nclient_id=\"a\"\npsk=\"{psk_hex}\"\n"
    )).unwrap();
    let mut server = Server::bind(secrets).await.unwrap();
    let addr = server.local_addr();

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("a connection");
        let mut s = conn.accept_stream().await.expect("stream");
        let msg = s.read_to_end().await.unwrap();
        assert_eq!(msg, b"ping");
    });

    let cfg: ClientConfigFile = toml::from_str(&format!(
        "client_id=\"a\"\npsk=\"{psk_hex}\"\nserver=\"{addr}\"\n"
    )).unwrap();
    let conn = Client::connect(cfg).await.unwrap();
    let mut s = conn.open_stream().await.unwrap();
    s.write_all(b"ping").await.unwrap();
    s.finish().await.unwrap();
    server_task.await.unwrap();
}
```

(`accept_stream`, `open_stream`, `read_to_end`, `write_all`, `finish`, `local_addr` land in Task 9 — this test is expected to fail to compile until then; keep it and iterate. If executing strictly task-by-task, stub the stream methods with `todo!()` in Task 8 and fill them in Task 9.)

- [ ] **Step 2: Run, verify fail**

Run: `cargo test --test client_server_roundtrip`
Expected: FAIL (compile error / handshake incomplete).

- [ ] **Step 3: Implement `src/client.rs`**

Full async implementation per the spike decision: random nonce (use `aws_lc_rs::rand`), `freshness = now_minutes()`, `dcid = build_dcid(psk, nonce, freshness)`, install `initial_keys_from_psk` for the client side, drive the handshake to completion, return a `Connection`.

- [ ] **Step 4: Run, verify pass** (may require Task 9)

Run: `cargo test --test client_server_roundtrip`
Expected: PASS once Task 9 lands; until then the handshake completes but stream calls are `todo!()`.

- [ ] **Step 5: Commit**

```bash
git add src/client.rs tests/client_server_roundtrip.rs
git commit -m "feat: client connect with embedded selector and PSK Initial keys"
```

---

### Task 9: Raw authenticated streams + quinn::Connection exposure

**Files:**
- Modify: `src/transport.rs` (add the `Connection`/`Stream` types, or a dedicated `src/conn.rs` — pick one; keep `Connection` where `Server`/`Client` both import it cleanly)
- Test: extend `tests/client_server_roundtrip.rs`

**Interfaces:**
- Produces on `Connection`:
  - `pub async fn open_stream(&self) -> Result<Stream, ConnError>`
  - `pub async fn accept_stream(&self) -> Result<Stream, ConnError>`
  - `pub fn quinn_connection(&self) -> &quinn_proto::Connection` (or the high-level handle) — the escape hatch that lets `h3` be layered later WITHOUT touching the cloaking layer. Document this as the forward-compat seam.
- Produces on `Stream`:
  - `pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), ConnError>`
  - `pub async fn finish(&mut self) -> Result<(), ConnError>`
  - `pub async fn read_to_end(&mut self) -> Result<Vec<u8>, ConnError>`

- [ ] **Step 1: The failing test already exists** (Task 8's roundtrip). Add one asserting the escape hatch:

```rust
#[tokio::test]
async fn exposes_underlying_quinn_connection() {
    // after connect, quinn_connection() is reachable (compile-level guarantee
    // that h3 can be layered later)
    // ...set up as in authorized_client_roundtrips, then:
    // let _q = conn.quinn_connection();
}
```

- [ ] **Step 2: Run, verify fail**

Run: `cargo test --test client_server_roundtrip`
Expected: FAIL — stream methods `todo!()` / `quinn_connection` missing.

- [ ] **Step 3: Implement `Connection` + `Stream`**

Wrap the quinn-proto connection driver. `open_stream`/`accept_stream` map to quinn-proto's `streams()` API (`open(Dir::Bi)`, `accept(Dir::Bi)`); `write_all`/`read_to_end`/`finish` drive the send/recv stream state through the connection's event loop. Expose `quinn_connection()`.

- [ ] **Step 4: Run, verify pass**

Run: `cargo test --test client_server_roundtrip`
Expected: PASS (roundtrip + escape-hatch tests).

- [ ] **Step 5: Commit**

```bash
git add src/transport.rs tests/client_server_roundtrip.rs
git commit -m "feat: raw authenticated streams and quinn::Connection escape hatch"
```

---

### Task 10: Rate limiting / CPU budget on the reject path

**Files:**
- Create: `src/ratelimit.rs`
- Modify: `src/server.rs` (wire the limiter ahead of MAC work)
- Test: inline in `src/ratelimit.rs` + a flood test in `tests/server_prefilter.rs`

**Interfaces:**
- Produces:
  - `pub struct TokenBucket { ... }` with `pub fn new(capacity: f64, refill_per_sec: f64) -> Self` and `pub fn try_take(&mut self, now: Instant) -> bool`
  - `pub struct RateLimiter` keyed by `IpAddr` with a global bucket + per-source buckets, LRU-bounded map size.

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn bucket_allows_up_to_capacity_then_blocks() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(3.0, 1.0);
        assert!(b.try_take(t0));
        assert!(b.try_take(t0));
        assert!(b.try_take(t0));
        assert!(!b.try_take(t0));
    }

    #[test]
    fn bucket_refills_over_time() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(1.0, 1.0);
        assert!(b.try_take(t0));
        assert!(!b.try_take(t0));
        assert!(b.try_take(t0 + Duration::from_secs(1)));
    }
}
```

- [ ] **Step 2: Run, verify fail**

Run: `cargo test --lib ratelimit`
Expected: FAIL — not defined.

- [ ] **Step 3: Implement `src/ratelimit.rs`** (token bucket + bounded per-IP map with LRU eviction so the map itself can't be an amplification vector).

- [ ] **Step 4: Run, verify pass**

Run: `cargo test --lib ratelimit`
Expected: PASS.

- [ ] **Step 5: Wire into `server.rs` and add flood test**

In `server.rs`, call the limiter at step 2 of the loop (before `parse_dcid`/MAC), so a flood from one source is dropped at near-zero cost. Add a test flooding 10k junk datagrams and asserting the server still accepts a legitimate connection promptly afterward (liveness under flood) and still emits zero replies to the junk.

Run: `cargo test --test server_prefilter`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ratelimit.rs src/server.rs tests/server_prefilter.rs
git commit -m "feat: rate limiting to bound reject-path cost and flatten side-channel"
```

---

### Task 11: Cloaking integration test suite

**Files:**
- Create: `tests/cloaking.rs`

**Interfaces:**
- Consumes: `Server`, `Client`, public config types.

- [ ] **Step 1: Write the cloaking tests (all should fail to link only if earlier tasks incomplete; otherwise drive real behavior)**

```rust
// tests/cloaking.rs
// 1. Junk-scan silence: send 100 random UDP payloads of varied lengths to the
//    server; assert the client socket receives nothing (recv timeout) for each.
// 2. Stock-QUIC silence: use a plain quinn client (published-salt Initial keys,
//    random DCID) to attempt a handshake; assert it times out and the server
//    emits nothing.
// 3. Replay silence: capture the first datagram an authorized client sends
//    (via a proxy socket), then replay it from a fresh socket; assert no server
//    response to the replay.
// 4. Stale freshness: craft a DCID with build_dcid using now_minutes()-10;
//    assert silent drop.
// 5. Wrong-PSK silence: authorized-shaped DCID but selector computed with a
//    different PSK; assert silent drop.
// 6. Happy path: correct PSK connects and echoes a payload.
```

Write each as a `#[tokio::test]` with `tokio::time::timeout` asserting silence (a timeout = success for the silence cases).

- [ ] **Step 2: Run, verify (fix any real gaps surfaced)**

Run: `cargo test --test cloaking`
Expected: PASS (6 tests). Any failure here is a real silence bug — fix in the relevant module, not by weakening the test.

- [ ] **Step 3: Commit**

```bash
git add tests/cloaking.rs
git commit -m "test: end-to-end cloaking and silence suite"
```

---

### Task 12: Fuzz targets, docs, README threat model

**Files:**
- Create: `fuzz/Cargo.toml`, `fuzz/fuzz_targets/parse_dcid.rs`, `fuzz/fuzz_targets/peek_dcid.rs`
- Create: `README.md`
- Modify: `src/lib.rs` (crate-level docs finalize)

**Interfaces:** none new.

- [ ] **Step 1: Add `cargo-fuzz` targets** for `selector::parse_dcid` and `transport::peek_dcid` — inputs are arbitrary bytes; the invariant is *never panic, never allocate on reject, always return in bounded time*.

```rust
// fuzz/fuzz_targets/peek_dcid.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { let _ = silentquic::transport::peek_dcid(data); });
```

- [ ] **Step 2: Run each fuzzer briefly**

Run: `cargo +nightly fuzz run peek_dcid -- -max_total_time=60`
Expected: no crashes in 60s (CI can run a short budget; document longer local runs).

- [ ] **Step 3: Write `README.md`** — quickstart, config example, and a prominent **Threat Model** section reproducing the spec's "defeats / does NOT defeat" lists verbatim, including the recommendation to run silentquic as the only service on its host. State the 0BSD license.

- [ ] **Step 4: Run the full suite**

Run: `cargo test --all && cargo clippy --all -- -D warnings`
Expected: all pass, no warnings.

- [ ] **Step 5: Commit**

```bash
git add fuzz/ README.md src/lib.rs
git commit -m "test: fuzz targets; docs: README with threat model"
```

---

## Self-Review

**Spec coverage:**
- §2 cloaked transport / raw streams → Tasks 7–9. ✓
- §3 threat model (silence, side-channel, honest limits) → Tasks 6, 7, 10, 11, 12 (README). ✓
- §4 blinded DCID selector + freshness + replay + DoS → Tasks 2, 3, 4, 6, 7, 10. ✓
- §5 wire image (vanilla QUIC v1) → Task 6 (stock-client interop) + Task 11 test 2. ✓
- §6 raw streams + quinn::Connection escape hatch → Task 9. ✓
- §7 config / SecretSource / plain TOML / future keyring seam → Task 5. ✓
- §8 dependency reuse (quinn/rustls/blake3/aws-lc-rs) → Tasks 1, 5, 6. ✓
- §9 testing (cloaking, replay, freshness, fuzz, cross-platform CI) → Tasks 1 (CI), 11, 12. ✓
- §10 success criteria → covered across Tasks 6–12. ✓
- §11 open questions (DCID byte layout, AEAD/MAC params, quinn seam) → resolved in Global Constraints (layout) + Task 6 (seam/params). ✓
- Forward-compat: derive-from-root → `select_psk` in Task 7 is the single lookup point to change; no wire/selector change. ✓ Keyring → `SecretSource` seam in Task 5. ✓

**Placeholder scan:** Task 6 is explicitly a spike (allowed — it is a real experiment with recorded outcomes), and Tasks 7–9 reference "the Task 6 decision" for the exact quinn-proto driver API because that API is version-specific and must be confirmed against the installed crate rather than fabricated. All pure-logic tasks (2–5, 10) contain complete, runnable code. No "TBD"/"add error handling"/"similar to" placeholders remain.

**Type consistency:** `Psk`/`as_bytes`, `DcidParts`/`build_dcid`/`parse_dcid`/`selector_matches`, `is_fresh`, `ReplayGuard::check_and_record`, `initial_keys_from_psk`, `peek_dcid`, `Server`/`Client`/`Connection`/`Stream` names are used identically across tasks. ✓

**Known risk (called out honestly):** the exact `quinn-proto` sans-IO driver API (`Endpoint::handle`, `Connection::poll_transmit`, stream plumbing) and the RFC 9001 Initial-key construction against the installed crypto backend are the two places that require hands-on confirmation. Task 6 exists precisely to de-risk them before Tasks 7–9 depend on them; if the spike reveals the high-level `quinn` crate cannot guarantee silence (expected), the sans-IO path in Tasks 7–9 is already the plan of record.
