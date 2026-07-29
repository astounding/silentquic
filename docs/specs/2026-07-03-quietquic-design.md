# quietquic — Design Spec

**Date:** 2026-07-03
**Status:** Approved design, pre-implementation
**License:** 0BSD (BSD Zero Clause)
**Language:** Rust

---

## 1. Context & Relationship to the Larger Effort

This is **Project A** of a two-project effort. The projects are deliberately
separated along a thin, one-directional interface:

- **Project A — `quietquic` (this spec):** a standalone Rust library providing a
  *cloaked* QUIC transport. A server built on it is invisible to network scanners
  and its traffic camouflages as ordinary QUIC/HTTP3. It authenticates and selects
  a per-client pre-shared key (PSK) entirely within the QUIC `Initial` packet, then
  exposes plain authenticated byte streams. **It contains no backup logic.**

- **Project B — the backup system (separate spec, later):** a zero-knowledge,
  deduplicating backup tool (borg/tarsnap/restic-inspired). It consumes `quietquic`
  as its *flagship* transport through a narrow transport trait, alongside portable
  transports (SFTP/WebDAV/SMB/S3/local via OpenDAL).

The dependency is **one-directional and late-binding**: Project B depends on
Project A only through a `send bytes / open stream` abstraction, so B can be built
and hardened against portable transports first and adopt `quietquic` when ready.
Project A is designed and built first because it carries the highest technical risk
(mangling QUIC's `Initial` derivation cleanly) and has a crisp, provable success
test independent of any backup code.

---

## 2. Purpose & Scope

`quietquic` provides a **cloaked QUIC transport library**:

- A server that emits **zero bytes** in response to any packet that does not prove
  possession of a valid PSK — indistinguishable from a closed/filtered UDP port to a
  scanner.
- Traffic that **camouflages as ordinary QUIC v1** (standard version field, long-header
  format, UDP/443), blending into the large volume of legitimate internet QUIC/HTTP3.
- Per-client PSK authentication and key *selection* folded into the QUIC `Initial`
  packet, before any connection state is allocated.
- A minimal API exposing **raw authenticated bidirectional byte streams**, with the
  underlying `quinn::Connection` reachable so higher layers (e.g. HTTP/3) can be added
  later without modifying the cloaking layer.

### Non-Goals (v1)

- **No HTTP/3 in v1.** The design keeps standard QUIC on the wire specifically so the
  off-the-shelf `h3` crate can be stacked on top later with no library change, but h3
  is not implemented here.
- **No certificate-based authentication.** PSK only. (The cert path was the weaker
  cloaking option and is explicitly abandoned.)
- **No protection against a resourced adversary** who can flood the host and observe a
  *co-located* service's latency, nor against a global passive traffic-analysis
  adversary. See Threat Model.

---

## 3. Threat Model

Stated plainly, and to be reproduced in the library's user-facing docs so no operator
over-trusts it.

### What quietquic defeats

- **Internet-wide active scanning** (nmap, zmap, masscan) and search engines
  (Shodan, Censys): the server never responds to an unauthorized probe, so it appears
  as a closed/filtered UDP port. UDP has no kernel-level handshake to refuse, so the
  silence is complete — no RST, no distinguishable timeout, no TLS alert.
- **Netflow / flow-log classification** and **casual DPI**: traffic looks like a normal
  QUIC connection to some IP on UDP/443.

### What quietquic does NOT defeat

- **Global passive traffic analysis.** Backups are large and periodic; the *volume and
  timing pattern* of traffic to a fixed endpoint leaks even when service identity and
  content do not. No packet-level trick hides this.
- **Sophisticated DPI that actively attempts `Initial` decryption on every flow.** In
  stock QUIC, the `Initial` packet is protected with keys derived from a *published*
  version salt plus the on-wire Destination Connection ID (DCID), so any observer can
  unseal it and read the TLS ClientHello. Because quietquic **re-keys the `Initial`
  with the PSK**, such an observer's unseal attempt produces garbage — revealing
  "QUIC whose Initial won't decrypt," an anomaly resembling an unknown/broken QUIC
  variant. This is the irreducible cost of folding authentication into the `Initial`;
  it cannot be avoided without surrendering auth secrecy. It is a non-issue against
  scanning and casual detection, and no packet-level design defeats an adversary
  already decrypting every QUIC `Initial` on the link.
- **Resource side-channel via a co-located service.** Even a silent server consumes
  CPU/memory to process-then-drop junk packets. An attacker flooding the host and
  watching an *unrelated* co-located service's latency can infer that something is
  doing per-packet crypto work. Mitigations (below) bound and flatten this channel but
  cannot close it. **Recommended deployment: quietquic is the only service on its
  host.**

---

## 4. Authentication & the Blinded DCID Selector

The core mechanism. Authentication and per-client key selection are folded into the
client's first packet so that unauthorized traffic is rejected at minimal cost with no
response.

### Construction

- The client chooses its Destination Connection ID as:

  ```
  DCID = nonce(8) ‖ freshness(4, u32 LE) ‖ selector(8)   # 20 bytes total
  selector = keyed-BLAKE3(psk, context ‖ nonce ‖ freshness)
  ```

  where `nonce` is fresh random bytes per connection, `freshness` is a coarse timestamp,
  and `context` is a fixed domain-separation string (`b"quietquic/v1/selector"`). The
  MAC input order (context first) is canonical and fixed by the implementation; the
  server recomputes it identically.

- On each inbound `Initial`, the server:
  1. Parses `nonce` and `freshness` from the DCID; rejects out-of-window `freshness`
     immediately (silent drop).
  2. Recomputes `keyed-BLAKE3(psk_i, context ‖ nonce ‖ freshness)` for each known PSK `psk_i`
     and compares to the packet's `selector` — a **cheap MAC compare** to *select* the
     candidate key. No match across all keys → **silent drop**, with no allocation and
     no QUIC state created.
  3. On a selector match, **re-keys the QUIC `Initial` protection with the selected PSK**
     and AEAD-unseals the packet to **verify** possession. Failure → silent drop.

### Replay protection

- The `freshness` stamp plus a short-lived **seen-nonce set** within the acceptance
  window prevents a captured valid `Initial` from being replayed to elicit a server
  response. This preserves silence against an active capture-and-replay adversary.

### DoS posture & side-channel flattening

- Unauthorized junk dies at O(number-of-keys) **cheap MAC compares**, never at
  expensive AEAD unseals (contrast with a naive "try to unseal against every key"
  design, whose amplification factor makes the resource side-channel far worse).
- **Per-source and global rate limits / a CPU budget** bound the work spent on
  unauthenticated packets, producing predictable, flat resource usage that minimizes
  the co-located-service side-channel.
- The reject path performs no heap allocation and avoids secret-dependent branching
  beyond the bounded compare.

### Forward compatibility: derive-from-root (future)

The current model is **per-client PSKs**: the server holds an explicit set. The selector
already carries per-client identity implicitly. A future **derive-from-root** scheme
(`psk = HKDF(root, client_id)`; revoke via blocklist; back up only the root) is a
**localized change to key lookup only** — the server would recompute a candidate key
instead of iterating a stored set. It requires **no change to the wire format or the
selector construction**. The design must not foreclose this.

---

## 5. Wire Image

- Standard **QUIC v1** version field, long-header format, default **UDP/443** (port
  configurable). To netflow logs and casual DPI, traffic is indistinguishable from an
  ordinary QUIC/HTTP3 connection.
- The **only** deviation from stock QUIC is the `Initial` *protection keying*
  (PSK-rekeyed instead of published-salt-keyed). Everything after the handshake is an
  ordinary QUIC connection.
- Rationale (the obfs4/Snowflake lesson): "look like something ubiquitous" beats "look
  like nothing." Unrecognizable-protocol UDP on a fixed port is itself the anomaly that
  draws attention; blending into the QUIC cover-traffic sea is stronger cloaking.

---

## 6. API Surface

- `open_bi()` / `accept_bi()` return split send/receive halves for
  **bidirectional authenticated byte streams**. The consumer (e.g. the backup
  protocol) supplies its own framing.
- The underlying **`quinn::Connection` remains reachable**, so `h3` or any other
  stream protocol can be layered later **without modifying the cloaking layer**.
- **Architectural principle:** *cloaking is a property of connection establishment
  only.* quietquic re-keys the `Initial`, authenticates via the blinded DCID selector,
  and drops silently — but once a connection is established it is ordinary QUIC.
- **Async runtime: tokio** (quinn's runtime; the practical default). The reject path
  remains cheap and bounded regardless of runtime.
- Errors surface as typed connection/stream errors. Unauthorized peers never produce a
  connection object at all.

---

## 7. Configuration & Secret Handling

- **v1:** plain **TOML**, `chmod 600`. The server config holds `client-id → psk`
  entries plus listen parameters; a client config holds its own `client-id`, `psk`, and
  server endpoint. Human-readable, cleartext-on-disk — the same security posture as an
  SSH `authorized_keys` file or a WireGuard config. Docs instruct operators to protect
  the file.
- **Secret-source seam:** secret loading goes through a `SecretSource` trait with one
  v1 implementation, `FileSource`.
- **Future:** an optional, feature-gated `KeyringSource` for platforms with solid
  keyrings (macOS Keychain, Linux Secret Service), skipped where support is weak (e.g.
  FreeBSD). The **plain-file / non-keyring source always remains available on every
  platform**, so keyring is a pure add-on and never a requirement.

---

## 8. Build Strategy & Dependencies

All reused code is BSD/MIT/ISC/Apache-2.0-friendly; everything originated here is 0BSD.
Snippets lifted from Apache-2.0 files retain their notices for those portions.

- **`quinn` + `rustls`** (`Apache-2.0 OR MIT`) for QUIC/TLS 1.3. We reach into the
  `Initial` key derivation to re-key it with the PSK. **Keep the "mangle" as thin as
  possible:** re-key the existing derivation and change nothing else, so quinn/rustls's
  tested paths continue to run. A mistake in this corner is a crypto bug in the most
  security-sensitive part of the system.
- **Selector MAC:** keyed BLAKE3 or HMAC.
- **AEAD** for the re-keyed `Initial`: the construction matching QUIC's own.
- **tokio** for async.

---

## 9. Testing Strategy

A security library; the test suite is a headline deliverable, not an afterthought.

- **Cloaking proof (integration):** probe the listener with (a) junk packets, (b) a
  stock QUIC client without the PSK, and assert **zero bytes are returned** in every
  case; assert that only a PSK-holding client completes a handshake and exchanges data.
- **Replay test:** capture a valid `Initial`, replay it, assert **silent drop** (no
  server response).
- **Freshness test:** out-of-window `freshness` → silent drop.
- **Property / fuzz tests:** malformed DCIDs and `Initial` packets must never panic,
  never leak timing beyond the bounded reject path, and never allocate on the reject
  path. Fuzz the selector parser and the Initial re-keying.
- **DoS / rate-limit tests:** floods of unauthenticated packets stay within the
  configured CPU/rate budget.
- **Cross-platform CI:** Linux + macOS native runners; **FreeBSD** via a VM/CI runner
  (e.g. Cirrus-style), since FreeBSD is a first-class target.

---

## 10. Success Criteria

1. A `quietquic` server, scanned by nmap/zmap/masscan and probed by a stock QUIC
   client, returns **zero bytes** and is indistinguishable from a closed UDP port.
2. A client holding a valid PSK establishes a connection and exchanges data over
   bidirectional streams.
3. Captured-`Initial` replay and out-of-window packets are silently dropped.
4. Unauthorized-packet floods stay within a bounded, configurable resource budget.
5. Builds and passes tests on Linux, macOS, and FreeBSD.
6. The underlying `quinn::Connection` is reachable such that `h3` can be layered on top
   in a follow-up without changes to the cloaking layer.
7. Per-client PSKs today; a future derive-from-root scheme requires no wire-format or
   selector change.

---

## 11. Open Questions / Deferred

- Exact byte layout and sizing of `nonce`, `freshness`, and `selector` within the DCID
  (bounded by QUIC's max CID length of 20 bytes) — to be fixed in the implementation
  plan.
- Precise AEAD/MAC primitive parameters and the exact seam in quinn/rustls where the
  `Initial` re-keying hooks in — to be determined during the implementation plan's
  first spike.
- Concrete rate-limit / CPU-budget defaults.
