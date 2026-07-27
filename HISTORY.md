# History and durable decisions

This repository starts with a clean snapshot split from a larger mother
repository in July 2026. The mother repository retains the detailed commit
history; this document preserves the reasoning future maintainers need.
Documents under `docs/` are preserved design records and may mention their
original monorepo paths or sibling projects.

## Why the project was renamed

The project and crates were originally published as `silentquic` and
`silentquic-proto`. They were renamed to `quietquic` and `quietquic-proto`
before the next prerelease to avoid confusion with the unrelated Rust crate
`silent-quic`.

The rename covers the repository, crate packages, Rust import paths,
documentation, and protocol domain-separation string. Changing the protocol
context intentionally changes the wire-format known-answer vectors, so the
renamed release is a distinct experimental protocol identity rather than an
alias for the original crates.

## Why QuietQUIC exists

The project began as transport research for a backup system. A normal public
QUIC listener reveals itself to unauthorized probes. QuietQUIC instead
requires proof of a per-client PSK in the first QUIC Initial and emits zero
bytes for traffic that fails the pre-filter.

The selector is carried in the Destination Connection ID, uses keyed BLAKE3,
includes freshness and replay material, and selects the client's PSK before
connection state is allocated. QUIC Initial keys are derived using the PSK in
place of the public QUIC salt. This preserves a QUIC-like wire image but cannot
hide from sophisticated DPI that attempts to decrypt every Initial; that
threat-model boundary is fundamental and must remain explicit.

## Silence is an API invariant

The reject path was deliberately placed before `quinn-proto`. In the sans-I/O
core, a rejected datagram queues no transmit, so even an embedding application's
control flow cannot accidentally reply. Tests cover junk, malformed selectors,
unknown clients, bad MACs, stale timestamps, replay, and rate-limit behavior.
Known-answer vectors lock the selector and Initial-key wire formats.

Never make the selector DCID an active routing identifier merely to accept a
retransmitted Initial. A captured Initial could then elicit a response and
break replay silence. The current client fixes its selector for an attempt;
duplicate Initials are rejected and early-flight recovery leans on the
server's PTO. Any refinement must preserve capture-replay silence.

## Why there are two crates

The first implementation directly owned Tokio UDP sockets. It was later split
into `quietquic-proto` and the Tokio wrapper, following the
`quinn-proto`/`quinn` layering model. The core performs no I/O, owns no runtime,
starts no threads, reads no clock, and accepts `now` from its caller. This is
required for hand-rolled zero-timeout event loops and FFI embedding. CI runs
the reference polling example and checks that the core does not acquire Tokio.

The core's loop ordering matters: process queued events and connection work
before trusting the next timeout. A dirty flag was added so progress is robust
even when an embedder's loop is imperfect. Connection handles are reusable
only after drained state has been fully reaped.

## Connection and routing corrections

Several implementation bugs established durable invariants:

- Issued and orphaned CIDs must be removed on all failure and drain paths.
- A full application accept channel must never block the network driver.
- Locally closing a `quinn-proto` connection does not necessarily yield
  `ConnectionLost`; drivers also reap when `is_drained()` becomes true.
- Client connect has an internal timeout.
- Client source binding is optional, preserves ephemeral binding by default,
  and rejects address-family mismatches early.
- Reject-path rate limiting is bounded and allocation-conscious. Its defaults
  are currently compile-time constants.

## Stream API decision

The original Tokio API exposed only unbounded `read_to_end`, which both risks
memory exhaustion and forced bespoke parked-read state. Incremental bounded
`read(max)` and split receive/send handles were added when `squicusock` needed
interactive full-duplex forwarding. The Tokio wrapper now offers
`read_to_end(limit)` as a bounded convenience over the incremental core path.
The remaining direction is to implement standard async read/write traits. The
sans-I/O core already has the correct incremental model.

## Validation record

The post-split source descends from a tree tested on macOS, Linux/musl, and
FreeBSD. Cross-host UDP tests exercised both client/server directions, optional
source-port pinning, payload echo, and the no-reply invariant for unauthorized
junk. Infrastructure failures during that work demonstrated an important test
rule: prove the plain UDP path and prove the server actually started before
attributing a timeout to the protocol.

## Repository separation

The Ruby gem was separated because it has its own API, runtime bridge,
packaging, and release lifecycle. The backup application remains transport
agnostic. `squicusock`, a proposed Unix-domain-socket relay over QuietQUIC, is
also its own project despite depending on this library.
