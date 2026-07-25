# Project status

SilentQUIC is an implemented Rust transport with two crates:

- `silentquic-proto`, the sans-I/O state machine in `proto/`;
- `silentquic`, the Tokio socket-owning wrapper at the repository root.

The cloaking, replay, rate-limit, connection lifecycle, stream, fuzz, and
cross-host test work described in [HISTORY.md](HISTORY.md) has been completed.
Known limitations and the threat boundary are documented in [README.md](README.md).

## Planned work

- Add incremental reads and `AsyncRead`/`AsyncWrite`-style split stream APIs.
- Make `read_to_end` require a size limit and implement it over incremental
  reads.
- Delete the Tokio layer's bespoke parked-read machinery once incremental
  reads exist.
- Consider configurable reject-path rate limits and improved early-flight loss
  recovery without weakening replay silence.
- Consider a C FFI over `silentquic-proto`.

The Ruby binding, backup application, and `squicusock` relay are maintained as
independent projects.
