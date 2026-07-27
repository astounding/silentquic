# Project status

SilentQUIC is an implemented Rust transport with two crates:

- `silentquic-proto`, the sans-I/O state machine in `proto/`;
- `silentquic`, the Tokio socket-owning wrapper at the repository root.

The cloaking, replay, rate-limit, connection lifecycle, stream, fuzz, and
cross-host test work described in [HISTORY.md](HISTORY.md) has been completed.
Known limitations and the threat boundary are documented in [README.md](README.md).

## Planned work

- Add standard `AsyncRead`/`AsyncWrite` trait implementations around the
  incremental split stream handles.
- Consider configurable reject-path rate limits and improved early-flight loss
  recovery without weakening replay silence.
- Consider a C FFI over `silentquic-proto`.

## Release status

The next release is `0.1.0-alpha.1`. It is an experimental preview, not a
production-hardening claim. Public connection handles are generation-safe,
accepted server connections expose their PSK-derived `client_id`, and
`read_to_end` requires an explicit memory bound.

The Ruby binding, backup application, and `squicusock` relay are maintained as
independent projects.
