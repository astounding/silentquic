# Project status

QuietQUIC is an implemented Rust transport with two crates:

- `quietquic-proto`, the sans-I/O state machine in `proto/`;
- `quietquic`, the Tokio socket-owning wrapper at the repository root.

The cloaking, replay, rate-limit, connection lifecycle, stream, fuzz, and
cross-host test work described in [HISTORY.md](HISTORY.md) has been completed.
Known limitations and the threat boundary are documented in [README.md](README.md).

## Release status

Version `0.1.0-alpha.2` is the first prerelease prepared under the QuietQUIC
crate names. The version was advanced instead of reusing the existing
`v0.1.0-alpha.1` tag and former-name publication identity. It remains an
experimental preview, not a production-hardening claim. Public connection
handles are generation-safe, accepted server connections expose their
PSK-derived `client_id`, and `read_to_end` requires an explicit memory bound.

The Ruby binding, backup application, and `squicusock` relay are maintained as
independent projects.
