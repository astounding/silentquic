# Changelog

All notable user-visible changes are recorded here. This project follows
Semantic Versioning while its wire protocol and Rust API remain experimental.

## 0.1.0-alpha.1 — unreleased

- Split the Sans-I/O protocol core (`silentquic-proto`) from the Tokio wrapper.
- Enforce silent rejection before allocating QUIC connection state.
- Add freshness, replay protection, bounded global/per-source rate limiting,
  known-answer vectors, fuzz targets, and cross-platform CI.
- Add incremental and split stream I/O.
- Require an explicit limit for `Stream::read_to_end`.
- Attach the server-configured client identity to accepted connections and
  reject duplicate identities or PSKs.
- Replace reusable raw Quinn connection handles with generation-safe handles.
- Replace the reject-path vector LRU with an O(1) intrusive LRU.
