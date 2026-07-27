# Documentation map

- [`specs/wire-protocol.md`](specs/wire-protocol.md) is the normative wire
  protocol for the current experimental release.
- The root [`README.md`](../README.md) is the current user guide, API overview,
  threat model, and limitations list.
- [`../SECURITY.md`](../SECURITY.md) states security status and reporting policy.
- Files under `plans/` are archived implementation plans. They intentionally
  preserve intermediate APIs, `todo!()` examples, and expected-failure notes;
  they are not current usage documentation.
- Dated files under `specs/` and `notes/` are historical design records unless
  the current wire-protocol document explicitly incorporates them.

When historical text conflicts with current API documentation or code, the
current Rust API and normative wire-protocol document take precedence.
