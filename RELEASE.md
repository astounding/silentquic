# Release checklist

1. Confirm the repository URL and security-reporting address are current in
   both manifests and `SECURITY.md`.
2. Remove `unreleased` from the changelog entry and set its date.
3. Confirm both manifests use the same version and the wrapper pins the core.
   Confirm the supported compiler is Rust 1.88 or newer.
4. Run:

   ```sh
   cargo fmt --all -- --check
   cargo test --workspace --all-targets
   cargo test --workspace --doc
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
   cargo package -p quietquic-proto
   cargo deny check
   ```

   For the first public release of the renamed `quietquic-proto` crate, the
   wrapper package cannot verify until the exact pinned core version is visible
   in the crates.io index. In that bootstrap case, publish
   `quietquic-proto` first, wait for indexing, then run
   `cargo package -p quietquic` before publishing `quietquic`.

5. Run dependency vulnerability, license, and source-policy checks.
6. Inspect `cargo package --list` for each crate.
7. Install both `.crate` archives into fresh temporary consumers.
8. Run the polling example and a two-host UDP round trip on supported systems.
9. Tag the exact tested commit.
10. Publish `quietquic-proto` first; after crates.io indexes it, publish
    `quietquic`.
11. Confirm both docs.rs builds and all package links.
