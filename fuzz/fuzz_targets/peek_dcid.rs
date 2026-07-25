// SPDX-License-Identifier: 0BSD
#![no_main]

use libfuzzer_sys::fuzz_target;

// `transport::peek_dcid` is the very first thing the server driver does with a
// raw inbound UDP datagram (see src/server.rs `on_datagram` / `read_dcid_any`):
// it is called on every packet, authenticated or not, before any other parsing
// or crypto work, so it is the highest-value fuzz target in the crate. The
// invariant under fuzzing: never panic, never over-read past `datagram`'s
// bounds, never allocate on reject, always return in bounded time.
fuzz_target!(|data: &[u8]| {
    let _ = silentquic::transport::peek_dcid(data);
});
