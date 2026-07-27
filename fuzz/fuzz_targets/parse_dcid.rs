// SPDX-License-Identifier: 0BSD
#![no_main]

use libfuzzer_sys::fuzz_target;

// `selector::parse_dcid` is the first structured parse of attacker-controlled
// bytes on the silence pre-filter path (see src/server.rs `prefilter`): every
// inbound datagram whose DCID is not already an active connection's CID is
// routed through here before any crypto work. The invariant under fuzzing is
// the same invariant the pre-filter design relies on: never panic, never
// allocate on reject (it only ever copies into fixed-size stack arrays), and
// always return in bounded time (no loops, pure slice indexing via `Option`).
fuzz_target!(|data: &[u8]| {
    let _ = quietquic::selector::parse_dcid(data);
});
