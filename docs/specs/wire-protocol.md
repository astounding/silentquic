# QuietQUIC wire protocol

Status: normative for the `0.1.x` experimental protocol. Multi-byte integer
encoding and domain-separation inputs are locked by known-answer tests.

## Selector destination connection ID

The first client Initial uses a 20-byte destination connection ID:

```text
nonce[8] || freshness_minute_le[4] || selector[8]
```

`nonce` is generated with the operating system cryptographic RNG.
`freshness_minute` is Unix time divided by 60 and encoded little-endian.
`selector` is the first eight bytes of keyed BLAKE3 over the implementation's
pinned domain-separation input, nonce, and freshness bytes. See
`proto/src/selector.rs`; its known-answer vector is the compatibility authority.

Server configuration requires unique PSKs. The matching PSK therefore selects
exactly one configured `client_id`; the identifier itself is not transmitted.

## Freshness and replay

The server accepts selectors within `WINDOW_MINUTES` of its wall clock,
including both past and future bounds. After a selector matches a PSK, the
server records `(nonce, freshness_minute)` in that client's replay guard.
Repeats are dropped silently. Expired entries are removed as the guard is
used.

## Initial protection

QUIC v1 Initial header and packet keys are derived from the 32-byte PSK in
place of QUIC's public version salt. Labels, key lengths, directionality, and
packet construction are defined in `proto/src/initial_keys.rs` and pinned by
known-answer vectors. After the Initial level, ordinary QUIC/TLS 1.3 key
schedule processing applies.

The TLS certificate is ephemeral and is not verified. The protocol's
authentication claim therefore depends on possession of the PSK and on the
correctness and transcript binding of the customized Initial construction.
This claim requires independent review before a production release.

## Silence invariant

On a server, a datagram whose destination connection ID is not an active
connection ID must pass, in order:

1. global and per-source rate limiting;
2. long-header and exact-length parsing;
3. freshness validation;
4. PSK selector matching;
5. replay rejection.

Failure at any stage returns before the datagram reaches Quinn, allocates no
connection state, and queues no transmit. Already-authenticated connection IDs
bypass this admission filter.

Documented exceptions and threat boundaries—including captured live or retired
connection IDs and sophisticated DPI—are listed in the README.

## Compatibility

Changes to the selector layout, byte order, domain-separation inputs, Initial
key derivation, or acceptance window semantics are wire-protocol changes.
Known-answer test failures must not be updated without an explicit protocol
versioning decision.
