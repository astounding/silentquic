# Security policy

## Release status

QuietQUIC `0.1.x` is experimental security software. Its implementation has
extensive automated tests, known-answer vectors, and fuzz targets, but the
protocol has not yet received an independent cryptographic review. It should
not be represented as production-hardened.

Read the threat model and limitations in [README.md](README.md) before
deployment. Scanner silence does not protect against global passive traffic
analysis, sophisticated QUIC Initial decryption attempts, host compromise, or
denial of service.

## Reporting a vulnerability

Do not open a public issue containing exploit details. Email reports privately
to [quietquic.astounding@sierrasand.com](mailto:quietquic.astounding@sierrasand.com).

Include affected versions, reproduction steps, expected impact, and whether
the issue can violate the no-reply invariant. Please allow up to five business
days for an initial acknowledgment. This is a response target, not a guarantee;
if no acknowledgment arrives, resend the report with `FOLLOW-UP` in the subject.

## Supported versions

Before the first stable release, only the newest published alpha is supported.
