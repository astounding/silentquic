// SPDX-License-Identifier: 0BSD
//! Cloaked QUIC transport plumbing shared by client and server.
//!
//! The datagram helper here — [`peek_dcid`] — is the first gate of the silent
//! pre-filter: a pure, allocation-free long-header parser that lets the server
//! read a packet's Destination Connection ID *without decryption*, so it can
//! decide whether to admit the datagram to the endpoint state machine at all.

/// Extract the Destination Connection ID from a QUIC long-header datagram,
/// without decryption. Returns `None` for short headers or malformed input.
///
/// Long header layout (RFC 9000 §17.2):
/// ```text
///   byte0:         1 f x x x x x x   (high bit = long-header form)
///   bytes1..5:     version (4 bytes, big-endian)
///   byte5:         DCID length (u8)
///   bytes6..6+len: DCID
/// ```
/// Short-header packets carry no on-wire DCID length field, so they cannot be
/// parsed here and are rejected — the router handles them by matching against
/// the set of already-active connection CIDs instead.
pub fn peek_dcid(datagram: &[u8]) -> Option<&[u8]> {
    let first = *datagram.first()?;
    if first & 0x80 == 0 {
        return None; // short header: no DCID length field on the wire
    }
    // [0]=flags, [1..5]=version, [5]=dcid_len, [6..6+len]=dcid
    let dcid_len = *datagram.get(5)? as usize;
    // A QUIC CID is at most 20 bytes (RFC 9000 §17.2); reject anything longer
    // or a zero-length CID (which our selector layout can never produce).
    if dcid_len == 0 || dcid_len > 20 {
        return None;
    }
    let end = 6 + dcid_len;
    if end > datagram.len() {
        return None;
    }
    Some(&datagram[6..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert_eq!(peek_dcid(&[]), None);
    }

    #[test]
    fn rejects_oversized_dcid_len() {
        // dcid_len = 21 is illegal per RFC 9000.
        let pkt = vec![0xc0, 0, 0, 0, 1, 21];
        assert_eq!(peek_dcid(&pkt), None);
    }

    #[test]
    fn rejects_truncated_dcid() {
        // Claims 4-byte DCID but only supplies 2.
        let pkt = vec![0xc0, 0, 0, 0, 1, 4, 0xaa, 0xbb];
        assert_eq!(peek_dcid(&pkt), None);
    }
}
