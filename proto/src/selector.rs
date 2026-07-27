// SPDX-License-Identifier: 0BSD
//! Blinded DCID selector: embeds per-client key selection into the QUIC DCID.

pub const CONTEXT: &[u8] = b"silentquic/v1/selector";
pub const DCID_LEN: usize = 20;

#[derive(Clone, Copy, Debug)]
pub struct DcidParts {
    pub nonce: [u8; 8],
    pub freshness: u32,
    pub selector: [u8; 8],
}

pub fn compute_selector(psk: &[u8; 32], nonce: &[u8; 8], freshness: u32) -> [u8; 8] {
    let mut hasher = blake3::Hasher::new_keyed(psk);
    hasher.update(CONTEXT);
    hasher.update(nonce);
    hasher.update(&freshness.to_le_bytes());
    let hash = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash.as_bytes()[..8]);
    out
}

pub fn build_dcid(psk: &[u8; 32], nonce: [u8; 8], freshness: u32) -> [u8; 20] {
    let selector = compute_selector(psk, &nonce, freshness);
    let mut dcid = [0u8; 20];
    dcid[..8].copy_from_slice(&nonce);
    dcid[8..12].copy_from_slice(&freshness.to_le_bytes());
    dcid[12..20].copy_from_slice(&selector);
    dcid
}

pub fn parse_dcid(dcid: &[u8]) -> Option<DcidParts> {
    if dcid.len() != DCID_LEN {
        return None;
    }
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&dcid[..8]);
    let freshness = u32::from_le_bytes(dcid[8..12].try_into().ok()?);
    let mut selector = [0u8; 8];
    selector.copy_from_slice(&dcid[12..20]);
    Some(DcidParts {
        nonce,
        freshness,
        selector,
    })
}

pub fn selector_matches(psk: &[u8; 32], parts: &DcidParts) -> bool {
    let expected = compute_selector(psk, &parts.nonce, parts.freshness);
    // constant-time compare
    let diff = expected
        .iter()
        .zip(parts.selector.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_is_deterministic_for_same_inputs() {
        let psk = [7u8; 32];
        let nonce = [1u8; 8];
        let a = compute_selector(&psk, &nonce, 100);
        let b = compute_selector(&psk, &nonce, 100);
        assert_eq!(a, b);
    }

    #[test]
    fn selector_differs_across_psk_nonce_freshness() {
        let base = compute_selector(&[7u8; 32], &[1u8; 8], 100);
        assert_ne!(base, compute_selector(&[8u8; 32], &[1u8; 8], 100));
        assert_ne!(base, compute_selector(&[7u8; 32], &[2u8; 8], 100));
        assert_ne!(base, compute_selector(&[7u8; 32], &[1u8; 8], 101));
    }

    #[test]
    fn build_then_parse_roundtrips() {
        let psk = [42u8; 32];
        let dcid = build_dcid(&psk, [9u8; 8], 12345);
        assert_eq!(dcid.len(), DCID_LEN);
        let parts = parse_dcid(&dcid).expect("parse");
        assert_eq!(parts.nonce, [9u8; 8]);
        assert_eq!(parts.freshness, 12345);
        assert!(selector_matches(&psk, &parts));
    }

    #[test]
    fn wrong_psk_does_not_match() {
        let dcid = build_dcid(&[1u8; 32], [9u8; 8], 12345);
        let parts = parse_dcid(&dcid).unwrap();
        assert!(!selector_matches(&[2u8; 32], &parts));
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(parse_dcid(&[0u8; 8]).is_none());
        assert!(parse_dcid(&[0u8; 19]).is_none());
        assert!(parse_dcid(&[0u8; 21]).is_none());
    }

    #[test]
    fn selector_known_answer_vector() {
        // Known-answer vector: pins the canonical wire format. If this breaks,
        // the on-wire selector changed — that's a breaking protocol change, not
        // a test to update blindly. The client↔server symmetry tests would stay
        // green even if the input order or endianness of `compute_selector`
        // changed (both sides would shift together), silently altering the wire
        // image; this hardcoded vector is what actually catches that.
        let psk = [7u8; 32];
        let nonce = [1u8; 8];
        let freshness: u32 = 100;
        const EXPECTED: [u8; 8] = [68, 97, 187, 227, 192, 229, 195, 215];
        assert_eq!(compute_selector(&psk, &nonce, freshness), EXPECTED);
    }
}
