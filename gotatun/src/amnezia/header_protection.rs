//! AWG 3.0 header protection: raw ChaCha20 over the start of each message.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};

use super::config::HEADER_PROTECTION_KEY_SIZE;

/// Nonce size; taken from the first bytes of the random padding prefix.
pub(crate) const HEADER_PROTECTION_NONCE_SIZE: usize = 12;
/// Length of the keystream mask (the largest protected span, the initiation).
pub(crate) const HEADER_PROTECTION_MASK_LEN: usize = 148;

/// Protected span of a handshake initiation.
pub(crate) const PROTECTED_LEN_INIT: usize = 148;
/// Protected span of a handshake response.
pub(crate) const PROTECTED_LEN_RESPONSE: usize = 92;
/// Protected span of a cookie reply.
pub(crate) const PROTECTED_LEN_COOKIE: usize = 64;
/// Protected span of a transport packet (its header).
pub(crate) const PROTECTED_LEN_TRANSPORT: usize = 16;

/// Header protection cipher. Mirrors amneziawg-go's `HeaderProtectionCipher`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeaderProtection {
    key: [u8; HEADER_PROTECTION_KEY_SIZE],
}

impl std::fmt::Debug for HeaderProtection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HeaderProtection(..)")
    }
}

impl HeaderProtection {
    pub(crate) fn new(key: [u8; HEADER_PROTECTION_KEY_SIZE]) -> Self {
        HeaderProtection { key }
    }

    /// The first 148 ChaCha20 keystream bytes (block counter 0) for `nonce12`.
    pub(crate) fn mask(&self, nonce12: &[u8; HEADER_PROTECTION_NONCE_SIZE]) -> [u8; 148] {
        let mut mask = [0u8; HEADER_PROTECTION_MASK_LEN];
        let mut cipher = ChaCha20::new((&self.key).into(), nonce12.into());
        cipher.apply_keystream(&mut mask);
        mask
    }

    /// XOR the first `protected_len` bytes of `msg` (clamped to its length and
    /// to 148) with the mask for the nonce in `prefix[..12]`. Self-inverse.
    ///
    /// # Panics
    /// Panics if `prefix` is shorter than 12 bytes; config validation
    /// (S1..S4 >= 12) rules that out for real packets.
    pub(crate) fn apply(&self, prefix: &[u8], msg: &mut [u8], protected_len: usize) {
        let nonce: &[u8; HEADER_PROTECTION_NONCE_SIZE] = prefix[..HEADER_PROTECTION_NONCE_SIZE]
            .try_into()
            .expect("slice has nonce length");
        let mask = self.mask(nonce);
        let n = protected_len.min(msg.len()).min(HEADER_PROTECTION_MASK_LEN);
        for (b, m) in msg[..n].iter_mut().zip(mask) {
            *b ^= m;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_protection_known_answer() {
        // RFC 8439 A.1 test vector #1: zero key, zero nonce, counter 0.
        let hp = HeaderProtection::new([0u8; HEADER_PROTECTION_KEY_SIZE]);
        let mask = hp.mask(&[0u8; 12]);
        let expected: [u8; 64] = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24,
            0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
        ];
        assert_eq!(&mask[..64], &expected);

        let mut msg = [0u8; 64];
        hp.apply(&[0u8; 12], &mut msg, 64);
        assert_eq!(msg, expected);
    }

    #[test]
    fn apply_round_trips_and_respects_span() {
        let hp = HeaderProtection::new([0x42; HEADER_PROTECTION_KEY_SIZE]);
        let prefix: Vec<u8> = (0..16).collect();
        let plain = [0x11u8; 40];
        let mut msg = plain;
        hp.apply(&prefix, &mut msg, PROTECTED_LEN_TRANSPORT);
        assert_ne!(msg[..16], plain[..16]);
        assert_eq!(msg[16..], plain[16..], "bytes past the span stay clear");
        hp.apply(&prefix, &mut msg, PROTECTED_LEN_TRANSPORT);
        assert_eq!(msg, plain);

        // A span longer than the message is clamped, not a panic.
        let mut short = [0u8; 8];
        hp.apply(&prefix, &mut short, PROTECTED_LEN_INIT);
    }
}
