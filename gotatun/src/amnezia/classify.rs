//! Receive boundary: classify an inbound datagram and turn it back into a
//! plain-looking WireGuard message.
//!
//! A receiver must classify a datagram before it knows which peer it belongs
//! to, so this only needs the device-wide [`AmneziaConfig`]. Mirrors
//! amneziawg-go's `DeterminePacketTypeAndPadding` and awgtun's
//! `PacketClassifier`.

use std::sync::Arc;

use bytes::Buf;

use super::config::{AmneziaConfig, HeaderRange};
use super::header_protection::{
    HEADER_PROTECTION_MASK_LEN, HEADER_PROTECTION_NONCE_SIZE, HeaderProtection,
    PROTECTED_LEN_COOKIE, PROTECTED_LEN_INIT, PROTECTED_LEN_RESPONSE, PROTECTED_LEN_TRANSPORT,
};
use crate::packet::{
    Packet, WgCookieReply, WgData, WgHandshakeInit, WgHandshakeResp, WgPacketType,
};

/// What [`Deobfuscator::classify`] recovered about a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Classified {
    /// Message type the datagram was classified as.
    pub(crate) kind: WgPacketType,
    /// Bytes of S1..S4 prefix in front of the message.
    pub(crate) prefix: usize,
    /// Bytes after the prefix covered by header protection.
    pub(crate) protected_len: usize,
    /// Fixed message size for the handshake types; anything past it is an
    /// AWG 3.1 trailer. `None` for transport.
    pub(crate) msg_size: Option<usize>,
    /// Header-protection keystream for this datagram, derived once during
    /// classification and reused to unprotect the message.
    pub(crate) mask: Option<[u8; HEADER_PROTECTION_MASK_LEN]>,
}

/// Device-wide receive-side classifier and de-obfuscator.
#[derive(Debug, Clone)]
pub(crate) struct Deobfuscator {
    cfg: Arc<AmneziaConfig>,
    header_protection: Option<HeaderProtection>,
}

impl Deobfuscator {
    pub(crate) fn new(cfg: Arc<AmneziaConfig>) -> Self {
        let header_protection = cfg.header_protection_key.map(HeaderProtection::new);
        Deobfuscator {
            cfg,
            header_protection,
        }
    }

    /// Classify `src` by trying each message type's prefix length and size,
    /// then checking the (unprotected) type value at that offset against the
    /// type's H range. `None` for junk, I-packets and garbage.
    pub(crate) fn classify(&self, src: &[u8]) -> Option<Classified> {
        let cfg = &*self.cfg;
        let p = &cfg.padding;
        let h = &cfg.headers;
        let init = Candidate {
            kind: WgPacketType::HandshakeInit,
            prefix: p.s1.into(),
            range: h.init,
            size: WgHandshakeInit::LEN,
            protected_len: PROTECTED_LEN_INIT,
            fixed: true,
        };
        let response = Candidate {
            kind: WgPacketType::HandshakeResp,
            prefix: p.s2.into(),
            range: h.response,
            size: WgHandshakeResp::LEN,
            protected_len: PROTECTED_LEN_RESPONSE,
            fixed: true,
        };
        let cookie = Candidate {
            kind: WgPacketType::CookieReply,
            prefix: p.s3.into(),
            range: h.cookie,
            size: WgCookieReply::LEN,
            protected_len: PROTECTED_LEN_COOKIE,
            fixed: true,
        };
        let transport = Candidate {
            kind: WgPacketType::Data,
            prefix: p.s4.into(),
            range: h.transport,
            size: WgData::OVERHEAD,
            protected_len: PROTECTED_LEN_TRANSPORT,
            fixed: false,
        };

        // AWG 3.1 relaxes the handshake size tests to `>=`, so each of them
        // matches any full-size transport packet on size alone, leaving only
        // the type-range test (over ciphertext, so uniformly random) between a
        // data packet and a handshake misparse. Tried first, 50M-wide ranges
        // would steal ~3.5% of all data packets. Classification is local, so
        // trying transport first costs no interoperability.
        let candidates = if cfg.random_trailers {
            [transport, init, response, cookie]
        } else {
            [init, response, cookie, transport]
        };

        // Every candidate's prefix starts at byte 0, so they all share the
        // nonce `src[..12]`: derive the keystream once and reuse it, both for
        // the type checks and (via `Classified::mask`) for unprotecting.
        let mask = match self.header_protection {
            Some(hp) => {
                let nonce: &[u8; HEADER_PROTECTION_NONCE_SIZE] =
                    src.get(..HEADER_PROTECTION_NONCE_SIZE)?.try_into().ok()?;
                Some(hp.mask(nonce))
            }
            None => None,
        };

        candidates.into_iter().find_map(|c| {
            let min_len = c.prefix.checked_add(c.size)?;
            let size_ok = if c.fixed && !cfg.random_trailers {
                src.len() == min_len
            } else {
                src.len() >= min_len
            };
            if !size_ok {
                return None;
            }
            let mut type_bytes: [u8; 4] = src.get(c.prefix..c.prefix + 4)?.try_into().ok()?;
            if let Some(mask) = &mask {
                for (b, m) in type_bytes.iter_mut().zip(mask) {
                    *b ^= m;
                }
            }
            let value = u32::from_le_bytes(type_bytes);
            (c.range.start <= value && value <= c.range.end).then_some(Classified {
                kind: c.kind,
                prefix: c.prefix,
                protected_len: c.protected_len,
                msg_size: c.fixed.then_some(c.size),
                mask,
            })
        })
    }

    /// Turn an inbound datagram into a plain WireGuard message: classify,
    /// strip the S-prefix, remove header protection and trim any trailer.
    ///
    /// The H value stays in the type field so MACs still verify over the raw
    /// bytes. Returns `None` (drop silently) for junk, I-packets and garbage.
    pub(crate) fn open(&self, mut packet: Packet) -> Option<(Packet, WgPacketType)> {
        let c = self.classify(&packet)?;
        packet.buf_mut().advance(c.prefix);
        if let Some(mask) = &c.mask {
            let n = c.protected_len.min(packet.len());
            for (b, m) in packet.buf_mut()[..n].iter_mut().zip(mask) {
                *b ^= m;
            }
        }
        if let Some(size) = c.msg_size {
            packet.truncate(size);
        }
        Some((packet, c.kind))
    }
}

/// One message type's framing, as tried by [`Deobfuscator::classify`].
#[derive(Clone, Copy)]
struct Candidate {
    kind: WgPacketType,
    prefix: usize,
    range: HeaderRange,
    /// Fixed message size, or the minimum (header + tag) for transport.
    size: usize,
    protected_len: usize,
    /// Handshake types have a fixed size; transport does not.
    fixed: bool,
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::super::config::{HeaderRanges, Junk, Padding};
    use super::super::cps::CpsChain;
    use super::super::junk::random_trailer_len;
    use super::super::rng::{DetRng, FastRandom, RandomSource};
    use super::*;

    /// Test-only sender: H value, S-prefix, header protection, then an
    /// optional trailer — awgtun's send order. Task 6 replaces this with
    /// `Obfuscator::seal`.
    pub(crate) fn seal_for_test(cfg: &AmneziaConfig, kind: WgPacketType, msg: &[u8]) -> Vec<u8> {
        let mut rng = FastRandom;
        let (range, prefix_len, protected_len) = match kind {
            WgPacketType::HandshakeInit => (cfg.headers.init, cfg.padding.s1, PROTECTED_LEN_INIT),
            WgPacketType::HandshakeResp => {
                (cfg.headers.response, cfg.padding.s2, PROTECTED_LEN_RESPONSE)
            }
            WgPacketType::CookieReply => (cfg.headers.cookie, cfg.padding.s3, PROTECTED_LEN_COOKIE),
            _ => (
                cfg.headers.transport,
                cfg.padding.s4,
                PROTECTED_LEN_TRANSPORT,
            ),
        };
        let mut message = msg.to_vec();
        let h = rng.range_u32(range.start, range.end);
        message[..4].copy_from_slice(&h.to_le_bytes());

        let mut out = vec![0u8; usize::from(prefix_len)];
        rng.fill(&mut out);
        if let Some(key) = cfg.header_protection_key {
            HeaderProtection::new(key).apply(&out, &mut message, protected_len);
        }
        out.extend_from_slice(&message);

        if cfg.random_trailers && kind != WgPacketType::Data {
            // Always append at least one byte so the trim is exercised.
            let len = random_trailer_len(&mut rng, 500, out.len()).max(1);
            let mut trailer = vec![0u8; len];
            rng.fill(&mut trailer);
            out.extend_from_slice(&trailer);
        }
        out
    }

    /// Synthetic AWG 3.x parameters with the real shape: S2 > 64, H ranges
    /// millions wide, every key populated.
    fn awg_cfg(header_protection: bool, random_trailers: bool) -> AmneziaConfig {
        AmneziaConfig {
            headers: HeaderRanges {
                init: HeaderRange {
                    start: 1_100_000,
                    end: 2_100_000,
                },
                response: HeaderRange {
                    start: 3_100_000,
                    end: 4_100_000,
                },
                cookie: HeaderRange {
                    start: 5_100_000,
                    end: 6_100_000,
                },
                transport: HeaderRange {
                    start: 7_100_000,
                    end: 8_100_000,
                },
            },
            padding: Padding {
                s1: 27,
                s2: 87,
                s3: 33,
                s4: 21,
            },
            junk: Junk {
                count: 6,
                min: 60,
                max: 300,
            },
            header_protection_key: header_protection.then_some([0x5a; 32]),
            random_trailers,
            ..AmneziaConfig::default()
        }
    }

    fn kinds() -> [(WgPacketType, usize); 4] {
        [
            (WgPacketType::HandshakeInit, WgHandshakeInit::LEN),
            (WgPacketType::HandshakeResp, WgHandshakeResp::LEN),
            (WgPacketType::CookieReply, WgCookieReply::LEN),
            (WgPacketType::Data, WgData::OVERHEAD + 48),
        ]
    }

    /// A plain WireGuard message of `kind` with recognisable body bytes.
    fn wg_message(kind: WgPacketType, len: usize) -> Vec<u8> {
        let mut msg: Vec<u8> = (0..len)
            .map(|i| (i as u8).wrapping_mul(31) ^ 0xa5)
            .collect();
        msg[..4].copy_from_slice(&u32::from(kind.0).to_le_bytes());
        msg
    }

    fn packet(bytes: &[u8]) -> Packet {
        Packet::from_bytes(BytesMut::from(bytes))
    }

    fn range_of(cfg: &AmneziaConfig, kind: WgPacketType) -> HeaderRange {
        match kind {
            WgPacketType::HandshakeInit => cfg.headers.init,
            WgPacketType::HandshakeResp => cfg.headers.response,
            WgPacketType::CookieReply => cfg.headers.cookie,
            _ => cfg.headers.transport,
        }
    }

    /// `open` must return the original message except for the type field,
    /// which keeps the H value from the configured range.
    fn assert_opened(cfg: &AmneziaConfig, kind: WgPacketType, msg: &[u8], datagram: &[u8]) {
        let deob = Deobfuscator::new(Arc::new(cfg.clone()));
        let (opened, got) = deob.open(packet(datagram)).expect("datagram classifies");
        assert_eq!(got, kind);
        assert_eq!(opened.len(), msg.len(), "{kind:?}: length");
        assert_eq!(&opened[4..], &msg[4..], "{kind:?}: body");
        let h = u32::from_le_bytes(opened[..4].try_into().unwrap());
        let r = range_of(cfg, kind);
        assert!((r.start..=r.end).contains(&h), "{kind:?}: H value {h} kept");
    }

    #[test]
    fn open_plain_cfg_is_identity() {
        let cfg = AmneziaConfig::default();
        let deob = Deobfuscator::new(Arc::new(cfg));
        for (kind, len) in kinds() {
            let msg = wg_message(kind, len);
            let (opened, got) = deob.open(packet(&msg)).expect("plain WG classifies");
            assert_eq!(got, kind);
            assert_eq!(&opened[..], &msg[..]);
        }
    }

    #[test]
    fn open_strips_prefix_each_kind() {
        let cfg = awg_cfg(false, false);
        for (kind, len) in kinds() {
            let msg = wg_message(kind, len);
            let datagram = seal_for_test(&cfg, kind, &msg);
            assert_eq!(datagram.len(), len + prefix_of(&cfg, kind));
            assert_opened(&cfg, kind, &msg, &datagram);
        }
    }

    fn prefix_of(cfg: &AmneziaConfig, kind: WgPacketType) -> usize {
        usize::from(match kind {
            WgPacketType::HandshakeInit => cfg.padding.s1,
            WgPacketType::HandshakeResp => cfg.padding.s2,
            WgPacketType::CookieReply => cfg.padding.s3,
            _ => cfg.padding.s4,
        })
    }

    #[test]
    fn open_unprotects_header() {
        let cfg = awg_cfg(true, false);
        for (kind, len) in kinds() {
            let msg = wg_message(kind, len);
            let datagram = seal_for_test(&cfg, kind, &msg);
            let p = prefix_of(&cfg, kind);
            assert_ne!(
                &datagram[p + 4..p + 16],
                &msg[4..16],
                "{kind:?}: header is protected on the wire"
            );
            assert_opened(&cfg, kind, &msg, &datagram);
        }
    }

    #[test]
    fn open_trims_trailer_before_size_check() {
        for hp in [false, true] {
            let cfg = awg_cfg(hp, true);
            for (kind, len) in kinds() {
                let msg = wg_message(kind, len);
                let datagram = seal_for_test(&cfg, kind, &msg);
                if kind != WgPacketType::Data {
                    assert!(
                        datagram.len() > len + prefix_of(&cfg, kind),
                        "trailer present"
                    );
                }
                // The fixed-size handshake messages come back at exactly
                // their WireGuard size, so `==` parsers downstream accept them.
                assert_opened(&cfg, kind, &msg, &datagram);
            }
        }
    }

    /// Port of awgtun's `awg31_transport_classification`: with trailers on,
    /// the relaxed `>=` handshake size tests match any full-size transport
    /// packet on size alone, so transport must be tried first.
    #[test]
    fn transport_classified_before_handshake_with_trailers() {
        const N: usize = 50_000;
        let wide = |start: u32| HeaderRange {
            start,
            end: start + 50_000_000,
        };
        for random_trailers in [true, false] {
            let cfg = AmneziaConfig {
                headers: HeaderRanges {
                    init: wide(1_100_000_000),
                    response: wide(1_250_000_000),
                    cookie: wide(1_400_000_000),
                    transport: wide(1_550_000_000),
                },
                padding: Padding {
                    s1: 41,
                    s2: 83,
                    s3: 29,
                    s4: 23,
                },
                random_trailers,
                ..AmneziaConfig::default()
            };
            let deob = Deobfuscator::new(Arc::new(cfg.clone()));
            // Ciphertext-shaped bytes from a cheap LCG (a CSPRNG is slow in
            // debug builds and buys nothing here).
            let mut x: u64 = 1;
            let mut msg = vec![0u8; WgData::OVERHEAD + 1400];
            let stolen = (0..N)
                .filter(|_| {
                    for b in msg.iter_mut() {
                        x = x
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(1_442_695_040_888_963_407);
                        *b = (x >> 33) as u8;
                    }
                    let datagram = seal_for_test(&cfg, WgPacketType::Data, &msg);
                    !matches!(
                        deob.classify(&datagram),
                        Some(c) if c.kind == WgPacketType::Data && c.prefix == 23
                    )
                })
                .count();
            assert!(
                stolen < N / 10_000,
                "{stolen} of {N} transport packets misclassified \
                 (random_trailers = {random_trailers})"
            );
        }
    }

    #[test]
    fn junk_and_cps_are_dropped() {
        for hp in [false, true] {
            for trailers in [false, true] {
                let cfg = awg_cfg(hp, trailers);
                let deob = Deobfuscator::new(Arc::new(cfg.clone()));

                let mut junk = Vec::new();
                for seed in 0..8 {
                    cfg.junk.render_into(&mut DetRng::new(seed), &mut junk);
                }
                for (i, j) in junk.iter().enumerate() {
                    assert!(deob.open(packet(j)).is_none(), "junk #{i} accepted");
                }

                let mut rng = DetRng::new(42);
                for chain in [
                    "<b 0xdeadbeefcafe><r 64>",
                    "<t><rc 100><rd 20>",
                    "<b 0x01000000>",
                ] {
                    let mut ipkt = Vec::new();
                    CpsChain::parse(chain).unwrap().render(&mut rng, &mut ipkt);
                    assert!(
                        deob.open(packet(&ipkt)).is_none(),
                        "I-packet {chain} accepted"
                    );
                }

                // Garbage: empty, too short, and a handshake-sized datagram
                // whose type value is out of every range.
                assert!(deob.open(packet(&[])).is_none());
                assert!(deob.open(packet(&[1, 0, 0, 0])).is_none());
                let mut bad = vec![0u8; usize::from(cfg.padding.s1) + WgHandshakeInit::LEN];
                bad[usize::from(cfg.padding.s1)..][..4].copy_from_slice(&9u32.to_le_bytes());
                if hp {
                    // Make the *unprotected* type value 9.
                    let hp = HeaderProtection::new(cfg.header_protection_key.unwrap());
                    let (prefix, msg) = bad.split_at_mut(usize::from(cfg.padding.s1));
                    hp.apply(prefix, msg, PROTECTED_LEN_INIT);
                }
                assert!(deob.open(packet(&bad)).is_none());
            }
        }
    }

    /// Port of awgtun's `classified_header_mask_matches_a_second_apply`: the
    /// keystream derived during classification undoes the sender's protection.
    #[test]
    fn classified_mask_reused() {
        let cfg = awg_cfg(true, false);
        let deob = Deobfuscator::new(Arc::new(cfg.clone()));
        let mut msg = vec![0u8; WgData::OVERHEAD + 64];
        msg[4..8].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        msg[8..16].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_le_bytes());
        let datagram = seal_for_test(&cfg, WgPacketType::Data, &msg);

        let c = deob.classify(&datagram).expect("transport classifies");
        assert_eq!(c.kind, WgPacketType::Data);
        let mask = c.mask.expect("header protection is on");
        let mut header = datagram[c.prefix..c.prefix + PROTECTED_LEN_TRANSPORT].to_vec();
        for (b, m) in header.iter_mut().zip(mask) {
            *b ^= m;
        }
        assert_eq!(
            &header[4..],
            &msg[4..16],
            "XORing the classifier's mask undoes `apply`"
        );
        let h = u32::from_le_bytes(header[..4].try_into().unwrap());
        assert!((cfg.headers.transport.start..=cfg.headers.transport.end).contains(&h));

        // And it is the same keystream `apply` would derive again.
        let nonce: [u8; HEADER_PROTECTION_NONCE_SIZE] =
            datagram[..HEADER_PROTECTION_NONCE_SIZE].try_into().unwrap();
        let hp = HeaderProtection::new(cfg.header_protection_key.unwrap());
        assert_eq!(mask, hp.mask(&nonce));
    }
}
