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
        self.classify_masked(src, mask, true)
    }

    /// Classify `src` again as a handshake-type message only, reusing the
    /// keystream of its first classification `first`.
    ///
    /// With AWG 3.1 trailers transport is tried first, so a handshake whose
    /// bytes at offset S4 happen to fall in the H4 range (|H4| / 2^32 of
    /// them) is first taken for transport. Its "receiver index" is then
    /// random, so the receiver asks for this second reading (ruling R14).
    #[cfg(test)]
    pub(crate) fn reclassify_handshake(
        &self,
        src: &[u8],
        first: &Classified,
    ) -> Option<Classified> {
        self.classify_masked(src, first.mask, false)
    }

    fn classify_masked(
        &self,
        src: &[u8],
        mask: Option<[u8; HEADER_PROTECTION_MASK_LEN]>,
        with_transport: bool,
    ) -> Option<Classified> {
        self.matches(src, mask, with_transport).next()
    }

    /// Every reading of `src` that passes its size and H-range test, in the
    /// classifier's order. Lazy: [`Deobfuscator::classify`] takes the first.
    fn matches<'a>(
        &'a self,
        src: &'a [u8],
        mask: Option<[u8; HEADER_PROTECTION_MASK_LEN]>,
        with_transport: bool,
    ) -> impl Iterator<Item = Classified> + 'a {
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

        candidates
            .into_iter()
            .filter(move |c| with_transport || c.kind != WgPacketType::Data)
            .filter_map(move |c| {
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
    #[cfg(test)]
    pub(crate) fn open(&self, packet: Packet) -> Option<(Packet, WgPacketType)> {
        self.open_with(packet, |_| true, |_, _| true)
    }

    /// [`Deobfuscator::open`], for a receiver that can tell whether a
    /// transport receiver index is one of its own (`known_idx`) and whether
    /// a handshake message's MAC1 verifies (`mac1_ok`, given the kind and the
    /// unprotected message).
    ///
    /// With AWG 3.1 trailers the size tests are `>=`, so a datagram can pass
    /// several readings; only the first is taken, unless it is clearly wrong:
    /// - transport with an unknown receiver index (ruling R14): it was a
    ///   handshake whose bytes at S4 fell in H4, read it as one;
    /// - several handshake readings (ruling R15; a trailered response passes
    ///   the init test |H1| / 2^32 of the time): take the first whose MAC1
    ///   verifies, a cookie reply having none.
    ///
    /// Both checks run before anything is modified and only when a datagram
    /// is ambiguous, so valid traffic pays no MAC and no copy. Without
    /// trailers sizes are exact and the first reading is taken.
    pub(crate) fn open_with(
        &self,
        packet: Packet,
        known_idx: impl FnOnce(u32) -> bool,
        mut mac1_ok: impl FnMut(WgPacketType, &[u8]) -> bool,
    ) -> Option<(Packet, WgPacketType)> {
        let first = self.classify(&packet)?;
        if !self.cfg.random_trailers
            || (first.kind == WgPacketType::Data
                && known_idx(transport_receiver_idx(&packet, &first)))
        {
            return Some(self.open_classified(packet, first));
        }

        let mut readings = [None; 3];
        for (slot, c) in readings
            .iter_mut()
            .zip(self.matches(&packet, first.mask, false))
        {
            *slot = Some(c);
        }
        let chosen = match readings {
            // Transport with an unknown index and no handshake reading: keep
            // it; no session takes it.
            [None, ..] => first,
            [Some(only), None, _] => only,
            [Some(head), ..] => readings
                .into_iter()
                .flatten()
                .find(|c| {
                    c.kind == WgPacketType::CookieReply
                        || mac1_ok(c.kind, &unprotected_message(&packet, c))
                })
                .unwrap_or(head),
        };
        Some(self.open_classified(packet, chosen))
    }

    fn open_classified(&self, mut packet: Packet, c: Classified) -> (Packet, WgPacketType) {
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
        (packet, c.kind)
    }
}

/// The message of a handshake-type reading `c`, prefix and trailer removed
/// and header protection undone, as a copy (for the MAC1 check of an
/// ambiguous datagram).
fn unprotected_message(src: &[u8], c: &Classified) -> Vec<u8> {
    let size = c.msg_size.unwrap_or(src.len() - c.prefix);
    let mut msg = src[c.prefix..c.prefix + size].to_vec();
    if let Some(mask) = &c.mask {
        let n = c.protected_len.min(msg.len());
        for (b, m) in msg[..n].iter_mut().zip(mask) {
            *b ^= m;
        }
    }
    msg
}

/// The receiver index of a datagram classified as transport, unprotected.
fn transport_receiver_idx(src: &[u8], c: &Classified) -> u32 {
    const IDX: std::ops::Range<usize> = 4..8;
    let mut idx = [0u8; 4];
    if let Some(bytes) = src.get(c.prefix + IDX.start..c.prefix + IDX.end) {
        idx.copy_from_slice(bytes);
    }
    if let Some(mask) = &c.mask {
        for (b, m) in idx.iter_mut().zip(&mask[IDX]) {
            *b ^= m;
        }
    }
    u32::from_le_bytes(idx)
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
    use super::super::rng::{DetRng, RandomSource};
    use super::super::seal::Obfuscator;
    use super::*;

    /// Fixed `<t>` timestamp, so CPS-rendered bytes are deterministic.
    const NOW: u32 = 0x6543_2100;

    /// Send `msg` through [`Obfuscator::seal_with`] with a `window`-byte UDP
    /// window and return the datagram carrying it. Init and response get an
    /// H1/H2 value first, as the noise layer writes it before their MACs.
    fn seal(
        cfg: &AmneziaConfig,
        kind: WgPacketType,
        msg: &[u8],
        window: usize,
        rng: &mut DetRng,
    ) -> Vec<u8> {
        let mut msg = msg.to_vec();
        if matches!(
            kind,
            WgPacketType::HandshakeInit | WgPacketType::HandshakeResp
        ) {
            let r = range_of(cfg, kind);
            msg[..4].copy_from_slice(&rng.range_u32(r.start, r.end).to_le_bytes());
        }
        let packet = packet(&msg)
            .try_into_wg_as(kind)
            .expect("well-formed message");
        let mut out = Vec::new();
        Obfuscator::new(Arc::new(cfg.clone()))
            .seal_with(packet, window, &mut out, rng, NOW)
            .expect("fits in a datagram");
        out.pop().expect("message datagram").to_vec()
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
        let mut rng = DetRng::new(10);
        for (kind, len) in kinds() {
            let msg = wg_message(kind, len);
            let datagram = seal(&cfg, kind, &msg, 500, &mut rng);
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
        let mut rng = DetRng::new(11);
        for (kind, len) in kinds() {
            let msg = wg_message(kind, len);
            let datagram = seal(&cfg, kind, &msg, 500, &mut rng);
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
        let mut rng = DetRng::new(12);
        for hp in [false, true] {
            let cfg = awg_cfg(hp, true);
            for (kind, len) in kinds() {
                let msg = wg_message(kind, len);
                let base = len + prefix_of(&cfg, kind);
                let datagram = seal(&cfg, kind, &msg, 500, &mut rng);
                if kind != WgPacketType::Data {
                    assert!(datagram.len() > base, "{kind:?}: trailer present");
                }
                // The fixed-size handshake messages come back at exactly
                // their WireGuard size, so `==` parsers downstream accept them.
                assert_opened(&cfg, kind, &msg, &datagram);

                // A window the message already fills: zero-length trailer.
                // (Cookie replies always size theirs against the default
                // window instead, as amneziawg-go does.)
                if kind == WgPacketType::CookieReply {
                    continue;
                }
                let datagram = seal(&cfg, kind, &msg, base, &mut rng);
                assert_eq!(datagram.len(), base, "{kind:?}: no trailer");
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
            let mut rng = DetRng::new(13);
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
                    let datagram = seal(&cfg, WgPacketType::Data, &msg, 500, &mut rng);
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

    /// R14: with trailers on, a handshake whose 4 bytes at offset S4 (after
    /// unmasking) fall in H4 is first taken for transport. Its receiver index
    /// is then unknown, and the handshake-only reading recovers it.
    #[test]
    fn handshake_misread_as_transport_is_recovered() {
        for hp in [false, true] {
            let mut cfg = awg_cfg(hp, true);
            // Wide H4 so the misreading is common enough to find quickly.
            cfg.headers.transport = HeaderRange {
                start: 100_000_000,
                end: 4_000_000_000,
            };
            let deob = Deobfuscator::new(Arc::new(cfg.clone()));
            for (kind, len) in kinds().into_iter().take(3) {
                let msg = wg_message(kind, len);
                let (datagram, first) = (0..)
                    .map(|seed| seal(&cfg, kind, &msg, 500, &mut DetRng::new(seed)))
                    .find_map(|d| {
                        let c = deob.classify(&d).expect("classifies");
                        (c.kind == WgPacketType::Data).then_some((d, c))
                    })
                    .expect("some datagram is misread");
                let p = usize::from(cfg.padding.s4);
                let mut type_bytes: [u8; 4] = datagram[p..p + 4].try_into().unwrap();
                if let Some(mask) = first.mask {
                    for (b, m) in type_bytes.iter_mut().zip(mask) {
                        *b ^= m;
                    }
                }
                let h = u32::from_le_bytes(type_bytes);
                assert!(
                    (cfg.headers.transport.start..=cfg.headers.transport.end).contains(&h),
                    "{kind:?}: bytes at S4 are in H4"
                );

                let again = deob
                    .reclassify_handshake(&datagram, &first)
                    .expect("handshake-only reading");
                assert_eq!(again.kind, kind, "hp={hp}");

                // A known index keeps the transport reading; an unknown one
                // takes the handshake reading, opened intact.
                let (_, got) = deob
                    .open_with(packet(&datagram), |_| true, |_, _| true)
                    .unwrap();
                assert_eq!(got, WgPacketType::Data);
                let (opened, got) = deob
                    .open_with(packet(&datagram), |_| false, |_, _| true)
                    .unwrap();
                assert_eq!(got, kind);
                assert_eq!(&opened[4..], &msg[4..], "{kind:?}: body");
            }
        }
    }

    /// R15: with trailers on, a response or cookie reply can pass the init
    /// test (size `>=` S1 + 148, bytes at S1 in H1). The init reading fails
    /// MAC1, so the next handshake reading that verifies wins; a cookie reply
    /// has no MAC1 and is taken as is.
    #[test]
    fn handshake_misread_as_other_handshake_is_recovered() {
        for hp in [false, true] {
            let mut cfg = awg_cfg(hp, true);
            // Wide H1 so the misreading is common enough to find quickly.
            cfg.headers.init = HeaderRange {
                start: 10_000_000,
                end: 4_000_000_000,
            };
            let deob = Deobfuscator::new(Arc::new(cfg.clone()));
            for (kind, len) in [
                (WgPacketType::HandshakeResp, WgHandshakeResp::LEN),
                (WgPacketType::CookieReply, WgCookieReply::LEN),
            ] {
                let msg = wg_message(kind, len);
                let datagram = (0..)
                    .map(|seed| seal(&cfg, kind, &msg, 500, &mut DetRng::new(seed)))
                    .find(|d| deob.classify(d).map(|c| c.kind) == Some(WgPacketType::HandshakeInit))
                    .expect("some datagram is read as an init first");

                // Taking the first reading gets it wrong ...
                let (_, got) = deob
                    .open_with(packet(&datagram), |_| false, |_, _| true)
                    .unwrap();
                assert_eq!(got, WgPacketType::HandshakeInit, "hp={hp}");

                // ... a MAC1 check walks on to the true kind, opened intact.
                let mut asked = vec![];
                let (opened, got) = deob
                    .open_with(
                        packet(&datagram),
                        |_| false,
                        |k, m| {
                            asked.push(k);
                            k == kind && m[4..] == msg[4..]
                        },
                    )
                    .unwrap();
                assert_eq!(got, kind, "hp={hp}");
                assert_eq!(&opened[4..], &msg[4..], "{kind:?}: message");
                assert_eq!(asked[0], WgPacketType::HandshakeInit);
                assert!(!asked.contains(&WgPacketType::CookieReply), "no MAC1 asked");
            }
        }
    }

    /// Valid unambiguous traffic pays no MAC check and no index lookup
    /// without trailers.
    #[test]
    fn unambiguous_datagrams_skip_the_checks() {
        for trailers in [false, true] {
            let cfg = awg_cfg(true, trailers);
            let deob = Deobfuscator::new(Arc::new(cfg.clone()));
            for (kind, len) in kinds() {
                let msg = wg_message(kind, len);
                let datagram = seal(&cfg, kind, &msg, 500, &mut DetRng::new(5));
                let (_, got) = deob
                    .open_with(
                        packet(&datagram),
                        |_| {
                            assert!(trailers, "index asked without trailers");
                            true
                        },
                        |_, _| panic!("MAC1 asked for an unambiguous {kind:?}"),
                    )
                    .unwrap();
                assert_eq!(got, kind);
            }
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
                    CpsChain::parse(chain)
                        .unwrap()
                        .render_at(&mut rng, NOW, &mut ipkt);
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
        let datagram = seal(&cfg, WgPacketType::Data, &msg, 500, &mut DetRng::new(14));

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
