//! Send boundary: turn a plain WireGuard message into the datagrams an
//! AmneziaWG peer expects on the wire.
//!
//! Mirrors the send side of amneziawg-go (`device/send.go`): I-packets and
//! junk ahead of each initiation, H3/H4 type values, S1..S4 random prefixes,
//! header protection and AWG 3.1 random trailers.

use std::sync::Arc;

use bytes::BytesMut;
use zerocopy::IntoBytes;

use super::config::HEADER_PROTECTION_MIN_PADDING;
use super::config::{AmneziaConfig, HeaderRange};
use super::cps::unix_now_secs;
use super::header_protection::{
    HEADER_PROTECTION_NONCE_SIZE, HeaderProtection, PROTECTED_LEN_COOKIE, PROTECTED_LEN_INIT,
    PROTECTED_LEN_RESPONSE, PROTECTED_LEN_TRANSPORT,
};
use super::junk::random_trailer_len;
use super::rng::{FastRandom, RandomSource};
use super::tunn_state::INITIAL_UDP_WINDOW;
use crate::packet::{Packet, WgCookieReply, WgData, WgHandshakeInit, WgHandshakeResp, WgKind};

/// Largest UDP payload a datagram can carry.
pub(crate) const MAX_DATAGRAM_LEN: usize = u16::MAX as usize;

/// Bound on S4 prefix redraws per transport packet, so a pathological
/// configuration cannot stall the send path.
const MAX_PREFIX_DRAWS: usize = 8;

/// Why [`Obfuscator::seal`] produced nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SealError {
    /// A datagram would exceed the 65535-byte UDP limit.
    #[error("obfuscated datagram exceeds the 65535-byte UDP limit")]
    TooLarge,
}

/// Device-wide send-side obfuscator.
#[derive(Debug, Clone)]
pub(crate) struct Obfuscator {
    cfg: Arc<AmneziaConfig>,
    hp: Option<HeaderProtection>,
}

impl Obfuscator {
    /// Build an obfuscator for `cfg`.
    ///
    /// `cfg` must have passed [`AmneziaConfig::validate`]: header protection
    /// takes its nonce from the first 12 prefix bytes, so it needs S1..S4 >= 12.
    pub(crate) fn new(cfg: Arc<AmneziaConfig>) -> Self {
        let p = &cfg.padding;
        debug_assert!(
            cfg.header_protection_key.is_none()
                || [p.s1, p.s2, p.s3, p.s4]
                    .iter()
                    .all(|s| *s >= HEADER_PROTECTION_MIN_PADDING),
            "header protection needs S1..S4 >= 12; validate the config first"
        );
        let hp = cfg.header_protection_key.map(HeaderProtection::new);
        Obfuscator { cfg, hp }
    }

    /// Append the datagrams that carry `packet` to `out`.
    ///
    /// A handshake initiation is preceded by the set I1..I5 packets and then
    /// Jc junk datagrams. Handshake initiations and responses must already
    /// carry their H1/H2 value (written before their MACs); cookie replies
    /// and transport packets get H3/H4 here. `window` is the peer's UDP
    /// window, read only to size init and response trailers; cookie replies
    /// always use the default 500 (amneziawg-go's `device.randomTrailer`).
    /// `seal` never widens it: amneziawg-go widens with the pre-padding size,
    /// which only the tunnel knows.
    ///
    /// On error `out` is left as it was.
    pub(crate) fn seal(
        &self,
        packet: WgKind,
        window: usize,
        out: &mut Vec<Packet>,
    ) -> Result<(), SealError> {
        self.seal_with(packet, window, out, &mut FastRandom, unix_now_secs())
    }

    /// [`Obfuscator::seal`] with injected randomness and `<t>` timestamp.
    pub(crate) fn seal_with(
        &self,
        packet: WgKind,
        window: usize,
        out: &mut Vec<Packet>,
        rng: &mut dyn RandomSource,
        unix_secs: u32,
    ) -> Result<(), SealError> {
        let p = &self.cfg.padding;
        let datagram = match packet {
            WgKind::HandshakeInit(packet) => {
                let start = out.len();
                if let Err(e) = self.push_pre_handshake(out, rng, unix_secs) {
                    out.truncate(start);
                    return Err(e);
                }
                match self.frame(packet.as_bytes(), p.s1, PROTECTED_LEN_INIT, window, rng) {
                    Ok(datagram) => datagram,
                    Err(e) => {
                        out.truncate(start);
                        return Err(e);
                    }
                }
            }
            WgKind::HandshakeResp(packet) => {
                self.frame(packet.as_bytes(), p.s2, PROTECTED_LEN_RESPONSE, window, rng)?
            }
            WgKind::CookieReply(mut packet) => {
                packet.set_wire_type(pick(rng, self.cfg.headers.cookie));
                // Cookie replies go out before any peer is known, so Go sizes
                // their trailer against the fixed default window.
                self.frame(
                    packet.as_bytes(),
                    p.s3,
                    PROTECTED_LEN_COOKIE,
                    INITIAL_UDP_WINDOW,
                    rng,
                )?
            }
            WgKind::Data(packet) => self.seal_transport(packet, rng)?,
        };
        out.push(datagram);
        Ok(())
    }

    /// I1..I5 (unset ones skipped), then Jc junk datagrams, as amneziawg-go's
    /// `SendHandshakeInitiation` queues them. A set chain that renders no
    /// bytes still sends an empty datagram, as Go does.
    fn push_pre_handshake(
        &self,
        out: &mut Vec<Packet>,
        rng: &mut dyn RandomSource,
        unix_secs: u32,
    ) -> Result<(), SealError> {
        for chain in self.cfg.init_packets.0.iter().flatten() {
            let mut buf = Vec::new();
            chain.render_at(rng, unix_secs, &mut buf);
            if buf.len() > MAX_DATAGRAM_LEN {
                return Err(SealError::TooLarge);
            }
            out.push(Packet::from_bytes(BytesMut::from(&buf[..])));
        }
        let mut junk = Vec::new();
        self.cfg.junk.render_into(rng, &mut junk);
        out.extend(
            junk.into_iter()
                .map(|j| Packet::from_bytes(BytesMut::from(&j[..]))),
        );
        Ok(())
    }

    /// A handshake-type datagram: random prefix, the message, header
    /// protection over its `protected_len` leading bytes, then (AWG 3.1) a
    /// random trailer sized against `window`.
    fn frame(
        &self,
        msg: &[u8],
        prefix_len: u16,
        protected_len: usize,
        window: usize,
        rng: &mut dyn RandomSource,
    ) -> Result<Packet, SealError> {
        let prefix_len = usize::from(prefix_len);
        let size = prefix_len + msg.len();
        if size > MAX_DATAGRAM_LEN {
            return Err(SealError::TooLarge);
        }
        let trailer_len = if self.cfg.random_trailers {
            random_trailer_len(rng, window.min(MAX_DATAGRAM_LEN), size)
        } else {
            0
        };

        let mut buf = BytesMut::zeroed(size + trailer_len);
        let (prefix, rest) = buf.split_at_mut(prefix_len);
        let (message, trailer) = rest.split_at_mut(msg.len());
        rng.fill(prefix);
        message.copy_from_slice(msg);
        if let Some(hp) = self.hp {
            hp.apply(prefix, message, protected_len);
        }
        rng.fill(trailer);
        Ok(Packet::from_bytes(buf))
    }

    /// A transport datagram: H4, the S4 prefix and header protection over the
    /// 16-byte header. Transport gets no trailer (content padding lives
    /// inside the AEAD instead).
    ///
    /// The prefix is redrawn while an unpatched peer would take the datagram
    /// for a handshake; see [`Obfuscator::peer_would_misclassify`].
    fn seal_transport(
        &self,
        mut packet: Packet<WgData>,
        rng: &mut dyn RandomSource,
    ) -> Result<Packet, SealError> {
        packet
            .header
            .set_wire_type(pick(rng, self.cfg.headers.transport));
        let s4 = usize::from(self.cfg.padding.s4);
        let msg = packet.as_bytes();
        let len = s4 + msg.len();
        if len > MAX_DATAGRAM_LEN {
            return Err(SealError::TooLarge);
        }

        // One allocation and one copy of the datagram (ruling R2: no
        // headroom API in `Session`).
        let mut buf = BytesMut::zeroed(len);
        buf[s4..].copy_from_slice(msg);
        drop(packet);

        let mut clear_header = [0u8; PROTECTED_LEN_TRANSPORT];
        clear_header.copy_from_slice(&buf[s4..s4 + PROTECTED_LEN_TRANSPORT]);

        // Without header protection the peer reads raw bytes, so a redraw
        // only changes its decision if some handshake candidate's type field
        // falls inside the S4 prefix.
        let p = &self.cfg.padding;
        let redraw_helps =
            self.hp.is_some() || [p.s1, p.s2, p.s3].iter().any(|s| usize::from(*s) + 4 <= s4);

        for _ in 0..MAX_PREFIX_DRAWS {
            rng.fill(&mut buf[..s4]);
            let mut type_mask = [0u8; 4];
            if let Some(hp) = self.hp {
                let nonce: &[u8; HEADER_PROTECTION_NONCE_SIZE] = buf
                    [..HEADER_PROTECTION_NONCE_SIZE]
                    .try_into()
                    .expect("validated S4 covers the nonce");
                let keystream: [u8; PROTECTED_LEN_TRANSPORT] = hp.keystream(nonce);
                for ((b, c), k) in buf[s4..].iter_mut().zip(clear_header).zip(keystream) {
                    *b = c ^ k;
                }
                type_mask.copy_from_slice(&keystream[..4]);
            }
            if !redraw_helps || !self.peer_would_misclassify(&buf, type_mask) {
                break;
            }
        }

        Ok(Packet::from_bytes(buf))
    }

    /// Would a peer running amneziawg-go's `DeterminePacketTypeAndPadding`
    /// take this transport datagram for a handshake and drop it?
    ///
    /// That classifier tries init, response and cookie before transport, and
    /// AWG 3.1 relaxes their size tests from `==` to `>`, so a full-size
    /// transport datagram passes all three on size alone. Only the type-range
    /// test, read at the candidate's prefix offset and so effectively random,
    /// then stands between it and a misparse: ~3.5% of packets with
    /// 50-million-wide ranges. This mirrors the unpatched order and size
    /// rules exactly (the fix is amneziawg-go PR #183 and kernel PR #242);
    /// once peers carry it, the redraw never triggers. `mask` is the first
    /// four header-protection keystream bytes (zeros without protection).
    fn peer_would_misclassify(&self, datagram: &[u8], mask: [u8; 4]) -> bool {
        let p = &self.cfg.padding;
        let h = &self.cfg.headers;
        [
            (p.s1, h.init, WgHandshakeInit::LEN),
            (p.s2, h.response, WgHandshakeResp::LEN),
            (p.s3, h.cookie, WgCookieReply::LEN),
        ]
        .into_iter()
        .any(|(padding, range, size)| {
            let padding = usize::from(padding);
            let expected = padding + size;
            let size_ok = datagram.len() == expected
                || (self.cfg.random_trailers && datagram.len() > expected);
            let Some(field) = datagram.get(padding..padding + 4) else {
                return false;
            };
            let mut type_bytes = [0u8; 4];
            for ((t, f), m) in type_bytes.iter_mut().zip(field).zip(mask) {
                *t = f ^ m;
            }
            let value = u32::from_le_bytes(type_bytes);
            size_ok && range.start <= value && value <= range.end
        })
    }
}

fn pick(rng: &mut dyn RandomSource, range: HeaderRange) -> u32 {
    rng.range_u32(range.start, range.end)
}

#[cfg(test)]
mod tests {
    use super::super::classify::Deobfuscator;
    use super::super::config::{CpsChain, HeaderRanges, InitPackets, Junk, Padding};
    use super::super::rng::DetRng;
    use super::*;
    use crate::packet::WgPacketType;

    const NOW: u32 = 0x6543_2100;

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
                count: 3,
                min: 40,
                max: 90,
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

    fn range_of(cfg: &AmneziaConfig, kind: WgPacketType) -> HeaderRange {
        match kind {
            WgPacketType::HandshakeInit => cfg.headers.init,
            WgPacketType::HandshakeResp => cfg.headers.response,
            WgPacketType::CookieReply => cfg.headers.cookie,
            _ => cfg.headers.transport,
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

    /// A WireGuard message of `kind` as the noise layer hands it to `seal`:
    /// init and response already carry an H1/H2 value, cookie reply and
    /// transport the standard type.
    fn message(cfg: &AmneziaConfig, kind: WgPacketType, len: usize, rng: &mut DetRng) -> Vec<u8> {
        let mut msg: Vec<u8> = (0..len)
            .map(|i| (i as u8).wrapping_mul(31) ^ 0xa5)
            .collect();
        let ty = match kind {
            WgPacketType::HandshakeInit | WgPacketType::HandshakeResp => {
                pick(rng, range_of(cfg, kind))
            }
            _ => u32::from(kind.0),
        };
        msg[..4].copy_from_slice(&ty.to_le_bytes());
        msg
    }

    fn wg(kind: WgPacketType, msg: &[u8]) -> WgKind {
        Packet::from_bytes(BytesMut::from(msg))
            .try_into_wg_as(kind)
            .expect("well-formed message")
    }

    /// Seal `msg` deterministically; returns every datagram pushed.
    fn seal_det(
        cfg: &AmneziaConfig,
        kind: WgPacketType,
        msg: &[u8],
        window: usize,
        rng: &mut DetRng,
    ) -> Result<Vec<Packet>, SealError> {
        let mut out = Vec::new();
        Obfuscator::new(Arc::new(cfg.clone())).seal_with(
            wg(kind, msg),
            window,
            &mut out,
            rng,
            NOW,
        )?;
        Ok(out)
    }

    /// Opening a sealed datagram gives back the message, H value included.
    fn assert_opens(cfg: &AmneziaConfig, kind: WgPacketType, msg: &[u8], datagram: &Packet) {
        let deob = Deobfuscator::new(Arc::new(cfg.clone()));
        // As a device would: only a real transport packet carries a receiver
        // index it knows, so a handshake misread as transport is read again
        // (ruling R14; this used to flake at |H4| / 2^32 with OS randomness).
        let known_idx = |_| kind == WgPacketType::Data;
        let (opened, got) = deob
            .open_with(datagram.clone(), known_idx)
            .expect("datagram classifies");
        assert_eq!(got, kind);
        assert_eq!(&opened[4..], &msg[4..], "{kind:?}: body");
        let h = u32::from_le_bytes(opened[..4].try_into().unwrap());
        let r = range_of(cfg, kind);
        assert!((r.start..=r.end).contains(&h), "{kind:?}: H value {h}");
        if matches!(
            kind,
            WgPacketType::HandshakeInit | WgPacketType::HandshakeResp
        ) {
            assert_eq!(&opened[..4], &msg[..4], "{kind:?}: H1/H2 left as written");
        }
    }

    #[test]
    fn seal_then_open_round_trips_every_kind() {
        let mut rng = DetRng::new(1);
        for hp in [false, true] {
            for trailers in [false, true] {
                let cfg = awg_cfg(hp, trailers);
                for (kind, len) in kinds() {
                    let msg = message(&cfg, kind, len, &mut rng);
                    let out = seal_det(&cfg, kind, &msg, 500, &mut rng).unwrap();
                    let datagram = out.last().unwrap();
                    let base = prefix_of(&cfg, kind) + len;
                    if trailers && kind != WgPacketType::Data {
                        assert!(datagram.len() >= base && datagram.len() < 500);
                    } else {
                        assert_eq!(datagram.len(), base, "{kind:?}: no trailer");
                    }
                    if hp {
                        let p = prefix_of(&cfg, kind);
                        assert_ne!(&datagram[p + 4..p + 16], &msg[4..16], "{kind:?}: protected");
                    }
                    assert_opens(&cfg, kind, &msg, datagram);
                }
            }
        }
    }

    #[test]
    fn seal_uses_fast_random_by_default() {
        let cfg = awg_cfg(true, true);
        let mut rng = DetRng::new(2);
        let msg = message(
            &cfg,
            WgPacketType::HandshakeResp,
            WgHandshakeResp::LEN,
            &mut rng,
        );
        let mut out = Vec::new();
        Obfuscator::new(Arc::new(cfg.clone()))
            .seal(wg(WgPacketType::HandshakeResp, &msg), 500, &mut out)
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_opens(&cfg, WgPacketType::HandshakeResp, &msg, &out[0]);
    }

    #[test]
    fn init_preceded_by_cps_then_junk() {
        let mut cfg = awg_cfg(true, true);
        cfg.init_packets = InitPackets([
            Some(CpsChain::parse("<b 0xc0ffee><t><r 10>").unwrap()),
            None,
            Some(CpsChain::parse("<rc 5>").unwrap()),
            None,
            // Renders nothing, so an empty datagram goes out for it (as Go).
            Some(CpsChain::parse("<d>").unwrap()),
        ]);
        let mut rng = DetRng::new(3);
        let msg = message(
            &cfg,
            WgPacketType::HandshakeInit,
            WgHandshakeInit::LEN,
            &mut rng,
        );
        let out = seal_det(&cfg, WgPacketType::HandshakeInit, &msg, 500, &mut rng).unwrap();

        assert_eq!(out.len(), 3 + 3 + 1, "I1, I3, I5, three junk, the init");
        assert_eq!(out[0].len(), 3 + 4 + 10);
        assert_eq!(&out[0][..3], &[0xc0, 0xff, 0xee]);
        assert_eq!(&out[0][3..7], &NOW.to_be_bytes(), "<t> stamped");
        assert_eq!(out[1].len(), 5);
        assert!(out[1].iter().all(u8::is_ascii_alphabetic));
        assert!(out[2].is_empty(), "I5 renders to an empty datagram");
        for junk in &out[3..6] {
            assert!((40..90).contains(&junk.len()), "junk size {}", junk.len());
        }
        assert_opens(&cfg, WgPacketType::HandshakeInit, &msg, &out[6]);

        // Only initiations get them.
        for (kind, len) in kinds().into_iter().skip(1) {
            let msg = message(&cfg, kind, len, &mut rng);
            let out = seal_det(&cfg, kind, &msg, 500, &mut rng).unwrap();
            assert_eq!(out.len(), 1, "{kind:?}");
        }
    }

    /// Spec item 13: every cookie reply gets S3, H3, protection and a trailer.
    #[test]
    fn cookie_reply_gets_trailer() {
        let kind = WgPacketType::CookieReply;
        let mut rng = DetRng::new(4);
        for hp in [false, true] {
            let cfg = awg_cfg(hp, true);
            let base = usize::from(cfg.padding.s3) + WgCookieReply::LEN;
            let mut lens = std::collections::HashSet::new();
            for _ in 0..32 {
                let msg = message(&cfg, kind, WgCookieReply::LEN, &mut rng);
                let out = seal_det(&cfg, kind, &msg, 500, &mut rng).unwrap();
                let d = &out[0];
                assert!(d.len() >= base && d.len() < 500, "len {}", d.len());
                lens.insert(d.len());
                assert_opens(&cfg, kind, &msg, d);
            }
            assert!(lens.len() > 1, "trailer length varies");
            assert!(lens.iter().any(|l| *l > base), "a trailer was appended");

            // Like amneziawg-go's `device.randomTrailer`, the cookie trailer
            // is sized against the fixed default window, whatever is passed.
            for window in [base, 10_000] {
                let mut lens = std::collections::HashSet::new();
                for _ in 0..32 {
                    let msg = message(&cfg, kind, WgCookieReply::LEN, &mut rng);
                    let out = seal_det(&cfg, kind, &msg, window, &mut rng).unwrap();
                    assert!(out[0].len() < 500, "window {window}: len {}", out[0].len());
                    lens.insert(out[0].len());
                    assert_opens(&cfg, kind, &msg, &out[0]);
                }
                assert!(lens.iter().any(|l| *l > base), "window {window}: trailer");
            }
        }
    }

    /// Spec item 14: keepalives (empty transport payload) carry S4 too.
    #[test]
    fn keepalive_gets_s4_prefix() {
        let mut rng = DetRng::new(5);
        for hp in [false, true] {
            let cfg = awg_cfg(hp, true);
            let msg = message(&cfg, WgPacketType::Data, WgData::OVERHEAD, &mut rng);
            let out = seal_det(&cfg, WgPacketType::Data, &msg, 500, &mut rng).unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].len(), usize::from(cfg.padding.s4) + WgData::OVERHEAD);
            assert_opens(&cfg, WgPacketType::Data, &msg, &out[0]);
        }
    }

    /// `seal` reads the window only to size trailers; it never widens it
    /// (the tunnel does, with the pre-padding size, as amneziawg-go does).
    #[test]
    fn seal_leaves_udp_window_alone() {
        let mut rng = DetRng::new(6);
        let cfg = awg_cfg(true, true);
        let obf = Obfuscator::new(Arc::new(cfg.clone()));
        let window: usize = 500;
        for (kind, len) in [
            (WgPacketType::Data, WgData::OVERHEAD + 1000),
            (WgPacketType::HandshakeInit, WgHandshakeInit::LEN),
            (WgPacketType::HandshakeResp, WgHandshakeResp::LEN),
            (WgPacketType::CookieReply, WgCookieReply::LEN),
        ] {
            let msg = message(&cfg, kind, len, &mut rng);
            let mut out = Vec::new();
            obf.seal_with(wg(kind, &msg), window, &mut out, &mut rng, NOW)
                .unwrap();
            let datagram = out.last().unwrap();
            if kind == WgPacketType::Data {
                assert!(datagram.len() > window, "a datagram larger than the window");
            } else {
                assert!(
                    datagram.len() < window,
                    "{kind:?}: trailer within the window"
                );
            }
        }
        assert_eq!(window, 500);

        // A handshake that already exceeds the window gets no trailer.
        let mut big = cfg.clone();
        big.padding.s2 = 900;
        let msg = message(
            &big,
            WgPacketType::HandshakeResp,
            WgHandshakeResp::LEN,
            &mut rng,
        );
        let out = seal_det(&big, WgPacketType::HandshakeResp, &msg, 500, &mut rng).unwrap();
        assert_eq!(
            out[0].len(),
            900 + WgHandshakeResp::LEN,
            "no room for a trailer"
        );
    }

    /// amneziawg-go's unpatched `DeterminePacketTypeAndPadding`: init,
    /// response and cookie before transport, `==` or (with trailers) `>`.
    fn unpatched_peer_takes_it_for_a_handshake(c: &AmneziaConfig, d: &[u8]) -> bool {
        let mask = match c.header_protection_key {
            Some(key) => HeaderProtection::new(key).mask(d[..12].try_into().unwrap()),
            None => [0u8; 148],
        };
        for (padding, range, size) in [
            (c.padding.s1, c.headers.init, WgHandshakeInit::LEN),
            (c.padding.s2, c.headers.response, WgHandshakeResp::LEN),
            (c.padding.s3, c.headers.cookie, WgCookieReply::LEN),
        ] {
            let padding = usize::from(padding);
            let expected = padding + size;
            if d.len() != expected && !(c.random_trailers && d.len() > expected) {
                continue;
            }
            let v = u32::from_le_bytes([
                d[padding] ^ mask[0],
                d[padding + 1] ^ mask[1],
                d[padding + 2] ^ mask[2],
                d[padding + 3] ^ mask[3],
            ]);
            if (range.start..=range.end).contains(&v) {
                return true;
            }
        }
        false
    }

    /// Port of awgtun's `awg31_peer_misclassification`: 50-million-wide ranges,
    /// trailers on. Without the redraw ~3.5% of transport packets would be
    /// dropped by an unpatched peer.
    #[test]
    fn transport_redraw_avoids_unpatched_misclassification() {
        let wide = |start: u32| HeaderRange {
            start,
            end: start + 50_000_000,
        };
        let headers = HeaderRanges {
            init: wide(1_100_000_000),
            response: wide(1_250_000_000),
            cookie: wide(1_400_000_000),
            transport: wide(1_550_000_000),
        };
        let protected = AmneziaConfig {
            headers,
            padding: Padding {
                s1: 41,
                s2: 83,
                s3: 29,
                s4: 23,
            },
            random_trailers: true,
            header_protection_key: Some([7u8; 32]),
            ..AmneziaConfig::default()
        };
        // No header protection, but every handshake candidate's type field
        // lies inside the S4 prefix, so a redraw still changes the outcome.
        let unprotected = AmneziaConfig {
            padding: Padding {
                s1: 12,
                s2: 70,
                s3: 150,
                s4: 200,
            },
            header_protection_key: None,
            ..protected.clone()
        };

        const N: usize = 3000;
        let mut rng = DetRng::new(7);
        for cfg in [protected, unprotected] {
            let mut payload = vec![0u8; WgData::OVERHEAD + 1200];
            let s4 = usize::from(cfg.padding.s4);
            let mut unredrawn_hits = 0;
            for _ in 0..N {
                rng.fill(&mut payload[16..]);
                let msg = message(&cfg, WgPacketType::Data, payload.len(), &mut rng);
                let msg = [&msg[..16], &payload[16..]].concat();
                let out = seal_det(&cfg, WgPacketType::Data, &msg, 500, &mut rng).unwrap();
                assert!(
                    !unpatched_peer_takes_it_for_a_handshake(&cfg, &out[0]),
                    "emitted a datagram an unpatched peer would drop as a handshake"
                );
                assert_opens(&cfg, WgPacketType::Data, &msg, &out[0]);

                // Control: the same datagram under one fresh, unchecked prefix.
                let mut control = out[0].to_vec();
                rng.fill(&mut control[..s4]);
                if let Some(key) = cfg.header_protection_key {
                    let (prefix, rest) = control.split_at_mut(s4);
                    rest[..16].copy_from_slice(&out[0][s4..s4 + 16]);
                    let hp = HeaderProtection::new(key);
                    hp.apply(&out[0][..s4], &mut rest[..16], PROTECTED_LEN_TRANSPORT);
                    hp.apply(prefix, &mut rest[..16], PROTECTED_LEN_TRANSPORT);
                }
                if unpatched_peer_takes_it_for_a_handshake(&cfg, &control) {
                    unredrawn_hits += 1;
                }
            }
            assert!(
                unredrawn_hits > N / 100,
                "control: only {unredrawn_hits} of {N} unredrawn datagrams collide"
            );
        }
    }

    /// An unvalidated config whose prefix cannot hold the header-protection
    /// nonce is caught at construction, not on the transport send path.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "S1..S4 >= 12")]
    fn new_rejects_short_prefix_with_header_protection() {
        let mut cfg = awg_cfg(true, false);
        cfg.padding.s4 = 11;
        let _ = Obfuscator::new(Arc::new(cfg));
    }

    #[test]
    fn seal_refuses_oversized_datagram() {
        let mut cfg = awg_cfg(false, true);
        cfg.init_packets.0[0] = Some(CpsChain::parse("<r 8>").unwrap());
        cfg.padding.s1 = u16::MAX;
        let mut rng = DetRng::new(8);
        let msg = message(
            &cfg,
            WgPacketType::HandshakeInit,
            WgHandshakeInit::LEN,
            &mut rng,
        );
        let mut out = Vec::new();
        let r = Obfuscator::new(Arc::new(cfg.clone())).seal_with(
            wg(WgPacketType::HandshakeInit, &msg),
            500,
            &mut out,
            &mut rng,
            NOW,
        );
        assert_eq!(r, Err(SealError::TooLarge));
        assert!(out.is_empty(), "no I-packets or junk without the init");

        // An I-packet that cannot fit in a datagram is refused too.
        let mut cfg = awg_cfg(false, false);
        cfg.init_packets.0[1] = Some(CpsChain::parse("<r 65535><b 0x01>").unwrap());
        let msg = message(
            &cfg,
            WgPacketType::HandshakeInit,
            WgHandshakeInit::LEN,
            &mut rng,
        );
        let r = seal_det(&cfg, WgPacketType::HandshakeInit, &msg, 500, &mut rng);
        assert_eq!(r.err(), Some(SealError::TooLarge));

        // Transport: S4 + 32 is the whole datagram; one byte over is refused.
        let mut cfg = awg_cfg(false, false);
        let msg = message(&cfg, WgPacketType::Data, WgData::OVERHEAD, &mut rng);
        cfg.padding.s4 = (MAX_DATAGRAM_LEN - WgData::OVERHEAD) as u16;
        let out = seal_det(&cfg, WgPacketType::Data, &msg, 500, &mut rng).unwrap();
        assert_eq!(out[0].len(), MAX_DATAGRAM_LEN);
        cfg.padding.s4 += 1;
        let r = seal_det(&cfg, WgPacketType::Data, &msg, 500, &mut rng);
        assert_eq!(r.err(), Some(SealError::TooLarge));
    }

    /// amneziawg-go's receive-side keystream use: XOR the type field with the
    /// first four keystream bytes, then continue the same stream over bytes
    /// `4..n`. Our sender XORs the whole span from offset 0; they must agree.
    fn go_style_decrypt(key: &[u8; 32], datagram: &[u8], padding: usize, n: usize) -> Vec<u8> {
        use chacha20::cipher::{KeyIvInit, StreamCipher};

        let nonce: [u8; 12] = datagram[..12].try_into().unwrap();
        let mut cipher = chacha20::ChaCha20::new(key.into(), (&nonce).into());
        let mut type_hash = [0u8; 4];
        cipher.apply_keystream(&mut type_hash);
        let mut message = datagram[padding..].to_vec();
        for (b, h) in message[..4].iter_mut().zip(type_hash) {
            *b ^= h;
        }
        cipher.apply_keystream(&mut message[4..n]);
        message
    }

    /// Port of awgtun's `awg3_wire_format_matches_go_keystream_sequence`.
    #[test]
    fn go_keystream_differential() {
        let key = [0x42u8; 32];
        let mut cfg = awg_cfg(true, false);
        cfg.header_protection_key = Some(key);
        cfg.padding = Padding {
            s1: 16,
            s2: 16,
            s3: 16,
            s4: 16,
        };
        let mut rng = DetRng::new(9);
        for (kind, len, n) in [
            (
                WgPacketType::HandshakeInit,
                WgHandshakeInit::LEN,
                PROTECTED_LEN_INIT,
            ),
            (
                WgPacketType::HandshakeResp,
                WgHandshakeResp::LEN,
                PROTECTED_LEN_RESPONSE,
            ),
            (
                WgPacketType::CookieReply,
                WgCookieReply::LEN,
                PROTECTED_LEN_COOKIE,
            ),
            (
                WgPacketType::Data,
                WgData::OVERHEAD + 64,
                PROTECTED_LEN_TRANSPORT,
            ),
        ] {
            let msg = message(&cfg, kind, len, &mut rng);
            let out = seal_det(&cfg, kind, &msg, 500, &mut rng).unwrap();
            let datagram = out.last().unwrap();
            let decrypted = go_style_decrypt(&key, datagram, 16, n);

            let h = u32::from_le_bytes(decrypted[..4].try_into().unwrap());
            let r = range_of(&cfg, kind);
            assert!((r.start..=r.end).contains(&h), "{kind:?}: plaintext H");
            let wire = u32::from_le_bytes(datagram[16..20].try_into().unwrap());
            assert_ne!(h, wire, "{kind:?}: H hidden on the wire");
            assert_eq!(
                &decrypted[4..],
                &msg[4..],
                "{kind:?}: Go decrypt recovers it"
            );
            assert_eq!(
                &datagram[16 + n..],
                &msg[n..],
                "{kind:?}: bytes past the protected span go out clear"
            );
        }
    }
}
