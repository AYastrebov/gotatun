//! Per-tunnel AmneziaWG state carried by a [`Tunn`](crate::noise::Tunn).

use std::sync::Arc;

use super::config::{AmneziaConfig, HeaderRange, HeaderRanges};
use super::junk::random_trailer_len;
use super::rng::{FastRandom, RandomSource};
use super::seal::MAX_DATAGRAM_LEN;
use crate::packet::{Packet, WgData};

/// Starting UDP window for random trailers and content padding, in bytes.
/// Matches amneziawg-go and awgtun; it widens to the largest datagram seen.
pub(crate) const INITIAL_UDP_WINDOW: usize = 500;

/// Draws the H1/H2 values written into handshake messages before their MACs
/// are computed, so the MACs cover the on-wire type field (amneziawg-go
/// writes `msgType` into the message before `addMacs`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct WireTypes {
    ranges: HeaderRanges,
}

impl WireTypes {
    pub(crate) fn new(ranges: HeaderRanges) -> Self {
        WireTypes { ranges }
    }

    /// A handshake-initiation type value from H1.
    pub(crate) fn init(&self) -> u32 {
        pick(self.ranges.init)
    }

    /// A handshake-response type value from H2.
    pub(crate) fn resp(&self) -> u32 {
        pick(self.ranges.response)
    }
}

fn pick(range: HeaderRange) -> u32 {
    FastRandom.range_u32(range.start, range.end)
}

/// AmneziaWG state owned by one [`Tunn`](crate::noise::Tunn).
///
/// The UDP window lives only here: the transport send path borrows it from
/// the peer's `Tunn` and widens it as larger datagrams go out.
#[derive(Debug, Clone)]
pub(crate) struct AmneziaTunnState {
    cfg: Arc<AmneziaConfig>,
    /// Read by content padding and the device send path.
    udp_window: usize,
    /// The TUN MTU last seen on the send path, an extra bound on content
    /// padding. `None` until a packet arrives with an MTU.
    mtu: Option<usize>,
}

impl AmneziaTunnState {
    pub(crate) fn new(cfg: Arc<AmneziaConfig>) -> Self {
        AmneziaTunnState {
            cfg,
            udp_window: INITIAL_UDP_WINDOW,
            mtu: None,
        }
    }

    /// Whether transport payloads get AWG padding (content padding or
    /// trailer-sized padding) instead of WireGuard's pad-to-16.
    pub(crate) fn pads_content(&self) -> bool {
        self.cfg.content_padding.is_some() || self.cfg.random_trailers
    }

    /// Remember the TUN MTU, the extra bound on content padding.
    pub(crate) fn set_mtu(&mut self, mtu: usize) {
        self.mtu = Some(mtu);
    }

    /// Raise the UDP window to cover a datagram of `size` bytes.
    ///
    /// Unconditional, as in amneziawg-go: content padding is measured against
    /// the window even when trailers are off.
    pub(crate) fn widen_udp_window(&mut self, size: usize) {
        self.udp_window = self.udp_window.max(size);
    }

    /// Reset the UDP window to [`INITIAL_UDP_WINDOW`]; it is a high-water mark
    /// of one path, so it starts over when the endpoint changes.
    pub(crate) fn reset_udp_window(&mut self) {
        self.udp_window = INITIAL_UDP_WINDOW;
    }

    /// Zero bytes to append to a `payload_len`-byte transport plaintext, or
    /// `None` when neither content padding nor random trailers is on (the
    /// caller then keeps WireGuard's pad-to-16).
    ///
    /// Mirrors amneziawg-go `send.go` (`RoutineEncryption`): content padding
    /// draws from its range, bounded by the window; failing that, random
    /// trailers draw uniformly from `[0, window - datagram)`. The size replaces
    /// the 16-byte alignment rather than adding to it. `datagram` is the whole
    /// datagram, `S4 + 32 + payload_len`. Beyond Go, the pad is also clamped by
    /// `mtu - datagram` (when known) and by the 65535-byte datagram limit.
    pub(crate) fn content_padding(
        &self,
        payload_len: usize,
        mtu: Option<usize>,
        rng: &mut dyn RandomSource,
    ) -> Option<usize> {
        let datagram = usize::from(self.cfg.padding.s4) + WgData::OVERHEAD + payload_len;
        let window = self.udp_window;
        let pick = if let Some(range) = self.cfg.content_padding {
            match window.checked_sub(datagram) {
                Some(space) => (rng.range_u32(range.lo, range.hi) as usize).min(space),
                None => 0,
            }
        } else if self.cfg.random_trailers {
            random_trailer_len(rng, window, datagram)
        } else {
            return None;
        };
        let pick = match mtu {
            Some(mtu) => pick.min(mtu.saturating_sub(datagram)),
            None => pick,
        };
        Some(pick.min(MAX_DATAGRAM_LEN.saturating_sub(datagram)))
    }

    /// The send-side transport hook, run on the plaintext just before
    /// encryption: widen the window with the pre-padding datagram size
    /// (`S4 + 32 + payload`, amneziawg-go `send.go:584-587`), then append the
    /// content padding. Returns whether the payload was a keepalive (empty
    /// before padding).
    pub(crate) fn pad_transport(&mut self, packet: &mut Packet) -> bool {
        self.pad_transport_with(packet, &mut FastRandom)
    }

    pub(crate) fn pad_transport_with(
        &mut self,
        packet: &mut Packet,
        rng: &mut dyn RandomSource,
    ) -> bool {
        let len = packet.len();
        self.widen_udp_window(usize::from(self.cfg.padding.s4) + WgData::OVERHEAD + len);
        if let Some(pad) = self.content_padding(len, self.mtu, rng) {
            packet.buf_mut().resize(len + pad, 0);
        }
        len == 0
    }

    /// The UDP window, for the send boundary to size trailers and widen.
    pub(crate) fn udp_window_mut(&mut self) -> &mut usize {
        &mut self.udp_window
    }

    /// The H1/H2 drawer for this tunnel's handshakes.
    pub(crate) fn wire_types(&self) -> WireTypes {
        WireTypes::new(self.cfg.headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges() -> HeaderRanges {
        HeaderRanges {
            init: HeaderRange {
                start: 1_200_000,
                end: 2_200_000,
            },
            response: HeaderRange {
                start: 3_200_000,
                end: 4_200_000,
            },
            ..HeaderRanges::default()
        }
    }

    #[test]
    fn wire_types_draw_from_their_ranges() {
        let wt = WireTypes::new(ranges());
        let (h1, h2) = (ranges().init, ranges().response);
        let inits: Vec<u32> = (0..200).map(|_| wt.init()).collect();
        assert!(inits.iter().all(|v| (h1.start..=h1.end).contains(v)));
        assert!(
            inits.iter().any(|v| *v != inits[0]),
            "values vary across draws"
        );
        assert!((0..200).all(|_| (h2.start..=h2.end).contains(&wt.resp())));
    }

    #[test]
    fn default_ranges_give_plain_types() {
        let wt = WireTypes::new(HeaderRanges::default());
        assert_eq!(wt.init(), 1);
        assert_eq!(wt.resp(), 2);
    }

    #[test]
    fn udp_window_starts_at_500() {
        let state = AmneziaTunnState::new(Arc::new(AmneziaConfig::default()));
        assert_eq!(state.udp_window, 500);
    }

    use super::super::config::{Padding, U32Range};
    use super::super::rng::DetRng;

    const S4: usize = 19;

    fn padded_state(content: Option<(u32, u32)>, trailers: bool) -> AmneziaTunnState {
        AmneziaTunnState::new(Arc::new(AmneziaConfig {
            padding: Padding {
                s1: 23,
                s2: 87,
                s3: 31,
                s4: S4 as u16,
            },
            content_padding: content.map(|(lo, hi)| U32Range { lo, hi }),
            random_trailers: trailers,
            ..AmneziaConfig::default()
        }))
    }

    /// The pad is `min(pick, window - datagram, mtu - datagram, buffer -
    /// datagram)`, with `datagram = S4 + 32 + payload`.
    #[test]
    fn content_padding_bounded_by_window_mtu_buffer() {
        let mut rng = DetRng::new(7);
        let state = padded_state(Some((1000, 1000)), false);
        let datagram = S4 + WgData::OVERHEAD + 100;

        // The window (500) bounds a 1000-byte pick.
        assert_eq!(
            state.content_padding(100, None, &mut rng),
            Some(500 - datagram)
        );
        // The MTU bounds it further when tighter.
        assert_eq!(
            state.content_padding(100, Some(300), &mut rng),
            Some(300 - datagram)
        );
        // A datagram already past the window or MTU gets nothing.
        assert_eq!(state.content_padding(600, None, &mut rng), Some(0));
        assert_eq!(state.content_padding(100, Some(100), &mut rng), Some(0));

        // A wide window leaves the pick itself as the bound.
        let mut state = padded_state(Some((10, 40)), false);
        state.widen_udp_window(10_000);
        for _ in 0..200 {
            let pad = state.content_padding(100, Some(1420), &mut rng).unwrap();
            assert!((10..=40).contains(&pad), "pad {pad} outside 10..=40");
        }
    }

    #[test]
    fn content_padding_never_exceeds_buffer() {
        let mut rng = DetRng::new(3);
        for (content, trailers) in [(Some((65_535, 65_535)), false), (None, true)] {
            let mut state = padded_state(content, trailers);
            state.widen_udp_window(1 << 20);
            for payload in [0, 1_000, 60_000, 65_000, 70_000] {
                let pad = state.content_padding(payload, None, &mut rng).unwrap();
                let datagram = S4 + WgData::OVERHEAD + payload;
                assert!(
                    pad == 0 || datagram + pad <= MAX_DATAGRAM_LEN,
                    "payload {payload}: datagram {datagram} + pad {pad} > 65535"
                );
            }
        }
    }

    /// Every transport payload widens the window by its pre-padding datagram
    /// size, whatever the padding mode; the window never shrinks and resets
    /// to 500.
    #[test]
    fn window_widens_unconditionally() {
        for (content, trailers) in [(None, false), (None, true), (Some((1, 64)), false)] {
            let mut state = padded_state(content, trailers);
            let mut big = Packet::from_bytes(bytes::BytesMut::zeroed(1_400));
            state.pad_transport_with(&mut big, &mut DetRng::new(1));
            assert_eq!(state.udp_window, S4 + WgData::OVERHEAD + 1_400);

            let mut small = Packet::from_bytes(bytes::BytesMut::zeroed(10));
            state.pad_transport_with(&mut small, &mut DetRng::new(2));
            assert_eq!(
                state.udp_window,
                S4 + WgData::OVERHEAD + 1_400,
                "never shrinks"
            );

            state.reset_udp_window();
            assert_eq!(state.udp_window, INITIAL_UDP_WINDOW);
        }
    }

    /// Random trailers size the transport padding only when content padding
    /// is unset; content padding wins when both are on, and neither leaves
    /// WireGuard's pad-to-16 in place.
    #[test]
    fn trailers_widen_transport_padding_only_when_unset() {
        let mut rng = DetRng::new(11);
        let datagram = S4 + WgData::OVERHEAD + 100;

        let both = padded_state(Some((4, 8)), true);
        for _ in 0..200 {
            let pad = both.content_padding(100, None, &mut rng).unwrap();
            assert!((4..=8).contains(&pad), "content padding wins, got {pad}");
        }

        let trailers = padded_state(None, true);
        let pads: Vec<usize> = (0..400)
            .map(|_| trailers.content_padding(100, None, &mut rng).unwrap())
            .collect();
        assert!(pads.iter().all(|p| *p < 500 - datagram), "half-open window");
        assert!(pads.iter().any(|p| *p > 64), "trailer-sized padding");

        assert_eq!(
            padded_state(None, false).content_padding(100, None, &mut rng),
            None
        );
    }

    #[test]
    fn keepalive_reported_before_padding() {
        let mut state = padded_state(Some((16, 16)), false);
        let mut keepalive = Packet::from_bytes(bytes::BytesMut::new());
        assert!(state.pad_transport_with(&mut keepalive, &mut DetRng::new(0)));
        assert_eq!(keepalive.len(), 16);
        assert!(keepalive.iter().all(|b| *b == 0), "padding is zeros");

        let mut data = Packet::from_bytes(bytes::BytesMut::zeroed(20));
        assert!(!state.pad_transport_with(&mut data, &mut DetRng::new(0)));
        assert_eq!(data.len(), 36);
    }
}
