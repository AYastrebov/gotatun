//! Per-tunnel AmneziaWG state carried by a [`Tunn`](crate::noise::Tunn).

use std::sync::Arc;

use super::config::{AmneziaConfig, HeaderRange, HeaderRanges};
use super::rng::{FastRandom, RandomSource};

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
}

impl AmneziaTunnState {
    pub(crate) fn new(cfg: Arc<AmneziaConfig>) -> Self {
        AmneziaTunnState {
            cfg,
            udp_window: INITIAL_UDP_WINDOW,
        }
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
}
