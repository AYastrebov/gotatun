//! Junk packet generation.

use super::config::Junk;
use super::rng::RandomSource;

impl Junk {
    /// Append `count` random datagrams to `out`.
    ///
    /// Sizes are drawn from the half-open range `[min, max)`, matching
    /// amneziawg-go's `min + fastrandn(max - min)`. When `min >= max` every
    /// datagram has size `min`.
    pub(crate) fn render_into(&self, rng: &mut dyn RandomSource, out: &mut Vec<Vec<u8>>) {
        out.reserve(usize::from(self.count));
        for _ in 0..self.count {
            let size = if self.max <= self.min {
                self.min
            } else {
                rng.range_u32(u32::from(self.min), u32::from(self.max) - 1) as u16
            };
            let mut buf = vec![0u8; usize::from(size)];
            rng.fill(&mut buf);
            out.push(buf);
        }
    }
}

/// Random trailer length for a packet of `size` bytes in a `window`-byte UDP
/// budget: uniform in the half-open `[0, window - size)`, or 0 once the packet
/// fills the window. Mirrors `randomTrailer` in amneziawg-go's `send.go`.
pub(crate) fn random_trailer_len(rng: &mut dyn RandomSource, window: usize, size: usize) -> usize {
    match window.checked_sub(size) {
        Some(space) if space > 0 => {
            let hi = u32::try_from(space - 1).unwrap_or(u32::MAX);
            rng.range_u32(0, hi) as usize
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::super::rng::DetRng;
    use super::*;

    #[test]
    fn junk_disabled_produces_nothing() {
        let mut out = Vec::new();
        Junk::default().render_into(&mut DetRng::new(0), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn junk_sizes_half_open() {
        let junk = Junk {
            count: 10,
            min: 64,
            max: 66,
        };
        let mut sizes = std::collections::HashSet::new();
        for seed in 0..32u8 {
            let mut out = Vec::new();
            junk.render_into(&mut DetRng::new(seed), &mut out);
            assert_eq!(out.len(), 10);
            for pkt in out {
                assert!(pkt.len() == 64 || pkt.len() == 65, "size {}", pkt.len());
                sizes.insert(pkt.len());
            }
        }
        assert_eq!(sizes.len(), 2);
    }

    #[test]
    fn junk_fixed_size_when_min_equals_max() {
        let junk = Junk {
            count: 2,
            min: 100,
            max: 100,
        };
        let mut out = Vec::new();
        junk.render_into(&mut DetRng::new(0), &mut out);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|p| p.len() == 100));
    }

    #[test]
    fn trailer_len_half_open() {
        let mut seen = std::collections::HashSet::new();
        for seed in 0..32u8 {
            let mut rng = DetRng::new(seed);
            for _ in 0..16 {
                let n = random_trailer_len(&mut rng, 102, 100);
                assert!(n < 2, "trailer {n} out of [0, 2)");
                seen.insert(n);
            }
        }
        assert_eq!(seen.len(), 2);
        let mut rng = DetRng::new(0);
        assert_eq!(random_trailer_len(&mut rng, 100, 100), 0);
        assert_eq!(random_trailer_len(&mut rng, 100, 500), 0);
        assert_eq!(random_trailer_len(&mut rng, 101, 100), 0);
    }
}
