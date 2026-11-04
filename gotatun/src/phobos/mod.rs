//! Phobos UDP obfuscation, client side.
//!
//! [Phobos](https://github.com/Ground-Zerro/Phobos) puts an obfuscating proxy
//! in front of a standard WireGuard server. Each WireGuard message is XORed
//! with a key-derived keystream, gets a random tail, and is framed as a STUN
//! Data Indication or an RTP packet. This module is that transformation for a
//! client. It owns no socket and no timer, and it has no tie to [`Tunn`]: the
//! caller runs every outgoing datagram through [`PhobosCodec::wrap`] and every
//! incoming one through [`PhobosCodec::unwrap`].
//!
//! The wire format is specified by the reference's observable behaviour, and this module is
//! written from that description. Don't port code from the Phobos tree: it is
//! (A)GPL-licensed and gotatun is BSD-3-Clause.
//!
//! # Not combinable with AmneziaWG
//!
//! A Phobos server forwards to plain kernel WireGuard, and its decoder relies
//! on bytes 1–3 of every WireGuard message being zero. Use Phobos with a
//! [`Tunn`] built by [`Tunn::new`], never one with AmneziaWG obfuscation enabled.
//!
//! # What the caller must do
//!
//! - Send the Binding Request that [`PhobosCodec::wrap`] returns *before* the
//!   wrapped datagram.
//! - Send [`Unwrapped::Reply`] back to the peer.
//! - Every [`PhobosCodec::control_interval`], send
//!   [`PhobosCodec::binding_request`].
//! - After the local address changes, start a new handshake rather than
//!   sending a keepalive. The server drops non-handshake traffic from an
//!   address it has not seen complete a handshake.
//! - Lower the tunnel MTU by [`Masking::overhead`].
//!
//! [`PhobosUdpFactory`] does all of this but the MTU for a
//! [`Device`](crate::device::Device): it wraps any [`UdpTransportFactory`]
//! and hands the device a [`PhobosHandle`] through which it asks for the
//! handshake. See its docs for the rebind gate.
//!
//! [`Tunn`]: crate::noise::Tunn
//! [`Tunn::new`]: crate::noise::Tunn::new
//! [`UdpTransportFactory`]: crate::udp::UdpTransportFactory

mod codec;
#[cfg(test)]
mod test_vectors;
mod transport;
#[cfg(test)]
pub(crate) use transport::testing;

use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng, TryRngCore};
use rand_chacha::ChaCha20Rng;

pub use codec::*;
pub use transport::{
    CONTROL_SESSION_WINDOW, PhobosHandle, PhobosUdpFactory, PhobosUdpRecv, PhobosUdpSend,
};

/// A [`PhobosConfig`] field could not be set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A key has an unusable value.
    #[error("invalid value for `{field}`: {reason}")]
    InvalidFieldValue {
        /// The key name.
        field: String,
        /// Why it was rejected.
        reason: &'static str,
    },
}

/// A source of random bytes and bounded integers.
pub trait RandomSource {
    /// Fill `out` with random bytes.
    fn fill_bytes(&mut self, out: &mut [u8]);

    /// A uniform value in `[start, end]` (inclusive). An inverted range
    /// (`start > end`) yields `start`.
    fn gen_range_u32(&mut self, start: u32, end: u32) -> u32 {
        if start >= end {
            return start;
        }
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        let raw = u32::from_le_bytes(buf);
        match (end - start).checked_add(1) {
            Some(range) => start + (raw % range),
            // Full `u32` span: every value is already in range.
            None => raw,
        }
    }

    /// A uniform value in `[start, end]` (inclusive).
    fn gen_range_u16(&mut self, start: u16, end: u16) -> u16 {
        self.gen_range_u32(u32::from(start), u32::from(end)) as u16
    }
}

/// Default random source: a ChaCha20 stream seeded from the OS.
///
/// Used for wire filler (tails, dummy lengths, transaction ids, RTP start
/// values), which needs to be unpredictable but not long-lived secret.
#[derive(Debug, Clone)]
pub struct SystemRandom(ChaCha20Rng);

impl SystemRandom {
    /// Seed a new stream from the OS RNG.
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        OsRng.try_fill_bytes(&mut seed).expect("OS RNG failure");
        SystemRandom(ChaCha20Rng::from_seed(seed))
    }
}

impl Default for SystemRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl RandomSource for SystemRandom {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.0.fill_bytes(out);
    }
}
