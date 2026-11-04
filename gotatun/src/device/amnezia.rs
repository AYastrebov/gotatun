//! AmneziaWG hooks for the device: the send and receive boundaries and the
//! device-wide configuration.
//!
//! Kept out of `device/mod.rs` so the upstream file only carries small,
//! feature-gated calls into this module.

use std::io;
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::sync::RwLock;

use super::{DeviceState, DeviceTransports, PeerState};
use crate::amnezia::classify::Deobfuscator;
use crate::amnezia::seal::Obfuscator;
use crate::amnezia::timers::{timer_extras_from, timer_params_from};
use crate::amnezia::tunn_state::{AmneziaTunnState, INITIAL_UDP_WINDOW};
use crate::amnezia::{AmneziaConfig, ConfigError};
use crate::noise::errors::WireGuardError;
use crate::noise::index_table::IndexTable;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{TimerExtras, TimerParams, Tunn, TunnResult};
use crate::packet::{Packet, WgKind};
use crate::udp::UdpSend;

/// The device-wide AmneziaWG state: the validated config and the send and
/// receive boundaries built from it.
#[derive(Debug)]
pub(super) struct DeviceAmnezia {
    cfg: Arc<AmneziaConfig>,
    obfs: Obfuscator,
    deobfs: Deobfuscator,
}

impl DeviceAmnezia {
    /// Validate `cfg` and build the device state for it. Zero values are read
    /// as the UAPI reads them ([`AmneziaConfig::normalized`]). A config that
    /// is plain WireGuard (or `None`) yields `None`, so the device keeps the
    /// unchanged upstream paths.
    pub(super) fn from_config(
        cfg: Option<AmneziaConfig>,
    ) -> Result<Option<Arc<Self>>, ConfigError> {
        let Some(cfg) = cfg else { return Ok(None) };
        let cfg = cfg.normalized();
        cfg.validate()?;
        if cfg.is_plain_wireguard() {
            return Ok(None);
        }
        let cfg = Arc::new(cfg);
        Ok(Some(Arc::new(DeviceAmnezia {
            obfs: Obfuscator::new(Arc::clone(&cfg)),
            deobfs: Deobfuscator::new(Arc::clone(&cfg)),
            cfg,
        })))
    }

    pub(super) fn obfuscator(&self) -> &Obfuscator {
        &self.obfs
    }
}

/// Send one WireGuard message to `addr`, through the obfuscator when Amnezia
/// is configured: a handshake initiation goes out as I1..I5, junk, then the
/// initiation, all on `udp` in order.
///
/// `window` is the peer's UDP window (see [`udp_window`]). A message the
/// obfuscator cannot frame (over 65535 bytes) is dropped.
pub(super) async fn send_wg(
    udp: &impl UdpSend,
    obfs: Option<&Obfuscator>,
    window: usize,
    packet: WgKind,
    addr: SocketAddr,
) -> io::Result<()> {
    let Some(obfs) = obfs else {
        return udp.send_to(packet.into(), addr).await;
    };
    let mut datagrams = Vec::new();
    if let Err(e) = obfs.seal(packet, window, &mut datagrams) {
        if obfs.first_seal_failure() {
            tracing::warn!("Dropping AmneziaWG message: {e} (further drops are logged at trace)");
        } else {
            tracing::trace!("Dropping AmneziaWG message: {e}");
        }
        return Ok(());
    }
    for datagram in datagrams {
        udp.send_to(datagram, addr).await?;
    }
    Ok(())
}

/// The peer's UDP window, read before its lock is released for the send.
pub(super) fn udp_window(tunnel: &mut Tunn) -> usize {
    tunnel
        .amnezia_udp_window_mut()
        .map_or(INITIAL_UDP_WINDOW, |w| *w)
}

/// Length of the Poly1305 tag that ends every transport message.
const AEAD_TAG_LEN: usize = 16;

/// After a received datagram of `datagram_len` bytes was handled: a decrypted
/// transport packet widens the peer's UDP window by `S4 + 16 + plaintext`,
/// i.e. the datagram without its 16-byte AEAD tag (amneziawg-go
/// `receive.go:517-520`).
pub(super) fn observe_received(tunnel: &mut Tunn, result: &TunnResult, datagram_len: usize) {
    if let TunnResult::WriteToTunnel(_) = result {
        tunnel.widen_amnezia_udp_window(datagram_len.saturating_sub(AEAD_TAG_LEN));
    }
}

/// The device's Amnezia state, shared by the device, the connection tasks and
/// DAITA's sender. [`DeviceState::set_amnezia`] swaps it in place, so a config
/// change never restarts the connection or rebinds UDP (ruling R13: an
/// embedder such as shoes hands over one pre-bound socket pair and cannot
/// bind again). Read per datagram; a swap happens under the device write lock,
/// so readers holding the device read lock see the state that matches the
/// peers' `Tunn`s.
#[derive(Clone, Default)]
pub(super) struct AmneziaCell(Arc<parking_lot::RwLock<Option<Arc<DeviceAmnezia>>>>);

impl AmneziaCell {
    pub(super) fn new(amnezia: Option<Arc<DeviceAmnezia>>) -> Self {
        AmneziaCell(Arc::new(parking_lot::RwLock::new(amnezia)))
    }

    /// The current state, `None` for plain WireGuard.
    pub(super) fn load(&self) -> Option<Arc<DeviceAmnezia>> {
        self.0.read().clone()
    }

    fn store(&self, amnezia: Option<Arc<DeviceAmnezia>>) {
        *self.0.write() = amnezia;
    }
}

/// The obfuscator of a loaded state, for [`send_wg`].
pub(super) fn obfs(amnezia: &Option<Arc<DeviceAmnezia>>) -> Option<&Obfuscator> {
    amnezia.as_deref().map(DeviceAmnezia::obfuscator)
}

/// Stand-in for the [`RateLimiter`] on the receive path. With Amnezia
/// configured, every datagram is classified and de-obfuscated, then verified
/// as the kind it classified as; the plain `verify_packet` would trust the low
/// type byte alone. Without Amnezia it is the upstream `verify_packet`.
pub(super) struct ReceiveGate {
    rate_limiter: Arc<RateLimiter>,
    amnezia: AmneziaCell,
    /// The device's session indices, to tell a transport packet for one of
    /// our sessions from a handshake misread as transport (ruling R14).
    index_table: IndexTable,
}

impl ReceiveGate {
    pub(super) fn new(
        rate_limiter: Arc<RateLimiter>,
        amnezia: AmneziaCell,
        index_table: IndexTable,
    ) -> Self {
        ReceiveGate {
            rate_limiter,
            amnezia,
            index_table,
        }
    }

    /// Same contract as [`RateLimiter::verify_packet`]. Junk, I-packets and
    /// anything else that does not classify are dropped silently.
    pub(super) fn verify_packet(
        &self,
        src_addr: SocketAddr,
        packet: Packet,
    ) -> Result<WgKind, TunnResult> {
        let Some(amnezia) = self.amnezia.load() else {
            return self.rate_limiter.verify_packet(src_addr, packet);
        };
        // With trailers on, an ambiguous datagram is resolved before it is
        // opened: transport with an unknown receiver index is read as a
        // handshake (ruling R14), and among several handshake readings the
        // one whose MAC1 verifies wins (ruling R15).
        let (packet, kind) = amnezia
            .deobfs
            .open_with(
                packet,
                |idx| self.index_table.in_use(idx),
                |_, msg| self.rate_limiter.mac1_matches(msg),
            )
            .ok_or(TunnResult::Err(WireGuardError::InvalidPacket))?;
        self.rate_limiter
            .verify_classified(src_addr, packet, kind, amnezia.cfg.disable_cookies)
    }

    /// The current state, for replies sent before any peer is known
    /// (under-load cookie replies).
    pub(super) fn amnezia(&self) -> Option<Arc<DeviceAmnezia>> {
        self.amnezia.load()
    }
}

impl<T: DeviceTransports> DeviceState<T> {
    /// The receive gate for `handle_incoming`, reading the shared cell.
    pub(super) async fn amnezia_receive_gate(
        device: &Weak<RwLock<Self>>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Option<ReceiveGate> {
        let device = device.upgrade()?;
        let device = device.read().await;
        Some(ReceiveGate::new(
            rate_limiter,
            device.amnezia.clone(),
            device.index_table.clone(),
        ))
    }

    /// The current state, for send sites that hold the device lock.
    pub(super) fn amnezia_current(&self) -> Option<Arc<DeviceAmnezia>> {
        self.amnezia.load()
    }

    /// The device's Amnezia config, `None` for plain WireGuard.
    pub(super) fn amnezia_config(&self) -> Option<AmneziaConfig> {
        self.amnezia.load().map(|a| AmneziaConfig::clone(&a.cfg))
    }

    /// Give a peer's new `Tunn` the device's Amnezia state and timing ranges.
    ///
    /// The timing ranges become the peer's [`TimerParams`] unless it has
    /// explicit `danger_timer_params`, which the caller applies.
    pub(super) fn amnezia_setup_tunn(
        &self,
        tunn: &mut Tunn,
        danger_timer_params: Option<&TimerParams>,
        keepalive_range: Option<&RangeInclusive<u16>>,
    ) {
        let amnezia = self.amnezia.load();
        if let Some(amnezia) = &amnezia {
            tunn.set_amnezia(Some(AmneziaTunnState::new(Arc::clone(&amnezia.cfg))));
        }
        // The per-peer keepalive range applies with or without a device config.
        if amnezia.is_some() || keepalive_range.is_some() {
            tunn.set_timer_extras(self.amnezia_timer_extras(keepalive_range));
        }
        let Some(amnezia) = amnezia else {
            return;
        };
        if danger_timer_params.is_none() {
            tunn.dangerously_set_timer_params(timer_params_from(&amnezia.cfg.timings));
        }
    }

    /// The peer's [`TimerExtras`]: the device-wide ranges plus the peer's
    /// persistent-keepalive range (seconds).
    pub(super) fn amnezia_timer_extras(
        &self,
        keepalive_range: Option<&RangeInclusive<u16>>,
    ) -> TimerExtras {
        let mut extras = self
            .amnezia
            .load()
            .map(|a| timer_extras_from(&a.cfg.timings))
            .unwrap_or_default();
        extras.persistent_keepalive = keepalive_range.map(|r| {
            Duration::from_secs(u64::from(*r.start()))..=Duration::from_secs(u64::from(*r.end()))
        });
        extras
    }

    /// Record `params` as the peer's explicit timer params and return the
    /// params it gets: those, or the device-wide Amnezia timing ranges (`None`
    /// keeps upstream's default).
    pub(super) fn amnezia_timer_params(
        &self,
        peer: &mut PeerState,
        params: Option<TimerParams>,
    ) -> Option<TimerParams> {
        peer.danger_timer_params = params.clone();
        params.or_else(|| {
            self.amnezia
                .load()
                .map(|a| timer_params_from(&a.cfg.timings))
        })
    }

    /// Validate and swap the device's Amnezia config, then rebuild every
    /// peer's `Tunn` (keeping keys, endpoints and explicit timer params), so
    /// each peer handshakes again under the new config.
    ///
    /// The connection keeps running on the same sockets: its tasks read the
    /// swapped state from the shared [`AmneziaCell`] per datagram. Per-peer
    /// tx/rx stats start over and packets queued for a handshake are dropped.
    pub(super) async fn set_amnezia(
        &mut self,
        cfg: Option<AmneziaConfig>,
    ) -> Result<(), ConfigError> {
        let amnezia = DeviceAmnezia::from_config(cfg)?;
        // A Phobos server forwards to plain WireGuard.
        #[cfg(feature = "phobos")]
        if amnezia.is_some() && self.phobos.is_some() {
            return Err(ConfigError::CombinedWithPhobos);
        }
        let current = self.amnezia.load();
        if current.as_ref().map(|a| &a.cfg) == amnezia.as_ref().map(|a| &a.cfg) {
            return Ok(());
        }
        self.amnezia.store(amnezia);

        // Without a key there are no peers yet; they are built from the new
        // config when added.
        if let (Some((private_key, _)), Some(rate_limiter)) = (&self.key_pair, &self.rate_limiter) {
            for (public_key, peer) in &self.peers {
                let mut peer = peer.lock().await;
                let mut tunn = Tunn::new(
                    private_key.clone(),
                    *public_key,
                    peer.tunnel.preshared_key(),
                    peer.tunnel.persistent_keepalive(),
                    self.index_table.clone(),
                    Arc::clone(rate_limiter),
                );
                if let Some(params) = &peer.danger_timer_params {
                    tunn.dangerously_set_timer_params(params.clone());
                }
                self.amnezia_setup_tunn(
                    &mut tunn,
                    peer.danger_timer_params.as_ref(),
                    peer.keepalive_range.as_ref(),
                );
                peer.tunnel = tunn;
            }
        }
        tracing::info!("AmneziaWG configuration updated, peers rebuilt");
        Ok(())
    }
}

/// The UDP sender handed to DAITA, which sends decoys and delayed transport
/// packets on its own: seals them as [`send_wg`] would, with the state current
/// at send time.
#[cfg(feature = "daita")]
#[derive(Clone)]
pub(super) struct SealingUdpSend<U> {
    inner: U,
    amnezia: AmneziaCell,
}

#[cfg(feature = "daita")]
impl<U> SealingUdpSend<U> {
    pub(super) fn new(inner: U, amnezia: AmneziaCell) -> Self {
        SealingUdpSend { inner, amnezia }
    }
}

#[cfg(feature = "daita")]
impl<U: UdpSend> UdpSend for SealingUdpSend<U> {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        let amnezia = self.amnezia.load();
        if amnezia.is_none() {
            return self.inner.send_to(packet, destination).await;
        }
        // DAITA only sends transport packets, whose framing needs no window.
        match packet.try_into_wg() {
            Ok(packet) => {
                send_wg(
                    &self.inner,
                    obfs(&amnezia),
                    INITIAL_UDP_WINDOW,
                    packet,
                    destination,
                )
                .await
            }
            Err(e) => {
                tracing::trace!("Dropping non-WireGuard packet from DAITA: {e}");
                Ok(())
            }
        }
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        self.inner.max_number_of_packets_to_send()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::DeviceAmnezia;
    use crate::amnezia::timers::{timer_extras_from, timer_params_from};
    use crate::amnezia::tunn_state::AmneziaTunnState;
    use crate::amnezia::{AmneziaConfig, CpsChain, U32Range};
    use crate::noise::TimerParams;

    /// Every field the UAPI (and amneziawg-go) reads as "off" or "default"
    /// when zero, set to zero through the Rust API.
    fn with_zero_values(mut cfg: AmneziaConfig) -> AmneziaConfig {
        let zero = Duration::ZERO..=Duration::ZERO;
        cfg.header_protection_key = Some([0; 32]);
        cfg.content_padding = Some(U32Range { lo: 0, hi: 0 });
        cfg.timings.rekey_after_time = Some(zero.clone());
        cfg.timings.rekey_timeout = Some(zero.clone());
        cfg.timings.reject_after_time = Some(zero.clone());
        cfg.timings.keepalive_timeout = Some(zero);
        cfg.timings.max_handshake_attempts = Some(0..=0);
        cfg.init_packets.0[0] = Some(CpsChain::parse("").unwrap());
        cfg
    }

    #[test]
    fn zero_values_alone_are_plain_wireguard() {
        let cfg = with_zero_values(AmneziaConfig::default());
        assert!(DeviceAmnezia::from_config(Some(cfg)).unwrap().is_none());
    }

    #[test]
    fn zero_values_behave_like_none() {
        let mut base = AmneziaConfig::default();
        base.padding.s4 = 8;
        let amnezia = DeviceAmnezia::from_config(Some(with_zero_values(base.clone())))
            .unwrap()
            .unwrap();
        assert_eq!(*amnezia.cfg, base);

        // No header protection, no content padding (x16 and trailers kept),
        // upstream timers.
        assert!(amnezia.cfg.header_protection_key.is_none());
        assert!(!AmneziaTunnState::new(amnezia.cfg.clone()).pads_content());
        assert_eq!(
            timer_params_from(&amnezia.cfg.timings),
            TimerParams::default()
        );
        assert_eq!(timer_extras_from(&amnezia.cfg.timings), Default::default());
    }
}
