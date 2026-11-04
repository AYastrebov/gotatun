//! AmneziaWG hooks for the device: the send and receive boundaries and the
//! device-wide configuration.
//!
//! Kept out of `device/mod.rs` so the upstream file only carries small,
//! feature-gated calls into this module.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};

use tokio::sync::RwLock;

use super::{DeviceState, DeviceTransports, PeerState, Reconfigure};
use crate::amnezia::classify::Deobfuscator;
use crate::amnezia::seal::Obfuscator;
use crate::amnezia::timers::{timer_extras_from, timer_params_from};
use crate::amnezia::tunn_state::{AmneziaTunnState, INITIAL_UDP_WINDOW};
use crate::amnezia::{AmneziaConfig, ConfigError};
use crate::noise::errors::WireGuardError;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{TimerParams, Tunn, TunnResult};
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
    /// Validate `cfg` and build the device state for it. A config that is
    /// plain WireGuard (or `None`) yields `None`, so the device keeps the
    /// unchanged upstream paths.
    pub(super) fn from_config(
        cfg: Option<AmneziaConfig>,
    ) -> Result<Option<Arc<Self>>, ConfigError> {
        let Some(cfg) = cfg else { return Ok(None) };
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
        tracing::trace!("Dropping AmneziaWG message: {e}");
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

/// Stand-in for the [`RateLimiter`] on the receive path. With Amnezia
/// configured, every datagram is classified and de-obfuscated, then verified
/// as the kind it classified as; the plain `verify_packet` would trust the low
/// type byte alone. Without Amnezia it is the upstream `verify_packet`.
pub(super) struct ReceiveGate {
    rate_limiter: Arc<RateLimiter>,
    amnezia: Option<Arc<DeviceAmnezia>>,
}

impl ReceiveGate {
    pub(super) fn new(rate_limiter: Arc<RateLimiter>, amnezia: Option<Arc<DeviceAmnezia>>) -> Self {
        ReceiveGate {
            rate_limiter,
            amnezia,
        }
    }

    /// Same contract as [`RateLimiter::verify_packet`]. Junk, I-packets and
    /// anything else that does not classify are dropped silently.
    pub(super) fn verify_packet(
        &self,
        src_addr: SocketAddr,
        packet: Packet,
    ) -> Result<WgKind, TunnResult> {
        let Some(amnezia) = &self.amnezia else {
            return self.rate_limiter.verify_packet(src_addr, packet);
        };
        let (packet, kind) = amnezia
            .deobfs
            .open(packet)
            .ok_or(TunnResult::Err(WireGuardError::InvalidPacket))?;
        self.rate_limiter
            .verify_classified(src_addr, packet, kind, amnezia.cfg.disable_cookies)
    }

    /// The obfuscator for replies sent before any peer is known (under-load
    /// cookie replies).
    pub(super) fn obfuscator(&self) -> Option<&Obfuscator> {
        self.amnezia.as_deref().map(DeviceAmnezia::obfuscator)
    }
}

impl<T: DeviceTransports> DeviceState<T> {
    /// The device's Amnezia state as the connection tasks see it. They take
    /// it once when they start; [`DeviceState::set_amnezia`] restarts them.
    pub(super) async fn amnezia_snapshot(
        device: &Weak<RwLock<Self>>,
    ) -> Option<Arc<DeviceAmnezia>> {
        let device = device.upgrade()?;
        let device = device.read().await;
        device.amnezia.clone()
    }

    /// The obfuscator, for send sites that hold the device lock.
    pub(super) fn amnezia_obfuscator(&self) -> Option<&Obfuscator> {
        self.amnezia.as_deref().map(DeviceAmnezia::obfuscator)
    }

    /// The device's Amnezia config, `None` for plain WireGuard.
    pub(super) fn amnezia_config(&self) -> Option<AmneziaConfig> {
        self.amnezia.as_ref().map(|a| AmneziaConfig::clone(&a.cfg))
    }

    /// Give a peer's new `Tunn` the device's Amnezia state and timing ranges.
    ///
    /// The timing ranges become the peer's [`TimerParams`] unless it has
    /// explicit `danger_timer_params`, which the caller applies.
    pub(super) fn amnezia_setup_tunn(
        &self,
        tunn: &mut Tunn,
        danger_timer_params: Option<&TimerParams>,
    ) {
        let Some(amnezia) = &self.amnezia else { return };
        tunn.set_amnezia(Some(AmneziaTunnState::new(Arc::clone(&amnezia.cfg))));
        tunn.set_timer_extras(timer_extras_from(&amnezia.cfg.timings));
        if danger_timer_params.is_none() {
            tunn.dangerously_set_timer_params(timer_params_from(&amnezia.cfg.timings));
        }
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
                .as_ref()
                .map(|a| timer_params_from(&a.cfg.timings))
        })
    }

    /// Validate and swap the device's Amnezia config, then rebuild every
    /// peer's `Tunn` (keeping keys, endpoints and explicit timer params), so
    /// each peer handshakes again under the new config.
    ///
    /// Returns whether the connection must be restarted: its tasks hold the
    /// previous config.
    pub(super) async fn set_amnezia(
        &mut self,
        cfg: Option<AmneziaConfig>,
    ) -> Result<Reconfigure, ConfigError> {
        let amnezia = DeviceAmnezia::from_config(cfg)?;
        if self.amnezia.as_ref().map(|a| &a.cfg) == amnezia.as_ref().map(|a| &a.cfg) {
            return Ok(Reconfigure::No);
        }
        self.amnezia = amnezia;

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
                self.amnezia_setup_tunn(&mut tunn, peer.danger_timer_params.as_ref());
                peer.tunnel = tunn;
            }
        }
        tracing::info!("AmneziaWG configuration updated, peers rebuilt");

        Ok(if self.connection.is_some() {
            Reconfigure::Yes
        } else {
            Reconfigure::No
        })
    }
}

/// The UDP sender handed to DAITA, which sends decoys and delayed transport
/// packets on its own: seals them as [`send_wg`] would.
#[cfg(feature = "daita")]
#[derive(Clone)]
pub(super) struct SealingUdpSend<U> {
    inner: U,
    obfs: Option<Obfuscator>,
}

#[cfg(feature = "daita")]
impl<U> SealingUdpSend<U> {
    pub(super) fn new(inner: U, amnezia: Option<&DeviceAmnezia>) -> Self {
        SealingUdpSend {
            inner,
            obfs: amnezia.map(|a| a.obfs.clone()),
        }
    }
}

#[cfg(feature = "daita")]
impl<U: UdpSend> UdpSend for SealingUdpSend<U> {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        let Some(obfs) = &self.obfs else {
            return self.inner.send_to(packet, destination).await;
        };
        // DAITA only sends transport packets, whose framing needs no window.
        match packet.try_into_wg() {
            Ok(packet) => {
                send_wg(
                    &self.inner,
                    Some(obfs),
                    INITIAL_UDP_WINDOW,
                    packet,
                    destination,
                )
                .await
            }
            Err(_) => Ok(()),
        }
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        self.inner.max_number_of_packets_to_send()
    }
}
