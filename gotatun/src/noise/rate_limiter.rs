// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//   Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

use super::handshake::{b2s_hash, b2s_keyed_mac_16, b2s_keyed_mac_16_2, b2s_mac_24};
use crate::noise::handshake::{LABEL_COOKIE, LABEL_MAC1};
use crate::noise::{TunnResult, WireGuardError};
#[cfg(feature = "amnezia")]
use crate::packet::WgPacketType;
use crate::packet::{Packet, WgCookieReply, WgHandshakeBase, WgKind};

use constant_time_eq::constant_time_eq;
use gotatun_crypto::x25519;
#[cfg(feature = "mock_instant")]
use mock_instant::thread_local::Instant;
use rand::TryRngCore;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[cfg(not(feature = "mock_instant"))]
use crate::sleepyinstant::Instant;

use aead::generic_array::GenericArray;
use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use parking_lot::Mutex;
use rand::rngs::OsRng;

const COOKIE_REFRESH: u64 = 128; // Use 128 and not 120 so the compiler can optimize out the division
const COOKIE_SIZE: usize = 16;
const COOKIE_NONCE_SIZE: usize = 24;

/// How often to reset the under-load counter
const RESET_PERIOD: Duration = Duration::from_secs(1);

type Cookie = [u8; COOKIE_SIZE];

struct IpCounts {
    counts: HashMap<IpAddr, u64>,
    last_reset: Instant,
}

/// There are two places where WireGuard requires "randomness" for cookies
/// * The 24 byte nonce in the cookie massage - here the only goal is to avoid nonce reuse
/// * A secret value that changes every two minutes
///
/// Because the main goal of the cookie is simply for a party to prove ownership of an IP address
/// we can relax the randomness definition a bit, in order to avoid locking, because using less
/// resources is the main goal of any DoS prevention mechanism.
/// In order to avoid locking and calls to rand we derive pseudo random values using the AEAD and
/// some counters.
pub struct RateLimiter {
    /// The key we use to derive the nonce
    nonce_key: [u8; 32],
    /// The key we use to derive the cookie
    secret_key: [u8; 16],
    start_time: Instant,
    /// A single 64 bit counter (should suffice for many years)
    nonce_ctr: AtomicU64,
    mac1_key: [u8; 32],
    cookie_key: Key,
    limit: u64,
    /// Per-source-IP packet counts, reset every `RESET_PERIOD`
    ip_counts: Mutex<IpCounts>,
}

impl RateLimiter {
    /// Create a new rate limiter for handshake packets.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The device's public key, used for cookie generation
    /// * `limit` - Maximum number of packets allowed per rate limiting period
    pub fn new(public_key: &x25519::PublicKey, limit: u64) -> Self {
        let mut secret_key = [0u8; 16];
        OsRng.try_fill_bytes(&mut secret_key).unwrap();
        RateLimiter {
            nonce_key: Self::rand_bytes(),
            secret_key,
            start_time: Instant::now(),
            nonce_ctr: AtomicU64::new(0),
            mac1_key: b2s_hash(LABEL_MAC1, public_key.as_bytes()),
            cookie_key: b2s_hash(LABEL_COOKIE, public_key.as_bytes()).into(),
            limit,
            ip_counts: Mutex::new(IpCounts {
                counts: HashMap::new(),
                last_reset: Instant::now(),
            }),
        }
    }

    fn rand_bytes() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.try_fill_bytes(&mut key).unwrap();
        key
    }

    /// Reset packet counts (ideally should be called with a period of 1 second)
    pub fn try_reset_count(&self) {
        let current_time = Instant::now();
        let mut ip_counts = self.ip_counts.lock();
        if current_time.duration_since(ip_counts.last_reset) >= RESET_PERIOD {
            ip_counts.counts.clear();
            ip_counts.last_reset = current_time;
        }
    }

    /// Compute the correct cookie value based on the current secret value and the source address
    fn current_cookie(&self, addr: SocketAddr) -> Cookie {
        let mut addr_bytes = [0u8; 18]; // 16 for IP + 2 for port

        match addr.ip() {
            IpAddr::V4(a) => addr_bytes[..4].copy_from_slice(&a.octets()),
            IpAddr::V6(a) => addr_bytes[..16].copy_from_slice(&a.octets()),
        }
        addr_bytes[16..18].copy_from_slice(&addr.port().to_be_bytes());

        // The current cookie for a given IP is the MAC(responder.changing_secret_every_two_minutes,
        // initiator.address) First we derive the secret from the current time, the value
        // of cur_counter would change with time.
        let cur_counter = Instant::now().duration_since(self.start_time).as_secs() / COOKIE_REFRESH;

        // Next we derive the cookie
        b2s_keyed_mac_16_2(&self.secret_key, &cur_counter.to_le_bytes(), &addr_bytes)
    }

    fn nonce(&self) -> [u8; COOKIE_NONCE_SIZE] {
        let ctr = self.nonce_ctr.fetch_add(1, Ordering::Relaxed);

        b2s_mac_24(&self.nonce_key, &ctr.to_le_bytes())
    }

    /// Increment the per-source-IP handshake counter and return whether it exceeds `self.limit`.
    ///
    /// Counters are cleared every `RESET_PERIOD` by [`try_reset_count`](Self::try_reset_count),
    /// so each IP is independently allowed `limit` handshakes per period.
    fn is_under_load(&self, src_addr: IpAddr) -> bool {
        let mut ip_counts = self.ip_counts.lock();
        let count = ip_counts.counts.entry(src_addr).or_insert(0);
        *count += 1;
        *count > self.limit
    }

    pub(crate) fn format_cookie_reply(
        &self,
        idx: u32,
        cookie: Cookie,
        mac1: &[u8],
    ) -> WgCookieReply {
        let mut wg_cookie_reply = WgCookieReply::new();

        // msg.message_type = 3
        // msg.reserved_zero = { 0, 0, 0 }
        // msg.receiver_index = little_endian(initiator.sender_index)
        wg_cookie_reply.receiver_idx.set(idx);
        wg_cookie_reply.nonce = self.nonce();

        let cipher = XChaCha20Poly1305::new(&self.cookie_key);

        let iv = GenericArray::from_slice(&wg_cookie_reply.nonce);

        wg_cookie_reply.encrypted_cookie.encrypted = cookie;
        let tag = cipher
            .encrypt_in_place_detached(iv, mac1, &mut wg_cookie_reply.encrypted_cookie.encrypted)
            .expect("wg_cookie_reply is large enough");

        wg_cookie_reply.encrypted_cookie.tag = tag.into();
        wg_cookie_reply
    }

    /// Decode the packet as wireguard packet.
    /// Then, verify the MAC fields on the packet (if any), and apply rate limiting if needed.
    pub fn verify_packet(
        &self,
        src_addr: SocketAddr,
        packet: Packet,
    ) -> Result<WgKind, TunnResult> {
        let packet = packet
            .try_into_wg()
            .map_err(|_err| TunnResult::Err(WireGuardError::InvalidPacket))?;

        // Verify and rate limit handshake messages only
        match packet {
            WgKind::HandshakeInit(packet) => self
                .verify_handshake(src_addr, packet)
                .map(WgKind::HandshakeInit),
            WgKind::HandshakeResp(packet) => self
                .verify_handshake(src_addr, packet)
                .map(WgKind::HandshakeResp),
            _ => Ok(packet),
        }
    }

    /// Verify the MAC fields on the handshake, and apply rate limiting if needed.
    pub(crate) fn verify_handshake<P: WgHandshakeBase>(
        &self,
        src_addr: SocketAddr,
        handshake: Packet<P>,
    ) -> Result<Packet<P>, TunnResult> {
        let sender_idx = handshake.sender_idx();
        let mac1 = handshake.mac1();
        let mac2 = handshake.mac2();

        let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, handshake.until_mac1());
        if !constant_time_eq(&computed_mac1, mac1) {
            return Err(TunnResult::Err(WireGuardError::InvalidMac));
        }

        if self.is_under_load(src_addr.ip()) {
            let cookie = self.current_cookie(src_addr);
            let computed_mac2 = b2s_keyed_mac_16_2(&cookie, handshake.until_mac1(), mac1);

            if !constant_time_eq(&computed_mac2, mac2) {
                let cookie_reply = self.format_cookie_reply(sender_idx, cookie, mac1);
                let packet = handshake.overwrite_with(&cookie_reply);
                return Err(TunnResult::WriteToNetwork(packet.into()));
            }

            // If under load but mac2 is valid, allow the handshake
            return Ok(handshake);
        }

        Ok(handshake)
    }
}

#[cfg(feature = "amnezia")]
#[allow(dead_code)] // Consumed by later AmneziaWG tasks; only tests use it yet.
impl RateLimiter {
    /// Like [`RateLimiter::verify_packet`], for a packet already classified by
    /// the AmneziaWG deobfuscator as `kind`.
    ///
    /// The type field may still carry an H value. MACs are verified over the
    /// raw bytes as received (H included), matching amneziawg-go. With
    /// `disable_cookies` the whole under-load path, MAC2 check included, is
    /// skipped. On success the type field is rewritten to the standard
    /// 1/2/3/4 so downstream code sees a normal WireGuard packet. An
    /// under-load cookie reply carries the standard type; the send boundary
    /// applies H3.
    pub(crate) fn verify_classified(
        &self,
        src_addr: SocketAddr,
        packet: Packet,
        kind: WgPacketType,
        disable_cookies: bool,
    ) -> Result<WgKind, TunnResult> {
        let packet = packet
            .try_into_wg_as(kind)
            .map_err(|_err| TunnResult::Err(WireGuardError::InvalidPacket))?;

        match packet {
            WgKind::HandshakeInit(packet) => {
                let mut packet =
                    self.verify_classified_handshake(src_addr, packet, disable_cookies)?;
                packet.set_wire_type(WgPacketType::HandshakeInit.0.into());
                Ok(WgKind::HandshakeInit(packet))
            }
            WgKind::HandshakeResp(packet) => {
                let mut packet =
                    self.verify_classified_handshake(src_addr, packet, disable_cookies)?;
                packet.set_wire_type(WgPacketType::HandshakeResp.0.into());
                Ok(WgKind::HandshakeResp(packet))
            }
            WgKind::CookieReply(mut packet) => {
                packet.set_wire_type(WgPacketType::CookieReply.0.into());
                Ok(WgKind::CookieReply(packet))
            }
            WgKind::Data(mut packet) => {
                packet.header.set_wire_type(WgPacketType::Data.0.into());
                Ok(WgKind::Data(packet))
            }
        }
    }

    /// [`RateLimiter::verify_handshake`], or only the MAC1 check when cookies
    /// are disabled.
    fn verify_classified_handshake<P: WgHandshakeBase>(
        &self,
        src_addr: SocketAddr,
        handshake: Packet<P>,
        disable_cookies: bool,
    ) -> Result<Packet<P>, TunnResult> {
        if !disable_cookies {
            return self.verify_handshake(src_addr, handshake);
        }

        let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, handshake.until_mac1());
        if !constant_time_eq(&computed_mac1, handshake.mac1()) {
            return Err(TunnResult::Err(WireGuardError::InvalidMac));
        }
        Ok(handshake)
    }
}

#[cfg(all(test, feature = "amnezia"))]
mod amnezia_tests {
    use super::*;
    use crate::packet::{WgData, WgHandshakeInit, WgHandshakeResp, WgPacketType};
    use bytes::BytesMut;
    use zerocopy::IntoBytes;

    /// Synthetic H value, well outside 1..=4.
    const H_INIT: u32 = 123_456;
    const H_RESP: u32 = 7_654_321;
    const H_DATA: u32 = 2_000_000_001;

    fn limiter(limit: u64) -> RateLimiter {
        let secret = crate::x25519::StaticSecret::from([7u8; 32]);
        RateLimiter::new(&crate::x25519::PublicKey::from(&secret), limit)
    }

    fn addr() -> SocketAddr {
        "192.0.2.1:51820".parse().unwrap()
    }

    /// Recompute mac1 over the current bytes (including the wire type field).
    fn set_mac1<P: WgHandshakeBase>(rl: &RateLimiter, hs: &mut P) {
        let mac1 = b2s_keyed_mac_16(&rl.mac1_key, hs.until_mac1());
        *hs.mac1_mut() = mac1;
    }

    fn init_with_h(rl: &RateLimiter) -> WgHandshakeInit {
        let mut init = WgHandshakeInit::new();
        init.sender_idx.set(42);
        init.unencrypted_ephemeral = [9; 32];
        init.set_wire_type(H_INIT);
        set_mac1(rl, &mut init);
        init
    }

    #[test]
    fn verify_classified_accepts_mac_over_h_value() {
        let rl = limiter(10);
        let init = init_with_h(&rl);
        assert_eq!(&init.as_bytes()[..4], &H_INIT.to_le_bytes());

        let p = Packet::copy_from(&init).into_bytes();
        let res = rl.verify_classified(addr(), p, WgPacketType::HandshakeInit, false);
        let Ok(WgKind::HandshakeInit(p)) = res else {
            panic!("expected Ok(HandshakeInit), got {res:?}");
        };
        assert_eq!(&p.as_bytes()[..4], &[1, 0, 0, 0]);
        assert_eq!(p.sender_idx.get(), 42);
    }

    #[test]
    fn verify_classified_accepts_response_over_h_value() {
        let rl = limiter(10);
        let mut resp = WgHandshakeResp::new(5, 6, [3; 32]);
        resp.set_wire_type(H_RESP);
        set_mac1(&rl, &mut resp);

        let p = Packet::copy_from(&resp).into_bytes();
        let res = rl.verify_classified(addr(), p, WgPacketType::HandshakeResp, false);
        let Ok(WgKind::HandshakeResp(p)) = res else {
            panic!("expected Ok(HandshakeResp), got {res:?}");
        };
        assert_eq!(&p.as_bytes()[..4], &[2, 0, 0, 0]);
    }

    #[test]
    fn verify_classified_rejects_mac_mismatch_after_retype() {
        let rl = limiter(10);
        let mut init = WgHandshakeInit::new();
        init.sender_idx.set(42);
        // MACs computed over the standard type 1 ...
        set_mac1(&rl, &mut init);
        // ... but the wire carries H.
        init.set_wire_type(H_INIT);

        let p = Packet::copy_from(&init).into_bytes();
        let res = rl.verify_classified(addr(), p, WgPacketType::HandshakeInit, false);
        assert!(
            matches!(res, Err(TunnResult::Err(WireGuardError::InvalidMac))),
            "got {res:?}"
        );
    }

    #[test]
    fn disable_cookies_skips_mac2_under_load() {
        // limit 0: every handshake counts as under load.
        let rl = limiter(0);

        // Cookies on: mac2 is missing, so we get a standard-type cookie reply.
        let p = Packet::copy_from(&init_with_h(&rl)).into_bytes();
        let res = rl.verify_classified(addr(), p, WgPacketType::HandshakeInit, false);
        let Err(TunnResult::WriteToNetwork(WgKind::CookieReply(reply))) = res else {
            panic!("expected cookie reply, got {res:?}");
        };
        assert_eq!(&reply.as_bytes()[..4], &[3, 0, 0, 0]);
        assert_eq!(reply.receiver_idx.get(), 42);

        // Cookies off: the whole under-load path, mac2 included, is skipped.
        let p = Packet::copy_from(&init_with_h(&rl)).into_bytes();
        let res = rl.verify_classified(addr(), p, WgPacketType::HandshakeInit, true);
        let Ok(WgKind::HandshakeInit(p)) = res else {
            panic!("expected Ok(HandshakeInit), got {res:?}");
        };
        assert_eq!(&p.as_bytes()[..4], &[1, 0, 0, 0]);

        // Cookies off still checks mac1.
        let mut bad = init_with_h(&rl);
        bad.mac1[0] ^= 1;
        let p = Packet::copy_from(&bad).into_bytes();
        let res = rl.verify_classified(addr(), p, WgPacketType::HandshakeInit, true);
        assert!(
            matches!(res, Err(TunnResult::Err(WireGuardError::InvalidMac))),
            "got {res:?}"
        );
    }

    #[test]
    fn verify_classified_retypes_data_and_checks_size() {
        let rl = limiter(10);
        let mut bytes = [0xabu8; WgData::OVERHEAD + 32];
        bytes[..4].copy_from_slice(&H_DATA.to_le_bytes());
        let p = Packet::from_bytes(BytesMut::from(&bytes[..]));
        let res = rl.verify_classified(addr(), p, WgPacketType::Data, false);
        let Ok(WgKind::Data(p)) = res else {
            panic!("expected Ok(Data), got {res:?}");
        };
        assert_eq!(&p.as_bytes()[..4], &[4, 0, 0, 0]);
        assert_eq!(&p.as_bytes()[4..], &bytes[4..]);

        // Too short for the classified kind.
        let p = Packet::from_bytes(BytesMut::from(&bytes[..WgData::OVERHEAD - 1]));
        let res = rl.verify_classified(addr(), p, WgPacketType::Data, false);
        assert!(
            matches!(res, Err(TunnResult::Err(WireGuardError::InvalidPacket))),
            "got {res:?}"
        );

        // Handshake kind with the wrong length.
        let short = [0u8; WgHandshakeInit::LEN - 1];
        let p = Packet::from_bytes(BytesMut::from(&short[..]));
        let res = rl.verify_classified(addr(), p, WgPacketType::HandshakeInit, false);
        assert!(
            matches!(res, Err(TunnResult::Err(WireGuardError::InvalidPacket))),
            "got {res:?}"
        );
    }
}
