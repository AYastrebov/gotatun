use super::*;
use crate::amnezia::classify::Deobfuscator;
use crate::amnezia::rng::DetRng;
use crate::amnezia::seal::Obfuscator;
use crate::amnezia::{AmneziaConfig, HeaderRange, HeaderRanges, Padding};

/// Synthetic AWG parameters with the real shape: S2 > 64, H ranges
/// millions wide. No header protection, so the test sender below only
/// has to prepend the S-prefix.
fn awg_cfg(s1: u16, s2: u16) -> Arc<AmneziaConfig> {
    Arc::new(AmneziaConfig {
        headers: HeaderRanges {
            init: HeaderRange {
                start: 1_300_000,
                end: 2_300_000,
            },
            response: HeaderRange {
                start: 3_300_000,
                end: 4_300_000,
            },
            cookie: HeaderRange {
                start: 5_300_000,
                end: 6_300_000,
            },
            transport: HeaderRange {
                start: 7_300_000,
                end: 8_300_000,
            },
        },
        padding: Padding {
            s1,
            s2,
            s3: 31,
            s4: 19,
        },
        ..AmneziaConfig::default()
    })
}

fn awg_tuns(cfg: &Arc<AmneziaConfig>) -> (Tunn, Tunn) {
    let (mut a, mut b) = create_two_tuns();
    a.set_amnezia(Some(AmneziaTunnState::new(cfg.clone())));
    b.set_amnezia(Some(AmneziaTunnState::new(cfg.clone())));
    (a, b)
}

fn addr() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345)
}

fn wire_type(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

/// The AmneziaWG send path: obfuscate `packet` and return the
/// datagram carrying the message itself.
///
/// Prefixes come from a deterministic RNG: with trailers on, a
/// handshake whose prefix happens to decode as H4 would be taken for
/// transport, and a test must not depend on that 1-in-4000 draw.
fn seal(cfg: &Arc<AmneziaConfig>, window: usize, packet: impl Into<WgKind>) -> Packet {
    let mut out = seal_all(cfg, window, packet);
    out.pop().expect("message datagram")
}

/// Every datagram `seal` emits for `packet` (I-packets, junk, message).
fn seal_all(cfg: &Arc<AmneziaConfig>, window: usize, packet: impl Into<WgKind>) -> Vec<Packet> {
    thread_local!(static SEED: std::cell::Cell<u8> = const { std::cell::Cell::new(0) });
    let seed = SEED.with(|s| {
        s.set(s.get().wrapping_add(1));
        s.get()
    });
    let mut out = Vec::new();
    Obfuscator::new(cfg.clone())
        .seal_with(packet.into(), window, &mut out, &mut DetRng::new(seed), 0)
        .expect("fits in a datagram");
    out
}

/// The AmneziaWG receive path: classify and open, verify the MACs
/// over the raw bytes (H included), then hand the plain message to
/// `to`.
fn deliver(cfg: &Arc<AmneziaConfig>, to: &mut Tunn, datagram: Packet) -> TunnResult {
    // Resolve ambiguous trailered datagrams as the device does
    // (rulings R14/R15): `to`'s sessions and MAC1 key are the oracle.
    let (packet, kind) = Deobfuscator::new(cfg.clone())
        .open_with(
            datagram,
            |idx| {
                to.sessions
                    .iter()
                    .flatten()
                    .any(|s| s.receiving_index.value() == idx)
            },
            |_, msg| to.rate_limiter.mac1_matches(msg),
        )
        .expect("datagram classifies");
    match to
        .rate_limiter
        .verify_classified(addr(), packet, kind, cfg.disable_cookies)
    {
        Ok(packet) => to.handle_incoming_packet(packet),
        Err(result) => result,
    }
}

#[test]
fn awg_handshake_completes_with_h_ranges() {
    let cfg = awg_cfg(23, 87);
    let (mut a, mut b) = awg_tuns(&cfg);

    let init = create_handshake_init(&mut a);
    let datagram = seal(&cfg, 500, init);
    let result = deliver(&cfg, &mut b, datagram);
    let TunnResult::WriteToNetwork(WgKind::HandshakeResp(resp)) = result else {
        panic!("expected a handshake response, got {result:?}");
    };

    let h2 = cfg.headers.response;
    let h = wire_type(resp.as_bytes());
    assert!(
        (h2.start..=h2.end).contains(&h),
        "response type {h} outside H2"
    );

    let datagram = seal(&cfg, 500, resp);
    let result = deliver(&cfg, &mut a, datagram);
    let TunnResult::WriteToNetwork(WgKind::Data(keepalive)) = result else {
        panic!("expected a keepalive after the handshake, got {result:?}");
    };
    parse_keepalive(&mut b, keepalive);
    assert_packet_roundtrip(&mut a, &mut b);
    assert_packet_roundtrip(&mut b, &mut a);
}

#[test]
fn init_type_field_in_h1_range() {
    let cfg = awg_cfg(23, 87);
    let (mut a, _b) = awg_tuns(&cfg);
    let h1 = cfg.headers.init;

    let types: Vec<u32> = (0..64)
        .map(|_| {
            let init = a
                .format_handshake_initiation(true)
                .expect("expected handshake init");
            wire_type(init.as_bytes())
        })
        .collect();
    for h in &types {
        assert!((h1.start..=h1.end).contains(h), "init type {h} outside H1");
    }
    assert!(
        types.iter().any(|h| *h != types[0]),
        "H1 is drawn per handshake"
    );
}

/// Full AWG 3.1 framing (header protection, trailers, S4 on the
/// keepalive) through real tunnels, each side sizing trailers
/// against its own UDP window.
#[test]
fn awg3_handshake_and_data_through_seal() {
    let mut c = (*awg_cfg(23, 87)).clone();
    c.header_protection_key = Some([0x42; 32]);
    c.random_trailers = true;
    c.junk = crate::amnezia::Junk {
        count: 2,
        min: 30,
        max: 60,
    };
    let cfg = Arc::new(c);
    let (mut a, mut b) = awg_tuns(&cfg);

    let init = create_handshake_init(&mut a);
    let window = *a.amnezia_udp_window_mut().expect("amnezia on");
    assert_eq!(window, 500);
    let mut out = seal_all(&cfg, window, init);
    assert_eq!(out.len(), 3, "junk, junk, init");
    let datagram = out.pop().unwrap();
    assert!(datagram.len() >= 23 + WgHandshakeInit::LEN);
    for junk in out {
        assert!(Deobfuscator::new(cfg.clone()).open(junk).is_none());
    }
    let result = deliver(&cfg, &mut b, datagram);
    let TunnResult::WriteToNetwork(resp) = result else {
        panic!("expected a handshake response, got {result:?}");
    };

    let window = *b.amnezia_udp_window_mut().unwrap();
    let datagram = seal(&cfg, window, resp);
    let result = deliver(&cfg, &mut a, datagram);
    let TunnResult::WriteToNetwork(keepalive) = result else {
        panic!("expected a keepalive after the handshake, got {result:?}");
    };
    let window = *a.amnezia_udp_window_mut().unwrap();
    let datagram = seal(&cfg, window, keepalive);
    assert!(
        (19 + WgData::OVERHEAD..window).contains(&datagram.len()),
        "S4-prefixed keepalive, trailer-padded within the window: {}",
        datagram.len()
    );
    let result = deliver(&cfg, &mut b, datagram);
    assert!(matches!(result, TunnResult::WriteToTunnel(p) if p.is_empty()));

    let sent = create_ipv4_udp_packet();
    let data = a
        .handle_outgoing_packet(sent.clone().into_bytes(), None)
        .expect("session should encrypt the packet");
    let window = *a.amnezia_udp_window_mut().unwrap();
    let datagram = seal(&cfg, window, data);
    let TunnResult::WriteToTunnel(received) = deliver(&cfg, &mut b, datagram) else {
        panic!("session should decrypt the packet");
    };
    let (ip, pad) = received.as_bytes().split_at(sent.as_bytes().len());
    assert_eq!(sent.as_bytes(), ip);
    assert!(pad.iter().all(|b| *b == 0), "trailer-sized content padding");
}

fn padded_cfg(content: Option<(u32, u32)>, trailers: bool) -> Arc<AmneziaConfig> {
    let mut c = (*awg_cfg(23, 87)).clone();
    c.content_padding = content.map(|(lo, hi)| crate::amnezia::U32Range { lo, hi });
    c.random_trailers = trailers;
    Arc::new(c)
}

/// Complete a handshake from `a` to `b` through the AWG framing.
fn awg_connect(cfg: &Arc<AmneziaConfig>, a: &mut Tunn, b: &mut Tunn) {
    let init = create_handshake_init(a);
    let result = deliver(cfg, b, seal(cfg, 500, init));
    let TunnResult::WriteToNetwork(resp) = result else {
        panic!("expected a handshake response, got {result:?}");
    };
    let result = deliver(cfg, a, seal(cfg, 500, resp));
    let TunnResult::WriteToNetwork(keepalive) = result else {
        panic!("expected a keepalive after the handshake, got {result:?}");
    };
    let result = deliver(cfg, b, seal(cfg, 500, keepalive));
    assert!(matches!(result, TunnResult::WriteToTunnel(p) if p.is_empty()));
}

/// Sending widens the window by the pre-padding datagram size
/// (`S4 + 32 + plaintext`), with or without any padding mode.
#[test]
fn window_widens_unconditionally() {
    for cfg in [padded_cfg(None, false), padded_cfg(Some((1, 64)), true)] {
        let (mut a, mut b) = awg_tuns(&cfg);
        awg_connect(&cfg, &mut a, &mut b);

        let mut big = create_ipv4_udp_packet().into_bytes();
        big.buf_mut().resize(1_200, 0);
        let mut mtu = MtuWatcher::new(1_420);
        a.handle_outgoing_packet(big, Some(&mut mtu))
            .expect("session encrypts");
        let window = *a.amnezia_udp_window_mut().unwrap();
        assert_eq!(window, 19 + WgData::OVERHEAD + 1_200);

        a.handle_outgoing_packet(create_ipv4_udp_packet().into_bytes(), None)
            .expect("session encrypts");
        assert_eq!(*a.amnezia_udp_window_mut().unwrap(), window);

        a.reset_amnezia_udp_window();
        assert_eq!(*a.amnezia_udp_window_mut().unwrap(), 500);
    }
}

/// A content-padded keepalive decrypts to zeros; the receiver takes
/// the zero first byte for a keepalive, not data. The sender, for its
/// part, decides by the empty payload before padding.
#[test]
fn padded_keepalive_detected_by_zero_byte() {
    let cfg = padded_cfg(Some((40, 40)), false);
    let (mut a, mut b) = awg_tuns(&cfg);
    awg_connect(&cfg, &mut a, &mut b);

    const SENTINEL: Duration = Duration::from_secs(1234);
    a.timers[TimerName::TimeLastDataPacketSent] = SENTINEL;
    let keepalive = a
        .handle_outgoing_packet(Packet::from_bytes(BytesMut::new()), None)
        .expect("session encrypts");
    let WgKind::Data(keepalive) = keepalive else {
        panic!("expected a data packet, got {keepalive:?}");
    };
    assert_eq!(keepalive.as_bytes().len(), WgData::OVERHEAD + 40, "padded");
    assert_eq!(a.timers[TimerName::TimeLastDataPacketSent], SENTINEL);

    b.timers[TimerName::TimeLastDataPacketReceived] = SENTINEL;
    let result = deliver(&cfg, &mut b, seal(&cfg, 500, keepalive));
    assert!(
        matches!(&result, TunnResult::WriteToTunnel(p) if p.is_empty()),
        "padded keepalive reaches the device as a keepalive, got {result:?}"
    );
    assert_eq!(b.timers[TimerName::TimeLastDataPacketReceived], SENTINEL);

    // Data still counts as data, padded or not.
    let sent = create_ipv4_udp_packet();
    let data = a
        .handle_outgoing_packet(sent.clone().into_bytes(), None)
        .expect("session encrypts");
    let TunnResult::WriteToTunnel(received) = deliver(&cfg, &mut b, seal(&cfg, 500, data)) else {
        panic!("session should decrypt the packet");
    };
    assert_eq!(
        &received.as_bytes()[..sent.as_bytes().len()],
        sent.as_bytes()
    );
    assert_ne!(b.timers[TimerName::TimeLastDataPacketReceived], SENTINEL);
}

/// With content padding or trailers on, the pad replaces WireGuard's
/// 16-byte alignment instead of adding to it (amneziawg-go
/// `send.go:609-616`).
#[test]
fn awg_padding_replaces_x16() {
    let cfg = padded_cfg(Some((5, 5)), false);
    let (mut a, mut b) = awg_tuns(&cfg);
    awg_connect(&cfg, &mut a, &mut b);
    let mut sent = create_ipv4_udp_packet().into_bytes();
    let len = sent.len() + 3;
    sent.buf_mut().resize(len, 0);
    assert!(!len.is_multiple_of(16) && !(len + 5).is_multiple_of(16));
    let mut mtu = MtuWatcher::new(1_420);
    let Some(WgKind::Data(data)) = a.handle_outgoing_packet(sent, Some(&mut mtu)) else {
        panic!("session encrypts");
    };
    assert_eq!(data.as_bytes().len(), WgData::OVERHEAD + len + 5);
}

/// Negative control: a plain WireGuard receiver must not take an
/// AmneziaWG initiation for a WireGuard one.
#[test]
fn plain_tunn_rejects_awg_init() {
    let plain = Arc::new(AmneziaConfig::default());
    for cfg in [awg_cfg(0, 0), awg_cfg(23, 87)] {
        let (mut a, _b) = create_two_tuns();
        a.set_amnezia(Some(AmneziaTunnState::new(cfg.clone())));

        for _ in 0..16 {
            let init = a
                .format_handshake_initiation(true)
                .expect("expected handshake init");
            let datagram = seal(&cfg, 500, init);

            // The type field holds H1 rather than 1, and S1 shifts
            // the message; the plain classifier recognises neither.
            assert!(
                Deobfuscator::new(plain.clone())
                    .open(datagram.clone())
                    .is_none(),
                "plain classifier accepted an AWG init (S1 = {})",
                cfg.padding.s1
            );
            if cfg.padding.s1 > 0 {
                assert!(datagram.try_into_wg().is_err());
            }
        }
    }
}
