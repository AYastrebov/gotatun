//! Device-level AmneziaWG tests: two in-memory devices and an eavesdropper
//! that sees the raw datagrams.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use either::for_both;
use futures::{Stream, StreamExt};
use tokio::time::timeout;
use tracing::{Event, Level, Metadata, Subscriber, field, span};
use zerocopy::IntoBytes;

use super::mock::{self, MockDevice};
use crate::amnezia::classify::Deobfuscator;
use crate::amnezia::timers::timer_params_from;
use crate::amnezia::{
    AmneziaConfig, CpsChain, HeaderRange, HeaderRanges, InitPackets, Junk, Padding, TimingRanges,
    U32Range,
};
use crate::device::{Connection, Error};
use crate::noise::TimerParams;
use crate::noise::rate_limiter::RateLimiter;
use crate::packet::{Ip, Packet, WgCookieReply, WgHandshakeInit, WgPacketType};

const ALICE_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const BOB_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

fn secs(lo: u64, hi: u64) -> Option<std::ops::RangeInclusive<Duration>> {
    Some(Duration::from_secs(lo)..=Duration::from_secs(hi))
}

fn range(start: u32, end: u32) -> HeaderRange {
    HeaderRange { start, end }
}

/// I1..I5 rendered sizes: `<b>` bytes plus the fixed-size tags.
const I_PACKET_LENS: [usize; 5] = [4 + 24, 4 + 4, 4 + 10, 4 + 6, 4];

/// Synthetic AWG 2.0 config with every 2.0 key set.
fn awg20() -> AmneziaConfig {
    let chain = |s: &str| Some(CpsChain::parse(s).expect("valid chain"));
    AmneziaConfig {
        headers: HeaderRanges {
            init: range(1_210_000_000, 1_260_000_000),
            response: range(1_370_000_000, 1_420_000_000),
            cookie: range(1_530_000_000, 1_580_000_000),
            transport: range(1_690_000_000, 1_740_000_000),
        },
        padding: Padding {
            s1: 27,
            s2: 87,
            s3: 33,
            s4: 21,
        },
        junk: Junk {
            count: 4,
            min: 40,
            max: 90,
        },
        init_packets: InitPackets([
            chain("<b 0xc0ffee01><r 24>"),
            chain("<b 0xc0ffee02><t>"),
            chain("<b 0xc0ffee03><rc 10>"),
            chain("<b 0xc0ffee04><rd 6>"),
            chain("<b 0xc0ffee05>"),
        ]),
        ..AmneziaConfig::default()
    }
}

/// AWG 3.0: 2.0 plus header protection, content padding and timing ranges.
fn awg30() -> AmneziaConfig {
    AmneziaConfig {
        header_protection_key: Some(*b"synthetic-test-key-not-real-0001"),
        content_padding: Some(U32Range { lo: 8, hi: 64 }),
        timings: TimingRanges {
            rekey_after_time: secs(100, 140),
            rekey_timeout: secs(2, 3),
            reject_after_time: secs(170, 200),
            keepalive_timeout: secs(9, 12),
            max_handshake_attempts: Some(10..=20),
        },
        ..awg20()
    }
}

/// AWG 3.1: 3.0 plus random trailers and `disable_cookies`.
fn awg31() -> AmneziaConfig {
    AmneziaConfig {
        random_trailers: true,
        disable_cookies: true,
        ..awg30()
    }
}

async fn awg_pair(cfg: AmneziaConfig) -> (MockDevice, MockDevice, mock::MockEavesdropper) {
    mock::device_pair_with(|b| b.with_amnezia(cfg.clone())).await
}

/// The UDP payload of a sniffed IP packet.
fn udp_payload(ip: Packet<Ip>) -> Packet {
    let ipvx = ip.try_into_ipvx().unwrap();
    for_both!(ipvx, ipvx => ipvx.try_into_udp().unwrap().into_payload().into_payload())
}

/// Datagrams sent to `dst`, in the order the eavesdropper saw them.
fn sent_to(eve: &mock::MockEavesdropper, dst: IpAddr) -> impl Stream<Item = Packet> + use<> {
    eve.ip()
        .filter(move |ip| std::future::ready(ip.destination() == Some(dst)))
        .map(udp_payload)
}

/// Collect a stream for `period`.
async fn collect_for<S: Stream<Item = Packet>>(stream: S, period: Duration) -> Vec<Packet> {
    let mut stream = std::pin::pin!(stream);
    let mut out = vec![];
    let deadline = tokio::time::Instant::now() + period;
    while let Ok(Some(p)) = tokio::time::timeout_at(deadline, stream.next()).await {
        out.push(p);
    }
    out
}

/// Collect a stream until it stays quiet for `idle`.
async fn drain<S: Stream<Item = Packet>>(stream: S, idle: Duration) -> Vec<Packet> {
    let mut stream = std::pin::pin!(stream);
    let mut out = vec![];
    while let Ok(Some(p)) = timeout(idle, stream.next()).await {
        out.push(p);
    }
    out
}

async fn ping(from: &MockDevice, to: &mut MockDevice, payload: &[u8]) {
    let packet = mock::packet(payload);
    from.app_tx.send(packet.clone()).await;
    // With AWG 3.1 trailers a handshake is misread as transport about 1% of
    // the time (|H4| / 2^32) and only a retry recovers, so the clock must run.
    let got = with_running_clock(timeout(Duration::from_secs(10), to.app_rx.recv()))
        .await
        .expect("packet should be delivered");
    assert_eq!(got.as_bytes(), packet.as_bytes());
}

async fn assert_blocked(from: &MockDevice, to: &mut MockDevice, wait: Duration) {
    from.app_tx.send(mock::packet(b"must not arrive")).await;
    assert!(
        timeout(wait, to.app_rx.recv()).await.is_err(),
        "mismatched peers must never complete a handshake"
    );
}

async fn ping_both_directions(cfg: AmneziaConfig) {
    let (mut alice, mut bob, _eve) = awg_pair(cfg).await;
    ping(&alice, &mut bob, b"alice to bob").await;
    ping(&bob, &mut alice, b"bob to alice").await;
    // Larger payloads exercise content padding against the UDP window.
    ping(&alice, &mut bob, &[0x45; 1200]).await;
    ping(&bob, &mut alice, &[0x45; 1200]).await;
}

#[tokio::test]
#[test_log::test]
async fn awg20_ping_both_directions() {
    ping_both_directions(awg20()).await;
}

#[tokio::test]
#[test_log::test]
async fn awg30_ping_both_directions() {
    ping_both_directions(awg30()).await;
}

#[tokio::test]
#[test_log::test]
async fn awg31_ping_both_directions() {
    ping_both_directions(awg31()).await;
}

#[tokio::test]
#[test_log::test]
async fn eavesdropper_sees_no_standard_types() {
    for cfg in [awg20(), awg30(), awg31()] {
        let (mut alice, mut bob, eve) = awg_pair(cfg).await;
        let seen = eve.udp().map(|udp| udp.into_payload());
        let traffic = async {
            for i in 0..5u8 {
                ping(&alice, &mut bob, &[i; 100]).await;
                ping(&bob, &mut alice, &[i; 600]).await;
            }
        };
        let (datagrams, ()) = tokio::join!(drain(seen, Duration::from_millis(500)), traffic);
        // 1 init + 1 response + 10 data, plus I-packets, junk and keepalives.
        assert!(datagrams.len() >= 12 + 5 + 4, "saw {}", datagrams.len());
        for d in &datagrams {
            for t in 1u8..=4 {
                assert!(
                    !d.starts_with(&[t, 0, 0, 0]),
                    "datagram starts with the standard type {t}: {:02x?}",
                    &d[..d.len().min(8)]
                );
            }
        }
    }
}

/// Records events above TRACE, to show mismatched peers fail silently.
#[derive(Clone, Default)]
struct LoudEvents(Arc<Mutex<Vec<String>>>);

struct MessageVisitor<'a>(&'a mut String);

impl field::Visit for MessageVisitor<'_> {
    fn record_debug(&mut self, field: &field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            *self.0 = format!("{value:?}");
        }
    }
}

impl Subscriber for LoudEvents {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, event: &Event<'_>) {
        if *event.metadata().level() != Level::TRACE {
            let mut message = String::new();
            event.record(&mut MessageVisitor(&mut message));
            self.0.lock().unwrap().push(message);
        }
    }
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

/// Initiator-side messages logged once per handshake attempt (also in plain
/// WireGuard), and configuration events. Anything else above TRACE would be
/// logged per received datagram.
const PER_ATTEMPT_MESSAGES: &[&str] = &[
    "Sending handshake_initiation",
    "HANDSHAKE(REKEY_TIMEOUT)",
    "CONNECTION_EXPIRED(REKEY_ATTEMPT_TIME)",
    "Peer added",
    "AmneziaWG configuration updated, peers rebuilt",
    "Stopping device",
];

/// `bob` gets `bob_cfg`; neither direction must ever handshake, and nothing
/// is logged above TRACE per received datagram.
async fn assert_never_handshakes(bob_cfg: Option<AmneziaConfig>) {
    let events = LoudEvents::default();
    let _guard = tracing::subscriber::set_default(events.clone());

    let (mut alice, mut bob, eve) = awg_pair(awg30()).await;
    bob.device
        .write(async |d| d.set_amnezia(bob_cfg).await)
        .await
        .unwrap()
        .expect("valid config");

    let to_bob = sent_to(&eve, BOB_V4.into());
    let to_alice = sent_to(&eve, ALICE_V4.into());
    let (to_bob, to_alice, ()) = tokio::join!(
        collect_for(to_bob, Duration::from_secs(8)),
        collect_for(to_alice, Duration::from_secs(8)),
        async {
            assert_blocked(&alice, &mut bob, Duration::from_secs(4)).await;
            assert_blocked(&bob, &mut alice, Duration::from_secs(4)).await;
        },
    );
    assert!(to_bob.len() > 5, "alice kept trying: {}", to_bob.len());
    assert!(!to_alice.is_empty(), "bob kept trying");

    drop((alice, bob));
    let loud: Vec<String> = events
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|m| !PER_ATTEMPT_MESSAGES.contains(&m.as_str()))
        .cloned()
        .collect();
    assert!(loud.is_empty(), "logged above TRACE: {loud:?}");
}

#[tokio::test]
async fn awg_vs_plain_never_handshakes() {
    assert_never_handshakes(None).await;
}

#[tokio::test]
async fn awg_mismatched_h_never_handshakes() {
    let mut cfg = awg30();
    cfg.headers.init = range(1_100_000_000, 1_150_000_000);
    assert_never_handshakes(Some(cfg)).await;
}

/// On a forced handshake the wire carries I1..I5, then Jc junk, then the
/// initiation, in that order, over IPv4 and over IPv6.
#[tokio::test]
#[test_log::test]
async fn pre_handshake_order_on_force_handshake() {
    let bob_v6: IpAddr = "fd00::2".parse().unwrap();
    for bob_ip in [IpAddr::V4(BOB_V4), bob_v6] {
        let cfg = awg30();
        let (mut alice, _bob, eve) = awg_pair(cfg.clone()).await;
        let bob_key = alice.device.peers().await[0].peer.public_key;
        if bob_ip.is_ipv6() {
            alice
                .device
                .modify_peer(&bob_key, |p| {
                    p.set_endpoint(Some(SocketAddr::new(bob_ip, 51820)))
                })
                .await
                .unwrap();
        }

        let to_bob = sent_to(&eve, bob_ip);
        let (datagrams, done) = tokio::join!(
            drain(to_bob, Duration::from_millis(500)),
            timeout(
                Duration::from_secs(5),
                alice.device.force_handshake(&bob_key)
            ),
        );
        done.expect("handshake completes").expect("peer exists");

        let n_i = I_PACKET_LENS.len();
        let jc = usize::from(cfg.junk.count);
        assert!(datagrams.len() > n_i + jc, "{bob_ip}: {}", datagrams.len());
        for (i, (d, len)) in datagrams.iter().zip(I_PACKET_LENS).enumerate() {
            assert_eq!(d.len(), len, "{bob_ip}: I{} size", i + 1);
            assert_eq!(
                &d[..4],
                &[0xc0, 0xff, 0xee, i as u8 + 1],
                "{bob_ip}: I{}",
                i + 1
            );
        }
        for d in &datagrams[n_i..n_i + jc] {
            let junk = usize::from(cfg.junk.min)..usize::from(cfg.junk.max);
            assert!(junk.contains(&d.len()), "{bob_ip}: junk size {}", d.len());
        }
        let init = &datagrams[n_i + jc];
        assert_eq!(
            init.len(),
            usize::from(cfg.padding.s1) + WgHandshakeInit::LEN
        );
        let deobfs = Deobfuscator::new(Arc::new(cfg));
        assert_eq!(
            deobfs.classify(init).map(|c| c.kind),
            Some(WgPacketType::HandshakeInit),
            "{bob_ip}: the initiation follows the junk"
        );
    }
}

/// Await `fut`, which waits on a handshake retry. Under `mock_instant` the
/// timers only see time the test advances, so advance it meanwhile.
async fn with_running_clock<F: std::future::Future>(fut: F) -> F::Output {
    #[cfg(feature = "mock_instant")]
    {
        let tick = async {
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                mock_instant::thread_local::MockClock::advance(Duration::from_millis(250));
            }
        };
        tokio::select! {
            out = fut => out,
            () = tick => unreachable!(),
        }
    }
    #[cfg(not(feature = "mock_instant"))]
    fut.await
}

/// Put `device` under load for every handshake source: a fresh rate limiter
/// with limit 0, installed where the device and its tunnels look for it.
async fn force_under_load(device: &MockDevice) {
    {
        let mut state = device.device.inner.write().await;
        let (private_key, public_key) = state.key_pair.clone().unwrap();
        let rate_limiter = Arc::new(RateLimiter::new(&public_key, 0));
        for peer in state.peers.values() {
            peer.lock().await.tunnel.set_static_private(
                private_key.clone(),
                public_key,
                Arc::clone(&rate_limiter),
            );
        }
        state.rate_limiter = Some(rate_limiter);
    }
    Connection::set_up(device.device.inner.clone())
        .await
        .unwrap();
}

/// An under-load responder answers with a cookie reply framed like any other
/// AWG 3.1 cookie reply (S3 prefix, H3, header protection, a trailer); the
/// initiator retries with MAC2 and the handshake completes.
#[tokio::test]
#[test_log::test]
async fn cookie_under_load_has_trailer_and_handshake_completes() {
    let cfg = AmneziaConfig {
        disable_cookies: false,
        ..awg31()
    };
    let deobfs = Deobfuscator::new(Arc::new(cfg.clone()));
    let cookie_len = usize::from(cfg.padding.s3) + WgCookieReply::LEN;

    // The trailer is uniform in [0, 500 - cookie_len), so it is empty about
    // once in 400 runs; retry so the assertion is about framing, not luck.
    let mut longest = 0;
    for _ in 0..3 {
        let (alice, mut bob, eve) = awg_pair(cfg.clone()).await;
        force_under_load(&bob).await;

        let to_alice = sent_to(&eve, ALICE_V4.into());
        let (datagrams, ()) = tokio::join!(
            drain(to_alice, Duration::from_millis(1500)),
            ping(&alice, &mut bob, b"after the cookie"),
        );
        let cookies: Vec<_> = datagrams
            .iter()
            .filter(|d| deobfs.classify(d).map(|c| c.kind) == Some(WgPacketType::CookieReply))
            .collect();
        assert!(!cookies.is_empty(), "bob must answer with a cookie reply");
        for c in &cookies {
            assert!(c.len() >= cookie_len);
            assert!(c.len() < 500, "trailer sized against the default window");
            longest = longest.max(c.len());
        }
        if longest > cookie_len {
            return;
        }
    }
    panic!("cookie replies never carried a trailer");
}

/// Swapping the config on both devices mid-traffic rebuilds the tunnels: the
/// next packet re-handshakes under the new config.
#[tokio::test]
#[test_log::test]
async fn uapi_set_amnezia_mid_traffic_rehandshakes() {
    let (mut alice, mut bob, eve) = mock::device_pair().await;
    ping(&alice, &mut bob, b"plain").await;
    ping(&bob, &mut alice, b"plain").await;

    for cfg in [awg30(), awg31(), awg20()] {
        let to_bob = sent_to(&eve, BOB_V4.into());
        for device in [&alice, &bob] {
            let new_cfg = cfg.clone();
            device
                .device
                .write(async |d| d.set_amnezia(Some(new_cfg)).await)
                .await
                .unwrap()
                .expect("valid config");
            assert_eq!(
                device.device.read(async |d| d.amnezia()).await,
                Some(cfg.clone())
            );
        }
        let (datagrams, ()) = tokio::join!(drain(to_bob, Duration::from_millis(500)), async {
            ping(&alice, &mut bob, b"after swap").await;
            ping(&bob, &mut alice, b"after swap").await;
        });

        let deobfs = Deobfuscator::new(Arc::new(cfg));
        assert!(
            datagrams
                .iter()
                .any(|d| deobfs.classify(d).map(|c| c.kind) == Some(WgPacketType::HandshakeInit)),
            "a new initiation under the new config"
        );
    }

    // And back to plain WireGuard.
    for device in [&alice, &bob] {
        device
            .device
            .write(async |d| d.set_amnezia(None).await)
            .await
            .unwrap()
            .expect("plain");
        assert_eq!(device.device.read(async |d| d.amnezia()).await, None);
    }
    ping(&alice, &mut bob, b"plain again").await;
    ping(&bob, &mut alice, b"plain again").await;
}

/// Explicit per-peer timer params win over the Amnezia timing ranges and
/// survive config swaps; peers without them follow the device config.
#[tokio::test]
#[test_log::test]
async fn danger_timer_params_survive_set_amnezia() {
    let (mut alice, mut bob, _eve) = mock::device_pair().await;
    let explicit = TimerParams {
        keepalive_timeout: Duration::from_secs(7)..=Duration::from_secs(8),
        ..TimerParams::default()
    };
    let alice_key = bob.device.peers().await[0].peer.public_key;
    bob.device
        .modify_peer(&alice_key, |p| {
            p.dangerously_set_timer_params(Some(explicit.clone()))
        })
        .await
        .unwrap();

    let timer_params =
        async |d: &MockDevice| d.device.peers().await[0].peer.danger_timer_params.clone();

    let cfg = awg30();
    let from_cfg = timer_params_from(&cfg.timings);
    assert_ne!(from_cfg, TimerParams::default());
    for device in [&alice, &bob] {
        let cfg = cfg.clone();
        device
            .device
            .write(async |d| d.set_amnezia(Some(cfg)).await)
            .await
            .unwrap()
            .unwrap();
    }
    assert_eq!(timer_params(&bob).await, Some(explicit.clone()));
    assert_eq!(timer_params(&alice).await, Some(from_cfg.clone()));
    ping(&alice, &mut bob, b"with timing ranges").await;

    // Clearing the explicit params falls back to the device's timing ranges.
    bob.device
        .modify_peer(&alice_key, |p| p.dangerously_set_timer_params(None))
        .await
        .unwrap();
    assert_eq!(timer_params(&bob).await, Some(from_cfg));
    bob.device
        .modify_peer(&alice_key, |p| {
            p.dangerously_set_timer_params(Some(explicit.clone()))
        })
        .await
        .unwrap();

    for device in [&alice, &bob] {
        device
            .device
            .write(async |d| d.set_amnezia(None).await)
            .await
            .unwrap()
            .unwrap();
    }
    assert_eq!(timer_params(&bob).await, Some(explicit));
    assert_eq!(timer_params(&alice).await, Some(TimerParams::default()));
    ping(&bob, &mut alice, b"plain").await;
}

/// Invalid configs are rejected by the builder and by `set_amnezia`, which
/// then leaves the device as it was.
#[tokio::test]
#[test_log::test]
async fn invalid_amnezia_config_is_rejected() {
    let mut bad = awg30();
    bad.padding.s4 = 4; // header protection needs S1..S4 >= 12

    let (tun, _tx, _rx) = mock::mock_tun();
    let built = crate::device::DeviceBuilder::new()
        .with_ip(tun)
        .with_udp(crate::udp::channel::UdpChannelFactory::new(
            ALICE_V4,
            crate::udp::channel::UdpChannelV4::new_pair(1).0,
            std::net::Ipv6Addr::UNSPECIFIED,
            crate::udp::channel::UdpChannelV6::new_pair(1).0,
        ))
        .with_amnezia(bad.clone())
        .build()
        .await;
    assert!(matches!(built, Err(Error::Amnezia(_))));

    let (alice, _bob, _eve) = awg_pair(awg20()).await;
    let result = alice
        .device
        .write(async |d| d.set_amnezia(Some(bad)).await)
        .await
        .unwrap();
    assert!(result.is_err());
    assert_eq!(
        alice.device.read(async |d| d.amnezia()).await,
        Some(awg20())
    );
}

/// The peer's UDP window as the device holds it.
async fn peer_window(device: &MockDevice) -> usize {
    let state = device.device.inner.read().await;
    let peer = state.peers.values().next().expect("one peer");
    let mut peer = peer.lock().await;
    *peer.tunnel.amnezia_udp_window_mut().expect("amnezia on")
}

/// A received transport datagram widens the receiver's window to the
/// datagram minus its AEAD tag (amneziawg-go `receive.go`: S4 + 16 +
/// plaintext); a new endpoint resets it to 500 before that packet counts.
#[tokio::test]
#[test_log::test]
async fn udp_window_widens_on_receive_and_resets_on_roaming() {
    let cfg = awg30();
    let (alice, mut bob, eve) = awg_pair(cfg).await;

    let to_bob = sent_to(&eve, BOB_V4.into());
    let (datagrams, ()) = tokio::join!(
        drain(to_bob, Duration::from_millis(500)),
        ping(&alice, &mut bob, &[0x45; 1200]),
    );
    let largest = datagrams.iter().map(|d| d.len()).max().unwrap();
    assert!(largest > 1200);
    // Bob only sent a response and a keepalive, so the window comes from
    // what he received.
    assert_eq!(peer_window(&bob).await, largest - 16);

    // Alice roams: Bob's window starts over from that packet.
    *alice.source_ipv4_override.lock().await = Some(Ipv4Addr::new(1, 2, 3, 4));
    let to_bob = sent_to(&eve, BOB_V4.into());
    let (datagrams, ()) = tokio::join!(
        drain(to_bob, Duration::from_millis(500)),
        ping(&alice, &mut bob, b"small"),
    );
    let small = datagrams.iter().map(|d| d.len()).max().unwrap();
    assert!(small < 500);
    assert_eq!(peer_window(&bob).await, 500);
}

/// IPv6 flow labels of sniffed datagrams. The mock channel writes its
/// per-bind connection id there, so a rebind changes it.
fn flow_labels(datagrams: &[Packet<crate::packet::Ipv6<crate::packet::Udp>>]) -> Vec<u32> {
    datagrams
        .iter()
        .map(|p| {
            let field = p.header.version_traffic_flow;
            field.flow_label()
        })
        .collect()
}

/// R13: a mid-traffic swap keeps the connection and its sockets (an embedder
/// may hand over a socket pair it cannot bind again), and traffic resumes
/// under the new config.
#[tokio::test]
#[test_log::test]
async fn set_amnezia_mid_traffic_keeps_sockets() {
    let bob_v6: IpAddr = "fd00::2".parse().unwrap();
    let (mut alice, mut bob, eve) = awg_pair(awg30()).await;
    let bob_key = alice.device.peers().await[0].peer.public_key;
    alice
        .device
        .modify_peer(&bob_key, |p| {
            p.set_endpoint(Some(SocketAddr::new(bob_v6, 51820)))
        })
        .await
        .unwrap();

    let collect_v6 = |eve: &mock::MockEavesdropper| {
        let stream = eve.ipv6();
        async move {
            let mut stream = std::pin::pin!(stream);
            let mut out = vec![];
            while let Ok(Some(p)) = timeout(Duration::from_millis(500), stream.next()).await {
                out.push(p);
            }
            out
        }
    };

    let (before, ()) = tokio::join!(collect_v6(&eve), async {
        ping(&alice, &mut bob, b"before").await;
        ping(&bob, &mut alice, b"before").await;
    });
    // Alice to fd00::2, and Bob's replies (to Alice's `::` source, where
    // Alice then roams to as well): both sockets' labels.
    let sockets = flow_labels(&before);
    assert!(sockets.len() >= 2);

    let cfg = awg31();
    for device in [&alice, &bob] {
        let cfg = cfg.clone();
        device
            .device
            .write(async |d| d.set_amnezia(Some(cfg)).await)
            .await
            .unwrap()
            .unwrap();
    }

    let (after, ()) = tokio::join!(collect_v6(&eve), async {
        ping(&alice, &mut bob, b"after").await;
        ping(&bob, &mut alice, b"after").await;
    });
    let labels = flow_labels(&after);
    assert!(!labels.is_empty());
    assert!(
        labels.iter().all(|l| sockets.contains(l)),
        "a socket was rebound: {sockets:?} -> {labels:?}"
    );
    let deobfs = Deobfuscator::new(Arc::new(cfg));
    assert!(
        after
            .into_iter()
            .map(|p| p.into_payload().into_payload())
            .any(|d| deobfs.classify(&d).map(|c| c.kind) == Some(WgPacketType::HandshakeInit)),
        "re-handshake under the new config"
    );
}

/// DAITA and Amnezia together: DAITA's decoys go out sealed, so the plain
/// receiver decrypts them (its UDP window grows to the decoy's size) and the
/// wire still shows no standard types.
#[cfg(feature = "daita")]
#[tokio::test]
#[test_log::test]
async fn daita_decoys_are_sealed() {
    use crate::device::Peer;
    use crate::device::daita::DaitaSettings;
    use ipnetwork::Ipv4Network;
    use std::str::FromStr;

    // On each normal packet, send one decoy 1 µs later (maybenot 2 machine:
    // state 0 -NormalSent-> 1 [SendPadding] -PaddingSent-> 0).
    const DECOY_MACHINE: &str =
        "02eNpVjLENACAMwxw4jNc4l5GdBVFAbb1UjeKsUTFm41PukQTd4/OSy0FKPNUMX9gGCQe9";

    let (alice, mut bob, eve) = awg_pair(awg30()).await;
    let bob_key = alice.device.peers().await[0].peer.public_key;
    let daita = DaitaSettings {
        maybenot_machines: vec![maybenot::Machine::from_str(DECOY_MACHINE).unwrap()],
        max_decoy_frac: 1.0,
        ..DaitaSettings::default()
    };
    alice.device.remove_peer(&bob_key).await.unwrap();
    alice
        .device
        .add_peer(
            Peer::new(bob_key)
                .with_endpoint((BOB_V4, 51820).into())
                .with_allowed_ip(Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).unwrap().into())
                .with_daita(daita),
        )
        .await
        .unwrap();
    // DAITA hooks start with the connection.
    Connection::set_up(alice.device.inner.clone())
        .await
        .unwrap();

    let seen = eve.udp().map(|udp| udp.into_payload());
    let (datagrams, ()) = tokio::join!(drain(seen, Duration::from_millis(500)), async {
        for _ in 0..3 {
            ping(&alice, &mut bob, b"hi").await;
        }
    });
    for d in &datagrams {
        for t in 1u8..=4 {
            assert!(
                !d.starts_with(&[t, 0, 0, 0]),
                "standard type {t} on the wire"
            );
        }
    }
    let decoy = usize::from(awg30().padding.s4) + 16 + usize::from(mock::TUN_MTU);
    assert!(
        peer_window(&bob).await >= decoy,
        "bob decrypted no decoy: window {}",
        peer_window(&bob).await
    );
}
