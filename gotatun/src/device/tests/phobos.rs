//! Device-level Phobos tests: a client device over [`PhobosUdpFactory`], and
//! a Phobos server, written here from the spec, in front of a plain gotatun
//! device. The server decodes with [`PhobosCodec`], which the reference's
//! golden vectors pin (`phobos::tests`), and drops everything but a handshake
//! initiation from an address that has not completed a handshake, as the
//! reference server does.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ipnetwork::Ipv4Network;
use tokio::select;
use tokio::time::timeout;
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::IntoBytes;

use super::mock::{self, MockAppRx, MockAppTx, MockTun};
use crate::device::{Device, DeviceBuilder, Peer};
use crate::phobos::testing::{Net, PipeFactory};
use crate::phobos::{Masking, PhobosCodec, PhobosConfig, PhobosUdpFactory, Unwrapped};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const UPSTREAM_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

fn front() -> SocketAddr {
    "10.0.0.9:443".parse().unwrap()
}

fn back() -> SocketAddr {
    "10.0.0.9:50000".parse().unwrap()
}

fn upstream() -> SocketAddr {
    SocketAddr::new(UPSTREAM_IP.into(), 51820)
}

fn config() -> PhobosConfig {
    let mut cfg = PhobosConfig::new(b"synthetic-preset-key".to_vec()).unwrap();
    cfg.masking = Masking::Stun;
    cfg
}

/// Whether a datagram starts with a plain WireGuard type field.
fn looks_plain(d: &[u8]) -> bool {
    d.len() >= 4 && (1..=4).contains(&d[0]) && d[1..4] == [0, 0, 0]
}

/// Run a Phobos server on `front`, forwarding to `upstream` from `back`.
/// Returns how many WireGuard messages it dropped for coming from an address
/// that had not completed a handshake.
fn spawn_server(net: &Net) -> Arc<AtomicUsize> {
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut front_ep = net.attach(front());
    let mut back_ep = net.attach(back());
    let counter = Arc::clone(&dropped);
    tokio::spawn(async move {
        let mut codec = PhobosCodec::new(config()).unwrap();
        let mut handshaked = HashSet::new();
        let mut client = None;
        loop {
            select! {
                (mut bytes, source) = front_ep.recv() => match codec.unwrap(&mut bytes, source) {
                    Unwrapped::WireGuard(message) => {
                        if message[..4] != [1, 0, 0, 0] && !handshaked.contains(&source) {
                            counter.fetch_add(1, Ordering::SeqCst);
                            continue;
                        }
                        client = Some(source);
                        back_ep.send(message, upstream());
                    }
                    Unwrapped::Reply(reply) => front_ep.send(&reply, source),
                    Unwrapped::Drop => {}
                },
                (bytes, _) = back_ep.recv() => {
                    let Some(client) = client else { continue };
                    if bytes[..4] == [2, 0, 0, 0] {
                        handshaked.insert(client);
                    }
                    let mut out = Vec::new();
                    if let Some(request) = codec.wrap(&bytes, &mut out).unwrap() {
                        front_ep.send(&request, client);
                    }
                    front_ep.send(&out, client);
                }
            }
        }
    });
    dropped
}

type ClientDevice = Device<(PhobosUdpFactory<PipeFactory>, MockTun, MockTun)>;
type UpstreamDevice = Device<(PipeFactory, MockTun, MockTun)>;

struct Setup {
    client: ClientDevice,
    client_tx: MockAppTx,
    client_rx: MockAppRx,
    _upstream: UpstreamDevice,
    upstream_tx: MockAppTx,
    upstream_rx: MockAppRx,
    dropped: Arc<AtomicUsize>,
}

async fn setup(net: &Net) -> Setup {
    let dropped = spawn_server(net);
    let (tun_c, client_tx, client_rx) = mock::mock_tun();
    let (tun_u, upstream_tx, upstream_rx) = mock::mock_tun();
    let key_c = StaticSecret::random();
    let key_u = StaticSecret::random();
    let all = Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).unwrap();

    let (udp, handle) = PhobosUdpFactory::new(
        PipeFactory::new(net.clone(), IpAddr::V4(CLIENT_IP), 40000),
        config(),
    )
    .unwrap();
    let client = DeviceBuilder::new()
        .with_private_key(key_c.clone())
        .with_ip(tun_c)
        .with_udp(udp)
        .with_phobos_handle(handle)
        .with_peer(
            Peer::new(PublicKey::from(&key_u))
                .with_endpoint(front())
                .with_allowed_ip(all.into()),
        )
        .build()
        .await
        .unwrap();

    let upstream = DeviceBuilder::new()
        .with_private_key(key_u)
        .with_ip(tun_u)
        .with_udp(PipeFactory::new(
            net.clone(),
            IpAddr::V4(UPSTREAM_IP),
            51820,
        ))
        .with_peer(Peer::new(PublicKey::from(&key_c)).with_allowed_ip(all.into()))
        .build()
        .await
        .unwrap();

    Setup {
        client,
        client_tx,
        client_rx,
        _upstream: upstream,
        upstream_tx,
        upstream_rx,
        dropped,
    }
}

async fn ping(tx: &MockAppTx, rx: &mut MockAppRx, payload: &[u8]) {
    let packet = mock::packet(payload);
    tx.send(packet.clone()).await;
    let got = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("ping did not arrive");
    assert_eq!(got.as_bytes(), packet.as_bytes());
}

/// A ping both ways through the Phobos server, with nothing plain from the
/// client on the wire.
#[tokio::test]
#[test_log::test]
async fn phobos_ping_through_reference_vectors_peer() {
    let net = Net::default();
    let mut tap = net.tap();
    let mut s = setup(&net).await;

    ping(&s.client_tx, &mut s.upstream_rx, b"ping").await;
    ping(&s.upstream_tx, &mut s.client_rx, b"pong").await;

    let mut from_client = 0;
    while let Ok((source, destination, bytes)) = tap.try_recv() {
        if source.ip() == IpAddr::V4(CLIENT_IP) {
            from_client += 1;
            assert_eq!(destination, front());
            assert!(!looks_plain(&bytes), "plain WireGuard on the wire");
        }
    }
    assert!(from_client >= 3, "initiation, data, keepalive or reply");
    let peers = s.client.peers().await;
    assert_eq!(
        peers[0].peer.endpoint,
        Some(front()),
        "the server stays the endpoint"
    );
    assert_eq!(s.dropped.load(Ordering::SeqCst), 0);
}

/// After the device rebinds its socket, it starts a handshake on its own,
/// and the server sees the initiation before anything else from the new
/// address.
///
/// Not under `mock_instant`: with the clock frozen, the second initiation's
/// timestamp is not newer than the first and the upstream drops it as a
/// replay.
#[cfg(not(feature = "mock_instant"))]
#[tokio::test]
#[test_log::test]
async fn phobos_rebind_sends_an_initiation_first() {
    let net = Net::default();
    let mut s = setup(&net).await;
    ping(&s.client_tx, &mut s.upstream_rx, b"before").await;

    let old_port = s.client.read(async |d| d.listen_port()).await;
    s.client
        .write(async |d| d.set_listen_port(1))
        .await
        .unwrap();
    let new_port = s.client.read(async |d| d.listen_port()).await;
    assert_ne!(old_port, new_port, "rebound");

    // The session is still up, so only the rebind gate's request makes the
    // device handshake before the next rekey. Data the gate held back before
    // the initiation went out is lost, as the server would have lost it.
    let packet = mock::packet(b"after");
    timeout(Duration::from_secs(5), async {
        loop {
            s.client_tx.send(packet.clone()).await;
            if let Ok(got) = timeout(Duration::from_millis(100), s.upstream_rx.recv()).await {
                assert_eq!(got.as_bytes(), packet.as_bytes());
                break;
            }
        }
    })
    .await
    .expect("no ping got through after the rebind");
    ping(&s.upstream_tx, &mut s.client_rx, b"back").await;
    assert_eq!(s.dropped.load(Ordering::SeqCst), 0);
}

/// AmneziaWG and Phobos cannot be configured together: at build, or later.
#[cfg(feature = "amnezia")]
#[tokio::test]
async fn amnezia_plus_phobos_build_errors() {
    use crate::amnezia::{AmneziaConfig, ConfigError, Junk};
    use crate::device::Error;

    let junk = AmneziaConfig {
        junk: Junk {
            count: 2,
            min: 10,
            max: 20,
        },
        ..AmneziaConfig::default()
    };
    let build = async |amnezia: AmneziaConfig| {
        let (tun, _, _) = mock::mock_tun();
        let (udp, handle) = PhobosUdpFactory::new(
            PipeFactory::new(Net::default(), IpAddr::V4(CLIENT_IP), 40000),
            config(),
        )
        .unwrap();
        DeviceBuilder::new()
            .with_private_key(StaticSecret::random())
            .with_ip(tun)
            .with_udp(udp)
            .with_phobos_handle(handle)
            .with_amnezia(amnezia)
            .build()
            .await
    };

    let err = build(junk.clone()).await.err().expect("must not build");
    assert!(
        matches!(err, Error::Amnezia(ConfigError::CombinedWithPhobos)),
        "{err:?}"
    );

    // Plain WireGuard is not "configured": Phobos builds over it, and
    // AmneziaWG cannot be switched on afterwards.
    let device = build(AmneziaConfig::default()).await.unwrap();
    let set = device
        .write(async |d| d.set_amnezia(Some(junk)).await)
        .await
        .unwrap();
    assert_eq!(set, Err(ConfigError::CombinedWithPhobos));
    assert_eq!(device.read(async |d| d.amnezia()).await, None);
}
