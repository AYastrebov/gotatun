use std::str::FromStr;
use std::sync::Mutex;

use super::{EINVAL, Request, UapiClient, UapiServer};
use crate::device::tests::mock::{self, MockDevice};

const PEER: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// A device pair where the first device is configured through UAPI.
async fn uapi_device() -> (UapiClient, MockDevice) {
    let (client, server) = UapiServer::new();
    let server = Mutex::new(Some(server));
    let (alice, _bob, _eve) =
        mock::device_pair_with(|builder| match server.lock().unwrap().take() {
            Some(server) => builder.with_uapi(server),
            None => builder,
        })
        .await;
    (client, alice)
}

/// Send one UAPI command and return the response text.
async fn uapi(client: &UapiClient, command: &str) -> String {
    let request = Request::from_str(command).expect("command parses");
    client.send(request).await.expect("response").to_string()
}

fn errno(response: &str) -> i32 {
    let line = response.lines().find(|l| l.starts_with("errno=")).unwrap();
    line["errno=".len()..].parse().unwrap()
}

#[tokio::test]
#[test_log::test]
async fn uapi_amnezia_set_get_round_trip() {
    let (client, device) = uapi_device().await;
    let set = "set=1\njc=5\njmin=10\njmax=50\ns1=20\ns2=30\ns3=40\ns4=8\n\
               h1=1210000000-1260000000\nh2=1370000000-1420000000\n\
               h3=1530000000-1580000000\nh4=1690000000-1740000000\n\
               i1=<b 0xc0ffee01><r 24>\nrekey_timeout=2-3\nrandom_trailers=true\n";
    assert_eq!(errno(&uapi(&client, set).await), 0);

    let cfg = device
        .device
        .read(async |d| d.amnezia())
        .await
        .expect("amnezia is set");
    assert_eq!(cfg.junk.count, 5);
    assert_eq!(cfg.padding.s3, 40);

    let get = uapi(&client, "get=1\n").await;
    let device_lines: String = cfg
        .to_uapi_lines()
        .iter()
        .map(|(k, v)| format!("{k}={v}\n"))
        .collect();
    assert!(
        get.contains(&device_lines),
        "{get}\n--- expected ---\n{device_lines}"
    );
    assert!(get.contains("jc=5\n") && get.contains("i1=<b 0xc0ffee01><r 24>\n"));
    assert!(get.contains("rekey_timeout=2-3\n"));
    assert!(get.ends_with("errno=0\n"));

    // What `get` prints is accepted by `set` and changes nothing.
    let echo = format!("set=1\n{device_lines}");
    assert_eq!(errno(&uapi(&client, &echo).await), 0);
    assert_eq!(device.device.read(async |d| d.amnezia()).await, Some(cfg));
}

#[tokio::test]
#[test_log::test]
async fn uapi_incremental_merge() {
    let (client, device) = uapi_device().await;
    assert_eq!(errno(&uapi(&client, "set=1\njc=3\n").await), 0);
    assert_eq!(errno(&uapi(&client, "set=1\ns1=20\n").await), 0);
    let cfg = device.device.read(async |d| d.amnezia()).await.unwrap();
    assert_eq!((cfg.junk.count, cfg.padding.s1), (3, 20));

    // Clearing a key goes back to its default; the others stay.
    assert_eq!(errno(&uapi(&client, "set=1\njc=0\n").await), 0);
    let cfg = device.device.read(async |d| d.amnezia()).await.unwrap();
    assert_eq!((cfg.junk.count, cfg.padding.s1), (0, 20));
}

#[tokio::test]
#[test_log::test]
async fn uapi_invalid_set_leaves_config_unchanged() {
    let (client, device) = uapi_device().await;
    assert_eq!(errno(&uapi(&client, "set=1\njc=3\ns1=20\n").await), 0);
    let before = device.device.read(async |d| d.amnezia()).await;

    // jmin > jmax is rejected after merging; the valid key is not applied either.
    let response = uapi(&client, "set=1\ns2=30\njc=5\njmin=90\njmax=10\n").await;
    assert_eq!(errno(&response), EINVAL);
    assert_eq!(device.device.read(async |d| d.amnezia()).await, before);

    // A key that does not parse never reaches the device.
    assert!(Request::from_str("set=1\njc=lots\n").is_err());
    assert!(Request::from_str("set=1\nh1=9-1\n").is_err());
    assert_eq!(device.device.read(async |d| d.amnezia()).await, before);
}

#[tokio::test]
#[test_log::test]
async fn uapi_peer_keepalive_range() {
    let (client, device) = uapi_device().await;
    let set = format!(
        "set=1\npublic_key={PEER}\npersistent_keepalive_interval=5-9\nallowed_ip=10.9.9.0/24\n"
    );
    assert_eq!(errno(&uapi(&client, &set).await), 0);

    let peers = device.device.peers().await;
    let key = x25519_dalek::PublicKey::from([0x11; 32]);
    let peer = peers.iter().find(|p| p.peer.public_key == key).unwrap();
    assert_eq!(peer.peer.keepalive_range, Some(5..=9));
    assert!(
        matches!(peer.peer.keepalive, Some(5..=9)),
        "{:?}",
        peer.peer.keepalive
    );

    let get = uapi(&client, "get=1\n").await;
    assert!(get.contains("persistent_keepalive_interval=5-9\n"), "{get}");

    // A change that does not mention keepalive keeps the range.
    let set = format!("set=1\npublic_key={PEER}\nendpoint=127.0.0.1:51820\n");
    assert_eq!(errno(&uapi(&client, &set).await), 0);
    assert!(
        uapi(&client, "get=1\n")
            .await
            .contains("persistent_keepalive_interval=5-9\n")
    );

    // A fixed interval replaces the range.
    let set = format!("set=1\npublic_key={PEER}\npersistent_keepalive_interval=25\n");
    assert_eq!(errno(&uapi(&client, &set).await), 0);
    let get = uapi(&client, "get=1\n").await;
    assert!(get.contains("persistent_keepalive_interval=25\n"), "{get}");

    // And a range replaces the fixed interval; a backwards one does not parse.
    assert!(
        Request::from_str(&format!(
            "set=1\npublic_key={PEER}\npersistent_keepalive_interval=9-5\n"
        ))
        .is_err()
    );
    let set = format!("set=1\npublic_key={PEER}\npersistent_keepalive_interval=7-7\n");
    assert_eq!(errno(&uapi(&client, &set).await), 0);
    assert!(
        uapi(&client, "get=1\n")
            .await
            .contains("persistent_keepalive_interval=7-7\n")
    );

    // `0` disables.
    let set = format!("set=1\npublic_key={PEER}\npersistent_keepalive_interval=0\n");
    assert_eq!(errno(&uapi(&client, &set).await), 0);
    assert!(
        !uapi(&client, "get=1\n")
            .await
            .contains("persistent_keepalive_interval")
    );

    // Both forms in one peer block: the last line wins, whichever order, as in
    // amneziawg-go.
    let set = format!(
        "set=1\npublic_key={PEER}\npersistent_keepalive_interval=10-20\npersistent_keepalive_interval=5\n"
    );
    assert_eq!(errno(&uapi(&client, &set).await), 0);
    let get = uapi(&client, "get=1\n").await;
    assert!(get.contains("persistent_keepalive_interval=5\n"), "{get}");
    let set = format!(
        "set=1\npublic_key={PEER}\npersistent_keepalive_interval=5\npersistent_keepalive_interval=10-20\n"
    );
    assert_eq!(errno(&uapi(&client, &set).await), 0);
    let get = uapi(&client, "get=1\n").await;
    assert!(
        get.contains("persistent_keepalive_interval=10-20\n"),
        "{get}"
    );
}

#[tokio::test]
#[test_log::test]
async fn uapi_awg1_key_errors() {
    for key in ["j1", "j2", "j3", "itime"] {
        let err = Request::from_str(&format!("set=1\n{key}=abc\n")).unwrap_err();
        assert!(format!("{err:#}").contains(key), "{key}: {err:#}");
    }
    // Other unknown keys are still rejected.
    assert!(Request::from_str("set=1\nbogus=1\n").is_err());
}
