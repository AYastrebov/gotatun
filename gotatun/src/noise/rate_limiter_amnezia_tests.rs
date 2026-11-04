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
fn mac1_matches_checks_init_and_response() {
    let rl = limiter(10);
    let init = init_with_h(&rl);
    assert!(rl.mac1_matches(init.as_bytes()));
    let mut resp = WgHandshakeResp::new(5, 6, [3; 32]);
    resp.set_wire_type(H_RESP);
    set_mac1(&rl, &mut resp);
    assert!(rl.mac1_matches(resp.as_bytes()));

    // The response's bytes read as anything else fail.
    let mut bytes = resp.as_bytes().to_vec();
    bytes[8] ^= 1;
    assert!(!rl.mac1_matches(&bytes));
    assert!(!rl.mac1_matches(&init.as_bytes()[..WgHandshakeResp::LEN]));
    assert!(!rl.mac1_matches(&[0; 16]));
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
