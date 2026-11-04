// Copyright (c) 2026 Mullvad VPN AB. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Encapsulate + decapsulate of a 1400-byte IPv4 packet through two [`Tunn`]s.
//!
//! Run with and without `--features amnezia` (and no Amnezia config) to check that plain
//! WireGuard throughput is unchanged by compiling the feature in.

use std::hint::black_box;
use std::sync::Arc;

use bytes::BytesMut;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use gotatun::noise::index_table::IndexTable;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{Tunn, TunnResult};
use gotatun::packet::{Packet, WgKind};

const PACKET_LEN: usize = 1400;

fn tunns() -> (Tunn, Tunn) {
    let a_secret = gotatun::x25519::StaticSecret::random_from_rng(rand_core::OsRng);
    let a_public = gotatun::x25519::PublicKey::from(&a_secret);
    let b_secret = gotatun::x25519::StaticSecret::random_from_rng(rand_core::OsRng);
    let b_public = gotatun::x25519::PublicKey::from(&b_secret);

    let a_limiter = Arc::new(RateLimiter::new(&a_public, 100));
    let a = Tunn::new(
        a_secret,
        b_public,
        None,
        None,
        IndexTable::from_os_rng(),
        a_limiter,
    );
    let b_limiter = Arc::new(RateLimiter::new(&b_public, 100));
    let b = Tunn::new(
        b_secret,
        a_public,
        None,
        None,
        IndexTable::from_os_rng(),
        b_limiter,
    );
    (a, b)
}

fn handshake(a: &mut Tunn, b: &mut Tunn) {
    let init = a.format_handshake_initiation(false).expect("init");
    let TunnResult::WriteToNetwork(WgKind::HandshakeResp(resp)) =
        b.handle_incoming_packet(WgKind::HandshakeInit(init))
    else {
        panic!("expected a handshake response");
    };
    let TunnResult::WriteToNetwork(WgKind::Data(keepalive)) =
        a.handle_incoming_packet(WgKind::HandshakeResp(resp))
    else {
        panic!("expected a keepalive");
    };
    b.handle_incoming_packet(WgKind::Data(keepalive));
}

fn ipv4_bytes() -> Vec<u8> {
    let header =
        etherparse::PacketBuilder::ipv4([192, 168, 1, 2], [192, 168, 1, 3], 5).udp(5678, 23);
    let payload = vec![0x5a; PACKET_LEN - 28];
    let mut bytes = Vec::with_capacity(header.size(payload.len()));
    header.write(&mut bytes, &payload).unwrap();
    bytes
}

fn encapsulate_decapsulate(c: &mut Criterion) {
    let (mut a, mut b) = tunns();
    handshake(&mut a, &mut b);
    let template = ipv4_bytes();

    let mut group = c.benchmark_group("tunn");
    group.throughput(Throughput::Bytes(PACKET_LEN as u64));
    group.bench_function("encapsulate_decapsulate_1400", |bench| {
        bench.iter(|| {
            let packet = Packet::from_bytes(BytesMut::from(&template[..]));
            let Some(WgKind::Data(data)) = a.handle_outgoing_packet(packet, None) else {
                panic!("expected data");
            };
            let TunnResult::WriteToTunnel(out) = b.handle_incoming_packet(WgKind::Data(data))
            else {
                panic!("expected plaintext");
            };
            black_box(out);
        });
    });
    group.finish();
}

criterion_group!(benches, encapsulate_decapsulate);
criterion_main!(benches);
