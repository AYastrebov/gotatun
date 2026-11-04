# AmneziaWG and Phobos in GotaTun

This document covers the two obfuscation features added on top of GotaTun, both off by default:

* `amnezia`: AmneziaWG 2.0, 3.0 and 3.1, interoperable with
  [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) and the AmneziaWG kernel module.
  Works in both roles (initiator and responder) on one device. One config per device, applied to
  all peers. On by default for `gotatun-cli`.
* `phobos` (implies `device`): the client side of [Phobos](https://github.com/Ground-Zerro/Phobos)
  UDP obfuscation. Phobos and AmneziaWG are mutually exclusive on one device: the Phobos decoder
  needs bytes 1-3 of every WireGuard message to be zero, which AmneziaWG headers break. The device
  refuses to build with both.

With both features off, upstream code paths compile unchanged, with one deliberate exception that
is a plain-WireGuard bug fix: the handshake timestamp epoch (see
[Fixes made while porting](#fixes-made-while-porting)). With `amnezia` compiled in but no config
set, the device is plain WireGuard and skips all Amnezia work on the hot path.

## AmneziaWG

### Wire format by version

Sizes are those of plain WireGuard: initiation 148 bytes, response 92, cookie reply 64, transport
header 16 (plus the encrypted payload and 16-byte tag). The type field is a little-endian `u32`.

**2.0** (`jc jmin jmax`, `s1..s4`, `h1..h4`, `i1..i5`)

* The message type is a value drawn at random from the configured `H` range, instead of 1-4. The
  type is written before MAC1/MAC2 are computed, since the MACs cover it. The four ranges must not
  overlap.
* `S1`/`S2`/`S3`/`S4` random bytes are prepended to initiations, responses, cookie replies and
  transport packets. The receiver uses the known sizes (`S1 + 148`, `S2 + 92`, ...) to find the
  header.
* Before each initiation the sender emits, in order: the `I1..I5` custom signature packets (each
  its own datagram, rendered from its tag chain), `Jc` junk datagrams of random size in
  `[jmin, jmax)`, then the initiation. Receivers drop all of these silently.
* `S4` is also written on keepalives (they are transport packets). A transport packet whose `S4`
  bytes would make an unpatched peer's classifier misread it as a handshake gets the prefix
  redrawn (up to 8 tries).

**3.0** adds

* `header_protection_key`: the first 16 (transport), 64 (cookie), 92 (response) or 148
  (initiation) bytes of the message are XORed with a ChaCha20 keystream. The nonce is taken from
  the first 12 bytes of the random `S` prefix, which is why `s1..s4` must each be at least 12 with
  protection on. An all-zero key means off.
* `content_padding_addition`: a random number of zero bytes in the range is added inside the AEAD
  of transport packets. It is bounded by the UDP window, the TUN MTU and the buffer.
* Randomized timers: `rekey_after_time`, `rekey_timeout`, `reject_after_time`,
  `keepalive_timeout`, `max_handshake_attempts`, and the per-peer `persistent_keepalive_interval`
  as a range. Each is drawn at random from its range.

**3.1** adds

* `random_trailers`: a random-length tail is appended to initiations, responses and cookie replies
  (length uniform in `[0, window - size)`, where `window` is the sliding UDP window, 500 to begin
  with). The receiver trims by known message size. Transport packets get no trailer: content
  padding covers them.
* `disable_cookies`: never send a cookie reply, and skip the whole under-load path, including the
  MAC2 check.

### Config keys

`AmneziaConfig` is one struct for all three versions; its default is plain WireGuard. Key names and
formats are amneziawg-go's and are accepted over UAPI (see [UAPI.md](UAPI.md)):

| Key | Meaning |
|---|---|
| `jc jmin jmax` | junk packet count and size range |
| `s1 s2 s3 s4` | padding for initiation / response / cookie / transport |
| `h1 h2 h3 h4` | message type, number or `lo-hi` |
| `i1 .. i5` | CPS signature packets, e.g. `<b 0x..><r 24><t>` |
| `header_protection_key` | 64 hex characters |
| `content_padding_addition` | range `lo-hi` |
| `rekey_after_time rekey_timeout reject_after_time keepalive_timeout` | seconds, number or range |
| `max_handshake_attempts` | number or range |
| `random_trailers disable_cookies` | booleans |
| `persistent_keepalive_interval` (peer key) | seconds or range `a-b` |

Validation is no stricter than amneziawg-go. Only these are rejected: overlapping `H` ranges,
`jmin > jmax` when `jc > 0`, any of `s1..s4` below 12 when header protection is on, and the 1.x
keys `j1 j2 j3 itime`. `H` values 1-4 are allowed, gaps in `i1..i5` are allowed, and a full-`u32`
range does not overflow (it does overlap the other ranges, as in Go).

### Rust API

```rust
// Start from the default (plain WireGuard) and apply amneziawg-go key=value lines.
// `?` is a `gotatun::amnezia::ConfigError` (bad value); `Ok(false)` means an unknown key.
let mut cfg = AmneziaConfig::default();
cfg.apply_uapi_line("jc", "4")?;
cfg.apply_uapi_line("s1", "15")?;
cfg.apply_uapi_line("h1", "100000-200000")?;
cfg.validate()?;   // rules that span several keys; with_amnezia/set_amnezia check it again

// at build time; fails with Error::Amnezia if the config is invalid
let device = DeviceBuilder::new()
    .with_amnezia(cfg.clone())
    /* ... */;

// at run time: validate, swap in place, rebuild peer tunnels
// `None` turns obfuscation off
device.write(async |w| w.set_amnezia(Some(cfg)).await).await??;
// the first `?` is the device `Error` from `write`, the second the `ConfigError`
```

Filling the struct's public fields directly works too. The device normalises zero values the way
the UAPI parser does (an all-zero `header_protection_key` and a `0` content-padding range mean
off, a `0` timing range means "WireGuard default", an empty `I` chain is unset) before it
validates. The standalone `AmneziaConfig::validate()` and `is_plain_wireguard()` do **not**
normalise yet: a config with `header_protection_key: Some([0; 32])` and an `s` value below 12
fails `validate()` even though `with_amnezia`/`set_amnezia` accept it and treat it as plain
WireGuard. Either pass such configs straight to the device, or go through `apply_uapi_line`,
which already maps zero to `None`. (Tracked under [Known limitations](#known-limitations).)

`set_amnezia` keeps the UDP sockets (an embedder may hand over one pre-bound socket pair that
cannot be bound twice) and swaps the config in place. Each peer's `Tunn` is rebuilt, keeping its
keys, endpoint and explicit timer params, so every peer handshakes again. The rebuild resets
tx/rx byte stats and drops packets queued while waiting for a handshake. Setting the current
config again is a no-op.

### MTU

GotaTun does not track the outer MTU, so the inner (TUN) MTU must be set by the embedder:

```text
inner MTU = outer path MTU
          - IP/UDP header (28 for IPv4, 48 for IPv6)
          - 32 (WireGuard transport overhead)
          - AmneziaConfig::transport_overhead()   (= s4, AmneziaWG)
            or Masking::overhead()                (Phobos)
```

For a 1500-byte path that is `1500 - 28 - 32 = 1440` minus `s4` on IPv4, and
`1500 - 48 - 32 = 1420` minus `s4` on IPv6. The usual WireGuard 1420 is the IPv6-safe figure. Content padding is clamped by the
UDP window, the live TUN MTU and the buffer, but the MTU clamp is conservative: it compares the
inner MTU with the whole outer datagram.

### Receive classification

The device classifies each datagram before peer lookup (the peer is not yet known): strip the `S`
prefix, undo header protection (reusing the keystream from classification), trim the trailer, map
the type value to a message kind. A datagram that matches nothing is dropped silently. All
AmneziaWG receive traffic goes through this path, never through upstream's plain type check.

With `random_trailers`, transport is classified before handshakes. Otherwise the relaxed length
tests used for trailered handshakes steal about 3.5% of data packets. Two consequences are handled
on receive, as Go cannot be patched from our side:

* A handshake whose bytes at offset `s4` fall inside `H4` classifies as transport (about
  `width(H4) / 2^32` of handshakes). If the receiver index is unknown, the datagram is
  re-classified as a handshake only.
* A trailered response or cookie reply whose bytes at offset `s1` fall inside `H1` looks like an
  initiation (about `width(H1) / 2^32`) and fails MAC1. On a MAC1 failure the other handshake
  interpretations are tried (at most 3 per datagram) before the datagram is dropped.

### Differences from amneziawg-go

Deliberate, with no interop impact:

* **Give-up time.** The give-up for handshake retries is time-based (`rekey_timeout x attempts`),
  following GotaTun's existing timers. That gives N initiations where Go makes N+2.
  `max_handshake_attempts` defaults to 18 when only `rekey_timeout` is set (Go's
  `MaxTimerHandshakes`), so the give-up grows with the rekey range.
* **`rekey_after_receive`** (Go's `keyRefreshTimeoutReceiving`) is drawn once per session, not on
  every check.
* **Floors.** A drawn `max_handshake_attempts` of 0 becomes 1, and a drawn persistent keepalive
  of 0 becomes 1 s. A `0` in a timing key means "WireGuard default".
* **Retransmit jitter** stays at GotaTun's 0-333 ms, not Go's `[0, 334)`.
* **Persistent-keepalive re-arming and per-tunnel timing ranges** follow GotaTun's timers.
* **`persistent_keepalive_interval`** ranges are wired from `Peer::keepalive_range`.

Where Go behaviour was copied even though it looks odd:

* An `I` chain that renders to 0 bytes (for example `<d>`) is still sent, as an empty datagram.
  An unset chain is skipped.
* The UDP window is widened on **both** send (`S4 + 32 + plaintext length`, before content
  padding) and receive, starts at 500 and resets on endpoint change. Cookie replies always use
  the fixed window 500, even when the peer is known (Go's `randomTrailer`), so a cookie trailer
  is drawn from at most 500 bytes.
* `disable_cookies` gates the whole under-load path.
* With content padding or random trailers on, the drawn padding replaces WireGuard's 16-byte
  alignment instead of adding to it, so transport payloads are not 16-byte aligned. Go does the
  same (`RoutineEncryption` only pads to 16 when neither is on).
* Zero values handed to the device through the Rust API are read the way the UAPI reads them: an
  all-zero `header_protection_key` and a `0` content padding range mean off, a `0` timing range
  means "WireGuard default", and an empty `I` chain is unset (see the caveat under
  [Rust API](#rust-api)).

### Fixes made while porting

* **Handshake TAI64N epoch.** GotaTun used `2^62 + 37`; the kernel and Go use `2^62 + 10`, so the
  timestamp ran 27 s ahead. The fix is unconditional (it is a plain-WireGuard interop bug, and
  gating it on a feature would make two builds of this crate with the same key stamp 27 s
  apart). After an upgrade, a peer that has already seen the old, 27 s-ahead stamps from this
  key rejects the new initiations as replays until the clock catches up, for up to 27 s. The
  fix is submitted upstream to Mullvad separately.
* **Mock UDP channel** (tests): the IPv6 flow label could overflow 20 bits (commit `daa7bf9`).
* **awgtun** (the boringtun fork this port was checked against) had two bugs that are not carried
  over: on its device path, cookie replies lacked the 3.1 trailer (here every cookie reply is
  sealed through the same function and gets S3, H3, protection and a trailer), and its
  `AMNEZIA.md` said keepalives carry no `S4` prefix (they do).

## Phobos

Phobos puts an obfuscating proxy in front of a standard WireGuard server. Each WireGuard message
is XORed with a key-derived keystream, gets a random tail, and is framed as a STUN Data
Indication or an RTP packet. This is the client side only, written from the reference's observable
behaviour (the reference is (A)GPL; no code was ported from it).

### API

```rust
use gotatun::phobos::{Masking, PhobosConfig};

let mut cfg = PhobosConfig::new(key_bytes)?;   // key is used as raw bytes
cfg.masking = Masking::Stun;                   // None | Stun | Media

let device = DeviceBuilder::new()
    .with_phobos(cfg)?                         // wraps the default UDP sockets
    /* ... */;
```

`with_phobos` is the convenience form. To wrap your own transport, build a
`PhobosUdpFactory::new(inner_factory, cfg)?`, which returns the factory and a `PhobosHandle`, and
register the handle with `DeviceBuilder::with_phobos_handle`. `PhobosConfig::set(name, value)`
accepts the reference's key spellings (`masking`, `max-dummy`, `obfuscate-bytes`, `media-pt`,
`media-ssrc`, `media-clock`, ...) and returns `Ok(false)` for names the codec does not use. The
`auto` and `tls` masking values parse to `Masking::None`: on UDP they frame nothing. Phobos has no
UAPI surface.

### Behaviour

* A Phobos server drops everything except a handshake initiation from an address that has not
  completed one. After a rebind, nothing but an initiation leaves the new socket until one has
  been sent (a per-socket generation gate), and the transport asks the device for the initiation
  through the `PhobosHandle`. Under `Stun` and `Media` every initiation is preceded by a STUN
  Binding Request, so the first datagram on a new socket is that request, then the initiation.
  With `None` the first datagram is the initiation.
* The first bind counts as a rebind: the device sends an initiation to every peer with an
  endpoint as soon as the socket is up, even with no traffic to send.
* The periodic STUN Binding Request (every 10 s for `Stun`, 5 s for `Media`) is sent by a small
  task. A Binding Request from the server (the address the transport last sent to) is answered
  with a 40-byte Binding Success; one from any other address is dropped, so the client is not a
  STUN reflector.

### Embedder duty: `address_changed()`

`DeviceBuilder::with_phobos(cfg)` keeps the `PhobosHandle` private and is for the default sockets
only. An embedder that needs `address_changed()` (for example shoes switching Direct and Detour,
or any path or address change without a rebind) must instead build
`PhobosUdpFactory::new(inner, cfg)?`, keep the returned `PhobosHandle`, and register a clone with
`DeviceBuilder::with_udp(factory).with_phobos_handle(handle.clone())`.

A new `bind()` is noticed by the factory, but a change of local address or path **without a
rebind** (route change, NAT rebinding, an embedder switching Direct and Detour paths under a
single socket) is not. Call `PhobosHandle::address_changed()` whenever that happens. It closes
the gate until a new initiation has been sent and asks the device for one. Forgetting it leaves
the tunnel silent until the next rekey.

### MTU

Lower the tunnel MTU by `Masking::overhead()` (0 for `None`, 24 for `Stun`, 12 for `Media`). The
random tail added to cookie and transport messages (`max-dummy`) is only added while a message is
under 1024 bytes, so large packets are not padded further (the same 1024 cap bounds the dummy tail
of handshake messages). With `Stun` the framed message may not
exceed `Masking::max_message_len()`.

## Known limitations

Found in review and left as follow-ups; none affects interoperability on the paths `gotatun`
and the UAPI use.

* `AmneziaConfig::validate()` and `is_plain_wireguard()` do not normalise zero values (see
  [Rust API](#rust-api)); the device does. Fix: normalise inside both.
* Phobos: a rebind racing with an initiation still queued on the old socket can, in a window of a
  few instructions, let that old-socket initiation open the new socket's gate. The server then
  drops the new address's data until WireGuard's own retry, about 15 s. A correct fix needs the
  bind and `address_changed()` bumps to be serialised with the senders' generation reads.
* Phobos: the gate is per socket, not per peer (a Phobos client has one peer, so this is fine),
  and an `address_changed()` in the middle of a batched send lets the rest of that one batch
  through.
* With `random_trailers` off, two message kinds can still be the same size (for example
  `s1 + 148 == s2 + 92`); the first match wins, as in amneziawg-go. Avoid such `s` values.
* `set_amnezia` rebuilds each peer's `Tunn` but not its DAITA instance.
* Every datagram takes a read lock on the shared Amnezia config cell even when nothing is
  configured. The `Tunn` benchmark cannot see it; a device-level benchmark could.
* Classifying a trailered transport packet takes one index-table lock per packet, shared with
  index allocation at handshake time.
* `DeviceRead::peers()` returns the AmneziaWG-derived timer params as explicit
  `danger_timer_params` only while no config is set; peers round-tripped through `with_peers`
  before `set_amnezia(Some(..))` keep those pinned defaults, as upstream semantics require.

## Rebasing on upstream

New code lives in new files (`amnezia/`, `phobos/`, `device/amnezia.rs`, `device/tests/`, the
`*_amnezia_tests.rs` test files and `noise/tests/amnezia.rs`), and most edits to upstream files
are added, cfg-gated lines. These upstream edits are not purely additive and are where a rebase
is most likely to conflict:

* `device/mod.rs`: the send path's `#[cfg(not(feature = "daita"))]` became
  `#[cfg(not(any(feature = "daita", feature = "amnezia")))]`, and the timer loop's
  `match p.update_timers()` became `match timers` (Phobos may force an initiation instead).
* `noise/mod.rs`: on the send path, `if !packet.is_keepalive()` became a local `is_keepalive`
  decided before Amnezia padding (a padded keepalive is no longer empty); upstream's `mod tests`
  ends with two lines declaring the Amnezia tests.
* `noise/timers.rs`: the `REJECT_AFTER_TIME`, `REKEY_ATTEMPT_TIME` and
  `REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT` constants in `update_timers` and
  `update_session_timers` became per-tunnel methods (`reject_after_time()`,
  `rekey_attempt_time()`, `rekey_after_receive()`).
* `device/configure.rs` (`DeviceRead::peers`) and `device/uapi/mod.rs` (peer update): the
  `danger_timer_params` field is split into `cfg(feature = "amnezia")` and
  `cfg(not(feature = "amnezia"))` variants.
* `device/tests/mock.rs`: `device_pair` is re-indented around a builder hook
  (`device_pair_with`).
* `udp/channel.rs`: the mock channel's flow-label fix is active with the features off too.

## Throughput

The existing `throughput_benches` and `crypto_benches` never touch `Tunn` or the device path, so
they cannot show the cost of compiling `amnezia` in. `cargo bench -p gotatun --bench tunn_benches`
does: it completes a handshake between two `Tunn`s and loops encapsulate + decapsulate of a
1400-byte IPv4 packet (`Tunn::handle_outgoing_packet` and `handle_incoming_packet`, no TUN MTU,
no Amnezia config). Measured with `-- --warm-up-time 1 --measurement-time 5`:

| Features | Median time per packet | Throughput |
|---|---|---|
| `device` | 2.2642 us | 589.67 MiB/s |
| `device,amnezia` (no config) | 2.2641 us | 589.70 MiB/s |

The difference is far below criterion's noise. The bench runs the `Tunn` hot path only (no UDP
sockets or device tasks).

## Testing against a live AmneziaWG server

The owner-run smoke test: two GotaTun devices talking to each other prove only that the code is
self-consistent; a real server proves it speaks AmneziaWG. It takes about a minute. You need an
AmneziaWG `.conf` of a working server, root, and `socat`. All values below are placeholders.

1. Translate the `.conf` into a UAPI block. The two formats differ:
   * keys are lower-cased and CamelCase becomes snake_case (`ContentPaddingAddition` becomes
     `content_padding_addition`);
   * `PrivateKey`, `PublicKey`, `PresharedKey` and `HeaderProtectionKey` go from base64 to hex
     (`private_key=<64 hex>`, `header_protection_key=<64 hex>`);
   * `Endpoint` must be `ip:port` (no DNS name);
   * `MTU`, `Address`, `DNS` have no UAPI key: set them with `ip`.

   Interface keys come first, then `replace_peers=true`, then the peer section. For the test,
   replace the peer's `AllowedIPs` by the tunnel subnet only, so the machine's default route is
   not hijacked.

2. Start the device (this creates `/var/run/wireguard/awgtest0.sock`):

   ```bash
   sudo WG_SUDO=1 ./target/release/gotatun --disable-drop-privileges \
       -f -v debug -l /tmp/gotatun.log awgtest0
   ```

   (The executable built from the `gotatun-cli` crate is named `gotatun`; it enables the
   `amnezia` feature by default.) On macOS the interface name is `utun` or `utun<N>`; the real
   name can be written to a file with `--tun-name-file` (or `WG_TUN_NAME_FILE`), and the socket is
   named after the interface you passed.

3. Push the config. A template (no real values; `errno=0` is success, `errno=22` means the
   AmneziaWG block was rejected, so check the log):

   ```text
   set=1
   private_key=<64 hex chars>
   jc=<n>
   jmin=<n>
   jmax=<n>
   s1=<n>
   s2=<n>
   s3=<n>
   s4=<n>
   h1=<lo-hi>
   h2=<lo-hi>
   h3=<lo-hi>
   h4=<lo-hi>
   i1=<b 0x..><r n><t>
   header_protection_key=<64 hex chars>
   content_padding_addition=<lo-hi>
   random_trailers=true
   replace_peers=true
   public_key=<64 hex chars>
   preshared_key=<64 hex chars>
   endpoint=<server ip>:<port>
   allowed_ip=<tunnel subnet, e.g. 10.0.0.0/24>
   persistent_keepalive_interval=25

   ```

   (The block ends with an empty line.) Send it with:

   ```bash
   printf 'set=1\n%s\n\n' "$(cat uapi.txt)" | sudo socat - UNIX-CONNECT:/var/run/wireguard/awgtest0.sock
   ```

   where `uapi.txt` holds the lines after `set=1`, without it.

4. Address, route and test:

   ```bash
   sudo ip addr add <client tunnel ip>/32 dev awgtest0
   sudo ip link set mtu <1420 - s4> up dev awgtest0
   sudo ip route add <tunnel subnet> dev awgtest0
   ping -c 4 <server tunnel ip>
   printf 'get=1\n\n' | sudo socat - UNIX-CONNECT:/var/run/wireguard/awgtest0.sock
   ```

   (`1420 - s4` is the IPv6-safe MTU for a 1500-byte path; see MTU above.)

   Healthy: 0% loss, a `last_handshake_time_sec` line, and `get=1` echoes back every AmneziaWG
   key that was set. `rx_bytes`/`tx_bytes` stay at 0 until real traffic flows.

5. Tear down with `sudo ip link del awgtest0`, and delete `uapi.txt`: it holds the private key and
   preshared key. Never paste the block into an issue, a commit or a transcript; redact with
   `sed -E 's/^(private_key|public_key|preshared_key|header_protection_key)=.*/\1=<redacted>/'`.

To see what left the machine, capture first with `sudo tcpdump -i any -n "udp and host <server ip>"
-w /tmp/awg.pcap`. Expect each configured I packet as its own datagram, then `jc` junk datagrams in
`[jmin, jmax)`, then one datagram of `148 + s1` bytes (plus a trailer with `random_trailers`). The
response is `92 + s2`.
