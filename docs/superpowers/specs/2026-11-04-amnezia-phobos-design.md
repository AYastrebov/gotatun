# AmneziaWG 2.0 / 3.0 / 3.1 and Phobos in gotatun — design

Date: 2026-11-04
Status: approved 2026-11-04; implemented on `feat/amnezia-phobos` the same day — see
[Implementation notes](#implementation-notes) at the end for where the build departed from this
text, and `docs/amnezia.md` for the user-facing description.

## Intent

Add AmneziaWG 2.0, 3.0 and 3.1 obfuscation and the Phobos UDP obfuscation
codec to this gotatun fork, so that upstream shoes (`cfal/shoes` `master`, which
already runs gotatun as both a WireGuard client and server) can later offer
them.

The owner already has these features in `~/VibeCode/awgtun`, a boringtun fork.
gotatun is the better WireGuard stack, so this is a **port that rebuilds the
features properly on gotatun's architecture**, using awgtun as the behavioural
reference and its recorded bug fixes as the test checklist — not a line-by-line
copy.

## Scope

**This project: gotatun only.** The shoes integration is a later, separate
project. It will use YAML option A (below), so gotatun's API is shaped to map
onto it 1:1.

### Goals

1. AmneziaWG 2.0: Jc/Jmin/Jmax junk, S1–S4 padding, H1–H4 header ranges,
   I1–I5 CPS signature packets.
2. AmneziaWG 3.0: header protection, content padding, randomized timing ranges.
3. AmneziaWG 3.1: random trailers, `disable_cookies`.
4. Amnezia works for **both roles**: initiator (client) and responder (server)
   in the same device, interoperable with amneziawg-go and the AWG kernel
   module.
5. Phobos: **client side only**, plain WireGuard only (Phobos and Amnezia are
   mutually exclusive on one device — the Phobos decoder needs bytes 1–3 of
   each WG message to be zero).
6. Configurable through the Rust API (`DeviceBuilder` / `DeviceWrite`) and, for
   Amnezia, through UAPI using the amneziawg-go key names, so `gotatun-cli`
   with `awg`-style tooling works.
7. Every awgtun correctness fix listed under "Behaviour to preserve" is kept
   and has a test.

### Non-goals

- shoes changes (later project).
- Phobos server side / `auto` detection / `tls` masking (behaves as `none`, as
  in awgtun).
- Per-peer Amnezia settings. **One Amnezia config per device**, applied to all
  peers. This matches amneziawg-go (all AWG keys are interface keys) and shoes
  (one server record holds the device settings; its `peers:` entries carry
  only key, PSK, endpoint, allowed IPs and keepalive). The one per-peer item,
  `persistent_keepalive_interval`, stays per-peer as in Go.
- AWG 1.x keys (`j1`, `j2`, `j3`, `itime`) — rejected with a clear error.
- C FFI / JNI bindings, mobile.
- Any change to `~/VibeCode/awgtun` or the shoes fork branches (read-only
  references).

### Anti-goals (failure even if it "works")

- Plain WireGuard behaviour, wire format or throughput changes when Amnezia and
  Phobos are not configured.
- Wire format that diverges from amneziawg-go (the interop reference).
  Validation must be **no stricter** than amneziawg-go.
- Real H/S/J/I values, Phobos keys or server ports committed anywhere
  (tests use synthetic values with the real shape — see awgtun `CLAUDE.md`).
- Copying code from the Phobos reference implementation (it is (A)GPL).
  awgtun's codec was written from the spec and is BSD-3; porting it into this
  MPL-2.0 crate is fine.

### Constraint: stay rebaseable on Mullvad upstream

The owner wants to rebase this fork on Mullvad's upstream gotatun without much
effort. So:

- **Keep new code in new files** (`amnezia/`, `phobos/`); edits to existing
  upstream files are small, local hooks (a call, a field, a match arm), not
  restructuring. Prefer adding a function next to an upstream one over
  rewriting it.
- **No breaking changes to gotatun's existing public API.** New API is
  additive (`with_amnezia`, `set_amnezia`, new types). For `packet/wg.rs`,
  keep the existing structs and constructors working with their WireGuard
  defaults; add Amnezia-aware variants/setters alongside.
- Everything Amnezia/Phobos sits behind the `amnezia` / `phobos` cargo
  features, so upstream code paths compile unchanged with them off.
- **Commit as a clean, ordered patch series** (one concern per commit: config
  types, packet type field, handshake/MAC, transport, receive classifier,
  timers, UAPI, Phobos codec, Phobos transport, docs), so a rebase conflict is
  local to one commit.
- Don't reformat or rename upstream code; don't bump upstream dependencies
  unless required.

## Reference material

| What | Where |
|---|---|
| AWG wire format, per-version behaviour, deliberate differences from Go | `~/VibeCode/awgtun/AMNEZIA.md` |
| Config types, validation, CPS, junk, header protection, RNGs | `~/VibeCode/awgtun/awgtun/src/amnezia.rs` |
| Send/receive integration, classifier, misclassification redraw | `~/VibeCode/awgtun/awgtun/src/noise/mod.rs` |
| Device receive path (classify before peer lookup, trailer trim) | `~/VibeCode/awgtun/awgtun/src/device/mod.rs:743-947` |
| UAPI keys and incremental merge | `~/VibeCode/awgtun/awgtun/src/device/api.rs` |
| Phobos spec notes and codec | `~/VibeCode/awgtun/docs/phobos.md`, `awgtun/src/phobos/` |
| Fix history | `~/VibeCode/awgtun/CHANGELOG.md` |
| Live server test procedure | `~/VibeCode/awgtun/.claude/skills/amnezia-dev/references/live-server-test.md` |
| AWG interop reference (authoritative wire format) | https://github.com/amnezia-vpn/amneziawg-go (local checkout: `~/VibeCode/amneziawg-go`) |
| Phobos reference implementation (authoritative behaviour) | https://github.com/Ground-Zerro/Phobos — awgtun was pinned to commit `22aedef`; check for changes since. **(A)GPL: read for behaviour, never copy code.** |

Where awgtun and a reference disagree, the reference wins unless awgtun
documents a deliberate difference (`AMNEZIA.md:1257-1275`).

## Architecture

### Where things live in gotatun

```
gotatun/src/
  amnezia/            NEW (feature "amnezia")
    config.rs         AmneziaConfig + sub-types, validation, UAPI parse/emit
    cps.rs            I1–I5 tag chains
    junk.rs           junk packet generation
    header_protection.rs
    classify.rs       PacketClassifier (works without a peer)
    rng.rs            FastRandom / OsRandom
  phobos/             NEW (feature "phobos")
    codec.rs          PhobosCodec (sans-IO, ported from awgtun)
    transport.rs      PhobosUdpFactory<F>: UdpTransportFactory wrapper
  packet/wg.rs        type byte becomes a configurable u32 (see below)
  noise/              handshake/session/rate_limiter/timers take the AWG knobs
  device/             device-wide AmneziaConfig, receive classification,
                      pre-handshake I/junk emission, UAPI keys
```

### Amnezia: in the core, not a UDP wrapper

A UDP-transport wrapper is not enough for Amnezia:

- **H1–H4** values are written into the message *before* mac1/mac2 are
  computed (the MACs cover the type field), so they must be set inside
  `noise/handshake.rs` / `rate_limiter.rs` / `session.rs`.
- **Header protection** (3.0) is keyed by the S-prefix and covers MAC'd bytes;
  **content padding** (3.0) lives inside the AEAD; **timing ranges** (3.0)
  live in timers.
- Classifying an incoming datagram (strip S-prefix, unprotect header, trim
  trailer, map H value → kind) has to happen in `handle_incoming` **before**
  peer lookup, because the peer is not yet known. Since the config is
  device-wide, the classifier needs only the device config.

So Amnezia is implemented in the core, following awgtun's layering:

- `amnezia/` is pure: config, validation, primitives, classifier. No I/O.
- The noise layer gets narrow knobs only (`msg_type: u32`, content padding
  length, `disable_cookies`, timing ranges) and stays ignorant of ranges and
  prefixes where possible.
- Prefix/protection/trailer application on send, and stripping on receive,
  sit at the boundary between `Tunn`/`PeerState` and the UDP send/recv calls in
  `device/mod.rs` — one place for send, one for receive — instead of being
  duplicated across `Tunn` and the device as in awgtun.

#### Send path

- Every outgoing WG message is finalised by one function
  (`amnezia::Obfuscator::seal(kind, &mut Packet) -> Packet`): pick H, write it
  (for handshakes this happens before MACs — via the knob), add S-prefix, apply
  header protection, add trailer (3.1, handshakes and cookie replies), redraw
  S4 prefix for transport packets if an unpatched peer would misclassify it.
- Transport data: `Session::format_packet_data` currently allocates
  `OVERHEAD + len`; reserve headroom for S4 there so the prefix is written in
  place, not by copying.
- **Pre-handshake packets** (I1–I5 then Jc junk, then the initiation) are
  emitted at every initiation send site: `handle_outgoing` (data-triggered),
  `handle_timers` (retries) and `Device::force_handshake`. They must go out in
  order on the same queue as the initiation (note: `force_handshake` currently
  bypasses `BufferedUdpSend`; route it consistently).
- Responder side: handshake responses and cookie replies (including the
  under-load cookie reply sent directly from `handle_incoming`) get S2/S3,
  H2/H3, protection and trailers.

#### Receive path

`handle_incoming` runs the device-wide classifier first: strip prefix →
unprotect header (reusing the keystream derived during classification) → trim
trailer by known message size → hand a normal-looking WG message to the
existing rate limiter / peer lookup / `Tunn` code. Datagrams that classify as
nothing (junk, I-packets, garbage) are dropped silently.

#### MTU / sizes

S4 adds to every outer datagram. gotatun has no outer-MTU tracking; content
padding is clamped by the UDP window, the live `MtuWatcher` value and the
buffer, as in awgtun. Embedders (shoes) must lower the inner MTU by S4 (the
docs say so; a helper `AmneziaConfig::transport_overhead()` returns the
number).

### Phobos: a UDP transport wrapper

Phobos does fit gotatun's `UdpTransportFactory` / `UdpSend` / `UdpRecv` seam:
it only rewrites whole datagrams, and as a client there is one endpoint.

- `PhobosUdpFactory<F: UdpTransportFactory>` wraps any factory (the default
  sockets, or shoes' own factory), so an embedder composes it explicitly;
  `DeviceBuilder::with_phobos(cfg)` is offered as a convenience over the
  default UDP factory.
- Send: `wrap()`; if a Binding Request is due, send it first.
- Receive: `unwrap()`; deliver `WireGuard` payloads, answer `Reply` (server's
  Binding Request → 40-byte Success) directly, drop `Drop`.
- A small task sends the periodic Binding Request (`control_interval()`).
- `Masking::overhead()` is exposed so the inner MTU can be lowered.
- Device refuses to build with both Amnezia and Phobos configured.

### Configuration surfaces

Rust API (mirrors the future shoes YAML option A):

```rust
let device = DeviceBuilder::new()
    .with_amnezia(AmneziaConfig { ... })   // absent = plain WireGuard
    ...;
device.write(|w| w.set_amnezia(cfg))      // validated; rebuilds peer tunnels
```

`AmneziaConfig` is one struct for 2.0/3.0/3.1 (all fields optional/default =
plain WireGuard), with a `parse`/`to_uapi_block` pair that uses amneziawg-go
key names: `jc jmin jmax s1..s4 h1..h4 i1..i5 header_protection_key
content_padding_addition rekey_after_time rekey_timeout reject_after_time
keepalive_timeout max_handshake_attempts persistent_keepalive_interval
random_trailers disable_cookies`.

UAPI: these keys are accepted on `set=1` as interface keys (incremental merge,
then validate, then rebuild peers — as awgtun does) and emitted on `get=1`
(non-defaults only, so the block round-trips). `UAPI.md` documents them.
Phobos has no UAPI surface (Rust API only).

Shoes YAML option A, for the later project (recorded so the API matches):

```yaml
type: wireguard
amnezia:            # absent = plain WireGuard
  jc: 4
  s1: 15
  h1: "100000-200000"
  i1: "<b 0x...><r 16>"
  header_protection_key: ...
  random_trailers: true
phobos:             # client only, plain WireGuard only
  key: ...
  masking: stun
```

## Behaviour to preserve (each needs a test)

From awgtun's audit and changelog:

1. With trailers on, classify transport **before** handshake types (relaxed
   `>=` handshake size tests otherwise steal ~3.5% of data packets).
2. Send-side redraw of the S4 prefix (≤ 8 tries) so an unpatched peer's
   classifier (init → response → cookie order, `==`/`>` tests) won't
   misclassify our transport packets.
3. Trim the trailer before parsing on the device receive path.
4. Content padding bounded by the UDP window, measured on the whole datagram
   (S4 + 32 + payload), also clamped by MTU and buffer space.
5. UDP window is widened unconditionally (send and receive), starts at 500,
   resets on endpoint change.
6. S1–S4 and Jc are `u16`. Oversized padding returns an error instead of
   panicking; the device drops that reply.
7. Retransmit / new-handshake jitter 0–334 ms, drawn per initiation.
8. Keepalive detection: outbound by empty payload, inbound by first byte 0
   (content-padded keepalive decrypts to zeros); non-IP payload counts as data
   received.
9. `disable_cookies` disables the whole under-load path including the MAC2
   check.
10. CPS random lengths capped only by 65535.
11. Validation no stricter than Go: only non-overlapping H ranges,
    `Jmin <= Jmax` (when Jc > 0), and S ≥ 12 when header protection is on.
    H values 1–4 allowed; gaps in I1–I5 allowed.
12. Junk sizes and trailer lengths are half-open ranges.
13. Cookie replies get S3, H3, protection **and a trailer on every path**
    (awgtun's device path is missing the trailer — fix, don't copy).
14. Keepalives carry the S4 prefix (awgtun's `AMNEZIA.md:473` says otherwise;
    the code is right).
15. UAPI `set=1` merges incrementally; `get=1` emits only non-defaults.
16. Header-protection keystream from classification is reused, not re-derived.
17. Per-packet randomness uses a fast per-thread ChaCha RNG that is reset
    after `fork()` (the S-prefix is the header-protection nonce); long-lived
    secrets use the OS RNG.
18. Full-u32 H ranges do not overflow; little-endian type field; all-zero
    header-protection key means off.
19. awgtun's documented deliberate differences from Go (no 16-byte content
    alignment, persistent-keepalive re-arm behaviour, per-tunnel timing
    ranges) — keep unless a test against Go shows a problem.
20. Handshake timestamp epoch matches kernel WireGuard (check gotatun already
    does; awgtun needed a fix here).

Phobos: the reference conformance vectors (keystream masks, decode, Binding
Success) from awgtun's `phobos/test_vectors.rs`.

## Testing

- Unit tests for `amnezia/` and `phobos/` (ported from awgtun's 53 + 32 tests
  where they still apply).
- Device-level tests on gotatun's in-memory `device_pair()` with the
  `MockEavesdropper`, asserting on raw wire bytes: client↔server handshake and
  data with each AWG version, a negative control (AWG vs plain WG must fail),
  pre-handshake I/junk ordering, cookie path under load with trailers.
- The Go-keystream differential and the unpatched-peer classifier tests from
  awgtun.
- `cargo hack check --feature-powerset` must pass (CI already runs it).
- **End-to-end against real AmneziaWG and Phobos servers is done by the
  owner**, using `gotatun-cli` + UAPI for Amnezia and a small example binary
  for Phobos.

### Timing ranges (AWG 3.0) vs gotatun's `TimerParams`

gotatun already has per-peer randomized `TimerParams` (`noise/timers.rs:74`,
`Peer::danger_timer_params`). AWG 3.0 timings **extend `TimerParams`** rather
than adding a parallel mechanism: add `reject_after_time`,
`max_handshake_attempts` (time-based give-up `rekey_timeout × attempts`
replacing the fixed `REKEY_ATTEMPT_TIME` only when set), and the AWG
new-handshake formula. The device-wide `AmneziaConfig` timing ranges are the
default `TimerParams` for every peer; an explicit per-peer
`danger_timer_params` wins over them; `set_amnezia` rebuilding tunnels keeps
per-peer params. `persistent_keepalive_interval` follows amneziawg-go: it is a
**peer** key (UAPI and `Peer`) that accepts a single value or a range — it is
not part of the device-wide `AmneziaConfig`.

### Phobos rebind / roaming

A Phobos server drops everything except a handshake initiation from an address
that has not completed one (found in the owner's shoes Phobos work, commits
05644faf, 4b154886, 5b3ea6c4 on `feat/phobos-obfuscation`). So in scope:

- After any rebind or local-address change (driven by gotatun or by the
  embedder's own factory), the first datagram sent must be an initiation;
  other traffic is held/dropped until that send succeeded (per-socket
  generation gate).
- The wrapper can ask the device to start a handshake: a small back-channel
  (e.g. a "needs initiation" signal the device polls in `handle_timers`, or a
  handle that calls `force_handshake`). Builder picks the mechanism.
- The periodic Binding Request only runs while the last handshake is < 180 s
  old.

### Cost when compiled in but not configured

shoes will always compile `amnezia` in and mostly run plain WireGuard. A
runtime `Option` check on hot paths is acceptable; the unconfigured path must
skip all Amnezia work (no classification, no extra headroom, no RNG). Gate:
`throughput_benches` with the feature on and no config show no regression
beyond noise vs. the feature off.

## Decisions made by Claude (check these)

- Timing ranges extend `TimerParams`; per-peer params win;
  `persistent_keepalive_interval` is a peer key accepting ranges (as in Go).
- Phobos rebind handling is in scope, with a device back-channel.
- Runtime `Option` branches are fine; verified by benchmarks.

- Cargo features `amnezia` and `phobos`, both off by default, so builds that
  don't use them are unchanged. (Alternative: always compiled, like awgtun.)
- Amnezia is device-wide, stored in `DeviceState`; changing it rebuilds peer
  tunnels.
- Phobos is exposed as a composable `UdpTransportFactory` wrapper, because
  shoes supplies its own UDP factory.
- Amnezia UAPI uses amneziawg-go key names; Phobos gets no UAPI.
- Work happens on a feature branch in this repo, not `main`.

## Left to the builder

- Exact type and function names, module split inside `amnezia/`.
- How the `msg_type` knob is threaded through `packet/wg.rs` (keep the
  zerocopy structs; make the type field a plain `u32` with a setter, or a
  const-generic default).
- Whether CPS/junk are queued on `PeerState` or returned alongside the
  initiation from `Tunn`, as long as ordering on the wire is I1..I5, junk,
  initiation.
- Order of implementation (2.0 → 3.0 → 3.1 → Phobos is the natural one).

## Implementation notes

Decisions taken during the build that change or sharpen the text above. The wire authority was
a fresh checkout of amneziawg-go (`b5928ef`); where this document, the plan and Go disagreed, Go
won unless awgtun's `AMNEZIA.md` documents a deliberate difference.

- **S4 on transport packets is added by one allocation and copy**, not zero-copy headroom:
  gotatun's `Packet<WgData>` cannot carry headroom without changing public types. The
  unconfigured path is unaffected (benchmarked in `tunn_benches`).
- **The UDP window is widened on both send and receive** (Go `send.go` `RoutineEncryption` and
  `receive.go`), with the pre-padding size on send; `seal` only reads it. Cookie replies always
  draw their trailer from the fixed 500-byte window, as Go's `device.randomTrailer` does.
- **An `I` chain that renders to zero bytes is still sent** as an empty datagram (Go sends every
  non-nil chain).
- **`max_handshake_attempts` defaults to 18** (Go's `MaxTimerHandshakes`) when only
  `rekey_timeout` is set, so the give-up time grows with the rekey range; the "only when set"
  wording above was too narrow.
- **`set_amnezia` never restarts the connection or rebinds sockets**: shoes hands over one
  pre-bound socket pair whose `bind()` errors on a second call. The config lives in a shared
  cell read per packet.
- **Receive-side recovery of misclassified trailered handshakes** (not in this document): with
  `random_trailers`, transport-first classification misreads about `width(H4)/2^32` of
  handshakes as data, and a trailered response can look like an initiation
  (`width(H1)/2^32`). Both are recovered on receive (idx-miss re-classification; trying the other
  handshake kinds on MAC1 failure, at most 3 per datagram). This also helps Go senders.
- **The handshake TAI64N epoch fix** (gotatun used `2^62 + 37`, kernel and Go `2^62 + 10`) was
  first gated on the `amnezia` cargo feature to keep feature-off builds identical to upstream,
  then made unconditional: two builds of this crate sharing a key would otherwise stamp 27 s
  apart. This is the one place a feature-off build differs from Mullvad's, until the fix lands
  upstream (submitted separately).
- **Phobos `Masking`** keeps three variants (`None`, `Stun`, `Media`); `auto` and `tls` parse to
  `None`. A `PhobosHandle::address_changed()` was added for local-address changes without a
  `bind()` (route change, NAT rebinding, shoes switching Direct/Detour); embedders that need it
  must wrap their own factory with `PhobosUdpFactory::new` and keep the handle, since
  `with_phobos` keeps it private.
- **Timing ranges** extend `TimerParams` through a separate `TimerExtras` (reject-after,
  max-attempts, receive-side rekey, per-peer keepalive range); `TimerParams` itself is unchanged.
- **Tests that need upstream's private test helpers** stay declared from inside the upstream test
  modules (two lines each) but live in sibling files; see "Rebasing on upstream" in
  `docs/amnezia.md`.
- **Open follow-up:** `AmneziaConfig::validate()` / `is_plain_wireguard()` do not normalise
  zero values the way the device does, so a direct Rust-API caller can get a spurious
  `HeaderProtectionPaddingTooSmall` for an all-zero key. One-line fix.
