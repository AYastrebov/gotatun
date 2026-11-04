# AmneziaWG 2.0/3.0/3.1 + Phobos in gotatun — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add AmneziaWG 2.0/3.0/3.1 (client and server) and a client-side Phobos transport to gotatun, interoperable with amneziawg-go and the Phobos reference, while staying easy to rebase on Mullvad upstream.

**Architecture:** Pure config/primitives live in new `amnezia/` and `phobos/` modules. The core gets a few narrow hooks: H1/H2 chosen at handshake-format time (MACs cover the type), a "classified" verify path in the rate limiter, content padding beside `pad_to_x16`, extra timer knobs. One device-side *send boundary* (`Obfuscator::seal`) adds pre-handshake packets, prefixes, header protection and trailers. One *receive boundary* (`Deobfuscator::open`) runs before peer lookup. Phobos is a `UdpTransportFactory` wrapper plus a small handle the device polls to force an initiation after a rebind.

**Tech Stack:** Rust 2024, tokio, zerocopy, `chacha20` (raw keystream for header protection), `rand`/`rand_chacha`.

**Spec:** `docs/superpowers/specs/2026-11-04-amnezia-phobos-design.md`. Read it before any task.

**Status:** executed 2026-11-04 on `feat/amnezia-phobos`. The spec's "Implementation notes" record where the build departed from this plan (zero-copy headroom dropped, window widening on send and receive, receive-side handshake recovery, in-place `set_amnezia`, `PhobosHandle::address_changed`, `tunn_benches` replacing `throughput_benches` as the cost gate).

**References (read-only, never modify):** `~/VibeCode/awgtun` (behaviour plus the tests to port), `~/VibeCode/amneziawg-go` (wire-format authority), https://github.com/Ground-Zerro/Phobos (behaviour authority; (A)GPL, so never copy its code).

## Global Constraints

- Toolchain is pinned by `rust-toolchain.toml` (1.95.0), with workspace `rust-version = "1.95"` and edition 2024.
- **Running tests.** The repo's `.cargo/config.toml` runs tests under `sudo -E`. Use this instead:
  ```bash
  export PATH="$(dirname "$(rustup which cargo)"):$PATH"
  export CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER=env   # on Linux: CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=env
  ```
  Below, `ct` means `cargo test -p gotatun --lib` with these variables set.
- **Features.**
  - New cargo features `amnezia = ["dep:chacha20"]` and `phobos = ["device"]`, both off by default.
  - All new code is `#[cfg(feature = ...)]`-gated. With both features off, upstream code paths compile byte-for-byte unchanged.
- **Dependencies.** The only new dependency is `chacha20` (optional, under `amnezia`). Pick the version that `chacha20poly1305 0.10` already pulls in (check `Cargo.lock`) so no second copy is built.
- **API.** Public API changes are additive only. Do not change the signature of any existing `pub` item. Do not reformat or rename upstream code.
- **Commits.** Commit once per task, with a message prefix `amnezia:` / `phobos:` / `docs:`. End every commit with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **Test data.** Never commit real H/S/J/I values, Phobos keys or server ports. Use synthetic values with the real shape: every key populated, S2 > 64, H ranges millions wide.
- **Validation.** It must be no stricter than amneziawg-go. Enforce only:
  - H ranges must not overlap;
  - `jmin <= jmax` when `jc > 0`;
  - each of `s1..s4 >= 12` when header protection is on;
  - AWG 1.x keys `j1 j2 j3 itime` are rejected.
- **Gates for every task:**
  - `cargo clippy -p gotatun --all-targets --features amnezia,phobos,device -- -D warnings` is clean.
  - `cargo hack check -p gotatun --feature-powerset --depth 2` passes (CI runs the powerset).

## Review Focus

1. **Config swapped at runtime via UAPI while traffic flows.** Peers re-handshake under the new config, per-peer `danger_timer_params` survive, and nothing panics. → Task 9, `uapi_set_amnezia_mid_traffic_rehandshakes`.
2. **Mismatched peers** (AWG client vs plain server, or different H ranges). The handshake simply never completes. Datagrams are dropped silently: no panic, and no log line per packet above `trace`. → Task 8, `awg_vs_plain_never_handshakes` and `awg_mismatched_h_never_handshakes`.
3. **Oversized output.** S1–S4 = 65535 or a huge content padding must yield a dropped packet, never a panic or a datagram over 65535. → Task 6, `seal_refuses_oversized_datagram`; Task 7, `content_padding_never_exceeds_buffer`.
4. **Dual-stack endpoints.** I1–I5, then junk, then the initiation stay in order on every send path, including `force_handshake`. → Task 8, `pre_handshake_order_on_force_handshake`.
5. **Rebind under Phobos.** The embedder's factory rebinds without telling the device. The first datagram after the rebind must be an initiation, and a handshake must be forced. → Task 12, `rebind_gates_until_initiation`.

---

### Task 1: Feature flags, `AmneziaConfig`, validation, UAPI block parse/emit

**Files:**
- Modify: `gotatun/Cargo.toml` (features, optional `chacha20`), `gotatun/src/lib.rs` (add `#[cfg(feature="amnezia")] pub mod amnezia;`)
- Create: `gotatun/src/amnezia/mod.rs`, `gotatun/src/amnezia/config.rs`
- Port from: `~/VibeCode/awgtun/awgtun/src/amnezia.rs` (types and validation at 240-706, 1060-1306, 1380-1863), keeping its tests.

**Interfaces:**
- Produces (all `pub`, re-exported from `gotatun::amnezia`):
  - `HeaderRange { start: u32, end: u32 }` (inclusive), plus `HeaderRanges { init, response, cookie, transport: HeaderRange }`. `Default` is 1/2/3/4. Provides `fn kind_of(&self, v: u32) -> Option<WgPacketType>`.
  - `Padding { s1, s2, s3, s4: u16 }`
  - `Junk { count: u16, min: u16, max: u16 }`
  - `CpsChain` (parsed I-packet), `InitPackets([Option<CpsChain>; 5])`
  - `U32Range { lo: u32, hi: u32 }`
  - `TimingRanges { rekey_after_time, rekey_timeout, reject_after_time, keepalive_timeout: Option<RangeInclusive<Duration>>, max_handshake_attempts: Option<RangeInclusive<u32>> }`
  - `#[non_exhaustive] AmneziaConfig { headers, padding, junk, init_packets, header_protection_key: Option<[u8; 32]>, content_padding: Option<U32Range>, timings, random_trailers: bool, disable_cookies: bool }` with `Default` meaning plain WireGuard.
  - `AmneziaConfig::validate(&self) -> Result<(), ConfigError>`
  - `AmneziaConfig::is_plain_wireguard(&self) -> bool`
  - `AmneziaConfig::transport_overhead(&self) -> usize` (returns `s4`)
  - `AmneziaConfig::apply_uapi_line(&mut self, key: &str, value: &str) -> Result<bool, ConfigError>` (returns `false` for unknown keys)
  - `AmneziaConfig::to_uapi_lines(&self) -> Vec<(String, String)>` (non-defaults only)
  - `ConfigError` (thiserror enum)
- UAPI keys: `jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 i1 i2 i3 i4 i5 header_protection_key content_padding_addition rekey_after_time rekey_timeout reject_after_time keepalive_timeout max_handshake_attempts random_trailers disable_cookies`.
  - `header_protection_key` is 64 hex characters; all zeros means off.
  - Booleans accept `0/1 t/f true/false on/off`, case-insensitive.
  - Ranges are written `a` or `a-b`.
- `persistent_keepalive_interval` is **not** here; it is a peer key (Task 10).

- [x] **Step 1: Port the config tests**

Port the config, validation and round-trip tests from awgtun's `amnezia.rs` test module into `amnezia/config.rs`. Rename types to match the new names. They must include:
`h_ranges_must_not_overlap`, `h_values_1_to_4_allowed`, `jmin_gt_jmax_rejected_only_when_jc_positive`, `header_protection_requires_s_ge_12`, `s_values_above_255_accepted` (s1 = 1000), `awg1_keys_rejected` (`j1`, `itime` give an error), `i_packet_gaps_allowed` (only `i3` set is valid), `uapi_round_trip` (parse → `to_uapi_lines` → parse is equal), `default_emits_nothing`, `zero_hp_key_means_off`, `full_u32_h_range_ok` (`0-4294967295` for h4 alone is valid).

- [x] **Step 2: Confirm the tests fail to compile**

Run: `ct --features amnezia amnezia::config`. Expected: compile errors, because the types do not exist yet.

- [x] **Step 3: Implement the types**

Implement the types in `amnezia/config.rs`, porting awgtun's parsing and validation and fitting them to the interfaces above. `CpsChain` parsing lives in Task 2. For now `i1..i5` store the raw string, and Task 2 replaces that with the parsed type.

- [x] **Step 4: Confirm the tests pass**

Run: `ct --features amnezia amnezia::config`. Expected: all pass.

- [x] **Step 5: Run the gates, then commit**

Run the clippy and powerset gates, then commit with the message `amnezia: config types, validation and UAPI key parsing`.

### Task 2: Primitives — RNG, CPS, junk, header protection, trailer length

**Files:**
- Create: `gotatun/src/amnezia/{rng.rs, cps.rs, junk.rs, header_protection.rs}`
- Port from: awgtun `amnezia.rs:74-236` (FastRandom), `756-1058` (CPS), `623-706` (junk), `1312-1372` (HeaderProtection), `1130-1139` (`random_trailer_len`).

**Interfaces:**
- `pub(crate) trait RandomSource { fn fill(&mut self, buf: &mut [u8]); fn range_u32(&mut self, lo: u32, hi_inclusive: u32) -> u32; }`, implemented by:
  - `FastRandom`: per-thread ChaCha with a `pthread_atfork` generation reset on unix;
  - `OsRandom`.
- `CpsChain::parse(&str) -> Result<CpsChain, ConfigError>` and `CpsChain::render(&self, rng, out: &mut Vec<u8>)`. Tags: `<b 0xHEX> <t> <r N> <rc N> <rd N> <d> <ds> <dz N>`. `d`, `ds` and `dz` emit nothing. `<t>` is a 4-byte big-endian Unix time. N is at most 65535.
- `Junk::render_into(&self, rng, out: &mut Vec<Vec<u8>>)`: produces `count` datagrams with sizes drawn from **half-open** `[min, max)`. When `min == max`, every datagram has size `min`.
- `HeaderProtection::new(key: [u8; 32])`, `fn mask(&self, nonce12: &[u8; 12]) -> [u8; 148]` (ChaCha20, block counter 0), and `fn apply(&self, prefix: &[u8], msg: &mut [u8], protected_len: usize)`. Protected spans: init 148, response 92, cookie 64, transport 16.
- `pub(crate) fn random_trailer_len(rng, window: usize, size: usize) -> usize`: uniform in half-open `[0, window - size)`, and 0 if `size >= window`.

- [x] **Step 1: Port the tests**

Port awgtun's tests for these items. They must include:
- `cps_tags_parse_and_render_lengths`
- `cps_rejects_over_65535`
- `junk_sizes_half_open`
- `header_protection_known_answer` (copy awgtun's ChaCha20 KAT vector)
- `trailer_len_half_open`
- `fast_random_regenerates_after_fork` (unix only)

- [x] **Step 2: Confirm the tests fail**

Run: `ct --features amnezia amnezia::`. Expected: FAIL.

- [x] **Step 3: Implement**

Implement, and switch `AmneziaConfig.init_packets` to `CpsChain`.

- [x] **Step 4: Confirm the tests pass, then commit**

Run: `ct --features amnezia amnezia::`. Expected: PASS. Commit with the message `amnezia: RNG, CPS chains, junk, header protection`.

### Task 3: Receive boundary — `Deobfuscator`

**Files:**
- Create: `gotatun/src/amnezia/classify.rs`
- Port from: awgtun `noise/mod.rs:173-343` (`PacketClassifier`), `device/mod.rs:777-813`.

**Interfaces:**
- `pub(crate) struct Deobfuscator { /* Arc<AmneziaConfig>, Option<HeaderProtection> */ }`, created with `Deobfuscator::new(cfg: Arc<AmneziaConfig>)`.
- `pub(crate) fn open(&self, packet: Packet) -> Option<(Packet, WgPacketType)>`. In order, it:
  1. classifies the datagram;
  2. strips the S-prefix (`buf_mut().advance`);
  3. removes header protection, reusing the mask derived during classification;
  4. trims a trailer down to the message's fixed size.

  It **leaves the H value in the type field** so that MACs still verify. It returns `None` for junk, I-packets and garbage.
- Classification rules. Each one needs a test:
  - Without trailers, a handshake type matches only if `len == s_x + fixed size` **and** the H value read at offset `s_x` is in range `x`. Transport needs `len >= s4 + 32` and an H4 value in range.
  - With `random_trailers`, try transport **first**, and relax the handshake checks to `>=`.
  - Header protection derives the 16-byte mask once per candidate from `prefix[0..12]`.

- [x] **Step 1: Write the tests**

Write these tests in `classify.rs`:
- `open_plain_cfg_is_identity`
- `open_strips_prefix_each_kind`
- `open_unprotects_header`
- `open_trims_trailer_before_size_check`
- `transport_classified_before_handshake_with_trailers` (the 50k-sample statistical test from awgtun `noise/mod.rs:3582+`; fewer than 0.01% stolen)
- `junk_and_cps_are_dropped`
- `classified_mask_reused` (port `classified_header_mask_matches_a_second_apply`)

Build the input packets with a test-only helper `seal_for_test(cfg, kind, msg) -> Vec<u8>` defined in this file. Task 6 later replaces it with `Obfuscator`, and these tests are then re-pointed at the real sender.

- [x] **Step 2: Confirm the tests fail, implement, confirm they pass**

Run `ct --features amnezia amnezia::classify` before and after implementing. Expected: FAIL first, then PASS.

- [x] **Step 3: Commit**

Commit with the message `amnezia: receive-side classifier`.

### Task 4: Core hooks — wire type on packets, classified verify

**Files:**
- Modify: `gotatun/src/packet/wg.rs`, which adds items next to the existing ones and changes nothing existing. It gets:
  - `#[cfg(feature="amnezia")] pub(crate) fn set_wire_type(&mut self, v: u32)` on `WgHandshakeInit`, `WgHandshakeResp`, `WgCookieReply` and `WgDataHeader`. It writes 4 bytes little-endian over `packet_type` and the reserved bytes.
  - `#[cfg(feature="amnezia")] pub(crate) fn try_into_wg_as(self, kind: WgPacketType) -> eyre::Result<WgKind>` on `Packet`. It applies the same size checks as `try_into_wg` (`packet/wg.rs:504`) but does not check the type byte.
- Modify: `gotatun/src/noise/rate_limiter.rs`. Add `#[cfg(feature="amnezia")] pub(crate) fn verify_classified(&self, src: SocketAddr, packet: Packet, kind: WgPacketType, disable_cookies: bool) -> Result<WgKind, TunnResult>`. It:
  - uses `try_into_wg_as`;
  - verifies MACs over the raw bytes, which still carry H;
  - skips the whole under-load path, MAC2 check included, when `disable_cookies` is set;
  - on success, rewrites the type field back to the standard 1/2/3/4, so downstream code sees normal packets.
  - The under-load cookie reply it returns has the standard type; the send boundary (Task 6) applies H3.

**Interfaces:** Tasks 3 and 9 use these as `deobfuscator.open(p)` → `rate_limiter.verify_classified(addr, p, kind, cfg.disable_cookies)`.

- [x] **Step 1: Write the tests**

Write these tests in `rate_limiter.rs`:
- `verify_classified_accepts_mac_over_h_value`: build an init, set the wire type to 123456 *before* the MACs (recompute them with a test helper), and verify it with kind `HandshakeInit`. Expect `Ok`, and the type byte back to `1`.
- `verify_classified_rejects_mac_mismatch_after_retype`: the MACs were computed over type 1 but the wire carries H. Expect `Err(InvalidMac)`.
- `disable_cookies_skips_mac2_under_load`

- [x] **Step 2: Confirm fail, implement, confirm pass**

Run `ct --features amnezia rate_limiter`: FAIL before, then PASS. Also run `ct` with no features, which must pass unchanged.

- [x] **Step 3: Commit**

Commit with the message `amnezia: wire-type hooks and classified MAC verification`.

### Task 5: H1/H2 at handshake-format time

**Files:**
- Modify: `gotatun/src/noise/handshake.rs`.
  - Add the field `#[cfg(feature="amnezia")] wire_types: Option<WireTypes>` to `Handshake`.
  - In `format_handshake_initiation` (`:761`) and `format_handshake_response` (`:842`), call `packet.set_wire_type(wt.init())` or `wt.resp()` **immediately before** `init_mac1_and_mac2`. This is one line in each function.
- Modify: `gotatun/src/noise/mod.rs`. Add `#[cfg(feature="amnezia")] pub(crate) fn set_amnezia(&mut self, state: Option<AmneziaTunnState>)` on `Tunn`. It sets the handshake's `wire_types` and stores the state for Task 7.
- Create: `gotatun/src/amnezia/tunn_state.rs`. It defines:
  - `pub(crate) struct WireTypes { ranges: HeaderRanges }` with `fn init(&self) -> u32` and `fn resp(&self) -> u32`, each drawing from its range with `FastRandom`;
  - `pub(crate) struct AmneziaTunnState { cfg: Arc<AmneziaConfig>, udp_window: usize /* starts at 500 */, mtu: ... }`.

- [x] **Step 1: Write the tests**

Write these tests in the `noise/mod.rs` test module, using two `Tunn`s that share one config and both pass through the Task 3 + Task 4 receive path:
- `awg_handshake_completes_with_h_ranges`
- `init_type_field_in_h1_range`
- `plain_tunn_rejects_awg_init` (negative control)

- [x] **Step 2: Check the handshake timestamp epoch**

Check that gotatun's TAI64N base matches kernel WireGuard, as awgtun's fix at `handshake.rs:191` (0.12.0, Unix + 10) does. If it differs, add `timestamp_epoch_matches_kernel` and fix it in its own commit. If it already matches, note that in the commit message.

- [x] **Step 3: Confirm fail, implement, confirm pass, commit**

Run `ct --features amnezia noise::`: FAIL before, then PASS. Commit with the message `amnezia: H1/H2 chosen before MACs`.

### Task 6: Send boundary — `Obfuscator::seal`

**Files:**
- Create: `gotatun/src/amnezia/seal.rs`
- Port from: awgtun `noise/mod.rs:761-883` (transport prefix, protection, misclassification redraw), `1207-1290` (pre-handshake queue), `971-993` and `1015-1060` (cookie and response padding).

**Interfaces:**
- `pub(crate) struct Obfuscator { cfg: Arc<AmneziaConfig>, hp: Option<HeaderProtection> }`
- `pub(crate) fn seal(&self, packet: WgKind, window: &mut usize, out: &mut Vec<Packet>) -> Result<(), SealError>`. It pushes, in this order:
  - for `HandshakeInit`: rendered I1..I5 (skipping unset ones), then Jc junk datagrams;
  - then the message itself, built like this:
    1. write H3 or H4 for cookie or transport (init and response already carry H from Task 5);
    2. prepend S1–S4 random bytes;
    3. apply header protection;
    4. append the trailer for init, response and cookie when `random_trailers` is on.
  - For transport, it redraws the S4 prefix up to 8 times while `peer_would_misclassify` is true. Port awgtun's `844-883`: the unpatched Go order is init → response → cookie, using `==` / `>` tests.
  - It updates `*window = max(*window, datagram_len)`.
  - It never copies the transport payload: the data packet is built with S4 headroom and the prefix is filled in place. This task adds that headroom path to `gotatun/src/noise/session.rs`: `#[cfg(feature="amnezia")] pub(super) fn format_packet_data_with_headroom(&self, packet: Packet, headroom: usize) -> Result<(BytesMut /*headroom*/, Packet<WgData>), Packet>`.
    - It allocates `headroom + OVERHEAD + len` once and uses `BytesMut::split_to(headroom)`, so `seal` can rejoin the two parts zero-copy with `unsplit`.
    - The existing `format_packet_data` becomes a one-line call into it with `headroom = 0` when the feature is on. Its body must not otherwise change.
    - Test: `headroom_path_matches_plain_path_bytes` (headroom 0 gives the same ciphertext as upstream).
- `SealError::TooLarge` when the datagram would exceed 65535.
- Re-point Task 3's tests to use `seal` instead of `seal_for_test`, then delete `seal_for_test`.

- [x] **Step 1: Write the tests**

Write these tests in `seal.rs`:
- `seal_then_open_round_trips_every_kind` (combinations of trailers on/off and header protection on/off)
- `init_preceded_by_cps_then_junk`
- `cookie_reply_gets_trailer` (spec item 13)
- `keepalive_gets_s4_prefix` (spec item 14)
- `transport_redraw_avoids_unpatched_misclassification` (port `awg31_peer_misclassification`)
- `seal_refuses_oversized_datagram` (s1 = 65535)
- `go_keystream_differential` (port `awg3_wire_format_matches_go_keystream_sequence`)

- [x] **Step 2: Confirm fail, implement, confirm pass, commit**

Run `ct --features amnezia amnezia::`: FAIL before, then PASS. Commit with the message `amnezia: send-side obfuscator`.

### Task 7: Content padding, UDP window, keepalive detection

**Files:**
- Modify: `gotatun/src/noise/mod.rs`, right after the `pad_to_x16` call site (`:509` helper). Append content-padding zero bytes from `AmneziaTunnState::content_padding(len, mtu) -> usize`. The amount is `min(pick, window - datagram, mtu - datagram, buffer - datagram)`, where `datagram = s4 + 32 + payload`. When `random_trailers` is on and `content_padding` is unset, widen the padding to `random_trailer_len`.
- Modify: `gotatun/src/noise/mod.rs` receive. A decrypted payload whose first byte is 0 is a keepalive. A non-IP payload still counts as data received.
- The window is observed on send (in `seal`) and on receive (Task 9), starts at 500, and is reset on endpoint change.

- [x] **Step 1: Write the tests**

Write these tests:
- `content_padding_bounded_by_window_mtu_buffer`
- `content_padding_never_exceeds_buffer`
- `window_widens_unconditionally`
- `padded_keepalive_detected_by_zero_byte`
- `trailers_widen_transport_padding_only_when_unset`

- [x] **Step 2: Confirm fail, implement, confirm pass**

Run `ct --features amnezia`: FAIL before, then PASS. Also run `ct` with no features: PASS.

- [x] **Step 3: Commit**

Commit with the message `amnezia: content padding and UDP window`.

### Task 8: Timers

**Files:**
- Modify: `gotatun/src/noise/timers.rs`. Add `#[cfg(feature="amnezia")] pub(crate) struct TimerExtras { reject_after_time: Option<RangeInclusive<Duration>>, max_handshake_attempts: Option<RangeInclusive<u32>>, persistent_keepalive: Option<RangeInclusive<Duration>> }`, stored on `Timers`.
  - With `max_handshake_attempts` set, the give-up check at `:355` uses `pick(rekey_timeout) * attempts` instead of `REKEY_ATTEMPT_TIME`.
  - Key expiry uses `Hi(reject_after_time)`.
  - A persistent-keepalive range is re-drawn each time it fires.
  - **`TimerParams` is not changed**, so its public API stays intact.
- Create: `gotatun/src/amnezia/timers.rs` with `pub(crate) fn timer_params_from(cfg: &TimingRanges) -> TimerParams`. It maps:
  - `rekey_timeout` → `rekey_timeout`, keeping upstream's `MAX_JITTER` (333 ms, against the reference's 0–334 ms; the 1 ms difference is accepted so no upstream constant changes);
  - `keepalive_timeout` → `keepalive_timeout`;
  - `new_handshake_timeout` → `(Hi(ka) + Lo(rekey))..=(Hi(ka) + Hi(rekey) + MAX_JITTER)`;
  - `rekey_after_time` → `rekey_after_time`.

  Unset ranges fall back to the defaults.

- [x] **Step 1: Write the tests**

Write these tests in `timers.rs` (`mock_instant` tests are gated the same way as the existing ones):
- `max_attempts_bounds_retries`
- `reject_after_uses_hi`
- `persistent_keepalive_range_redrawn`
- `unset_ranges_equal_upstream_defaults`

- [x] **Step 2: Confirm fail, implement, confirm pass, commit**

Run `ct --features amnezia,mock_instant timers`: FAIL before, then PASS. Commit with the message `amnezia: timing ranges`.

### Task 9: Device integration

**Files:**
- Modify: `gotatun/src/device/mod.rs`.
  - `DeviceState` gets `#[cfg(feature="amnezia")] amnezia: Option<Arc<AmneziaConfig>>`, plus a cached `Obfuscator` and `Deobfuscator`.
  - **Receive** (`handle_incoming`, `:688-692`): when Amnezia is configured, run `deobfuscator.open` → `verify_classified`; otherwise run the unchanged `verify_packet`. After the peer is found, observe the datagram length into that peer's window.
  - **Send:** add one helper, `async fn send_wg(udp, obfs: Option<&Obfuscator>, peer_window: Option<&mut usize>, packet: WgKind, addr) -> io::Result<()>`. It replaces the bare `udp.send_to(packet.into(), addr)` at each WG send site:
    - `:653` (timers)
    - `:694-700` (under-load cookie reply)
    - `:761` (responses and queued packets)
    - `:907` (outgoing data)
    - `:388` (`force_handshake`)
  - DAITA decoys go through the same helper.
  - `create_peer` (`:472`) and `PeerState`: call `tunnel.set_amnezia(...)`. The peer's `TimerParams` come from `danger_timer_params` if set, otherwise from `timer_params_from(&cfg.timings)`.
  - On an endpoint change, reset the peer's window to 500.
- Modify: `gotatun/src/device/builder.rs`. Add `#[cfg(feature="amnezia")] pub fn with_amnezia(self, cfg: AmneziaConfig) -> Self`. `build()` validates the config and returns the existing error type on failure.
- Modify: `gotatun/src/device/configure.rs`. Add `DeviceWrite::set_amnezia(&mut self, cfg: Option<AmneziaConfig>) -> Result<(), ConfigError>` and `DeviceRead::amnezia(&self) -> Option<AmneziaConfig>`. A set validates the config, swaps it, and rebuilds every peer's `Tunn` while keeping keys, endpoints and per-peer timer params.
- Modify: `gotatun/src/device/tests/mock.rs`. Add `pub async fn device_pair_with(f: impl Fn(DeviceBuilder<..>) -> DeviceBuilder<..>) -> (MockDevice, MockDevice, MockEavesdropper)`. The existing `device_pair()` becomes `device_pair_with(|b| b)`.

- [x] **Step 1: Write the tests**

Write these tests in `device/tests.rs`, using a synthetic config with every key populated:
- `awg20_ping_both_directions`
- `awg30_ping_both_directions`
- `awg31_ping_both_directions`
- `eavesdropper_sees_no_standard_types` (no datagram starts with `01 00 00 00` through `04 00 00 00`)
- `awg_vs_plain_never_handshakes`
- `awg_mismatched_h_never_handshakes`
- `pre_handshake_order_on_force_handshake` (the eavesdropper sees I1..In, then Jc junk, then the init, on both v4 and v6 pairs)
- `cookie_under_load_has_trailer_and_handshake_completes`
- `uapi_set_amnezia_mid_traffic_rehandshakes` (uses `DeviceWrite::set_amnezia` here; Task 10 adds the UAPI variant)
- `danger_timer_params_survive_set_amnezia`

- [x] **Step 2: Confirm fail, implement, confirm pass**

Run `ct --features amnezia,device device::tests`: FAIL before, then PASS. Also run `ct --features device` (no amnezia): PASS.

- [x] **Step 3: Commit**

Commit with the message `amnezia: device send/receive boundaries and config API`.

### Task 10: UAPI and CLI

**Files:**
- Modify: `gotatun/src/device/uapi/command.rs`.
  - In `impl FromStr for Set` (`:570-595`), delegate unknown keys to `#[cfg(feature="amnezia")] try_process_amnezia_line`, mirroring `try_process_daita_line` (`:680`). They accumulate into `Set.amnezia: Option<Vec<(String, String)>>`.
  - Peer key `persistent_keepalive_interval` accepts `a` or `a-b` under the feature, stored as a new field `SetPeer.persistent_keepalive_range`.
  - `GetResponse` emits `to_uapi_lines()` and the per-peer range.
- Modify: `gotatun/src/device/uapi/mod.rs` `on_api_set` (`:570-597`). Merge incrementally: take the current config, apply the lines, validate, and `set_amnezia`. If validation fails, nothing changes and an errno is returned.
- Modify: `gotatun/src/device/peer.rs`. Add `#[cfg(feature="amnezia")] pub keepalive_range: Option<RangeInclusive<u16>>` (`Peer` is `#[non_exhaustive]`).
- Modify: `gotatun-cli/Cargo.toml`. Add an `amnezia` feature that is forwarded to the library and enabled by default for the CLI.
- Modify: `UAPI.md` (document every key, with the amneziawg-go names), `README.md` (a "UAPI extensions" line).

- [x] **Step 1: Write the tests**

Write these tests in `device/uapi/mod.rs`:
- `uapi_amnezia_set_get_round_trip`
- `uapi_incremental_merge` (set `jc` alone, then `s1` alone; both stay set)
- `uapi_invalid_set_leaves_config_unchanged`
- `uapi_peer_keepalive_range`
- `uapi_awg1_key_errors`

- [x] **Step 2: Confirm fail, implement, confirm pass**

Run `ct --features amnezia,device uapi`: FAIL before, then PASS.

- [x] **Step 3: Commit**

Commit with the message `amnezia: UAPI keys and docs`.

### Task 11: Phobos codec

**Files:**
- First, diff the Phobos reference from commit `22aedef` to HEAD:
  ```bash
  git clone https://github.com/Ground-Zerro/Phobos /private/tmp/claude-502/phobos-ref
  git -C /private/tmp/claude-502/phobos-ref log --oneline 22aedef..HEAD
  ```
  Record any wire-relevant change in the commit message, and port it from the *behaviour*, never the code. If something changes the wire format, stop and report it.
- Create: `gotatun/src/phobos/{mod.rs, codec.rs, test_vectors.rs}`, and add `#[cfg(feature="phobos")] pub mod phobos;` in `lib.rs`.
- Port from: awgtun `phobos/mod.rs` (929 lines), `test_vectors.rs`, `tests.rs`.

**Interfaces** (same as awgtun's):
- `PhobosConfig { key: Vec<u8> /*1..=255*/, masking: Masking, max_dummy: u16 /*0..=1024, default 4*/, obfuscate_bytes: u32, media: MediaParams }` with `set(name, value) -> Result<bool, _>` and a `Debug` impl that redacts the key.
- `Masking::{None, Stun, Media, Auto, Tls}`, with `overhead()`.
- `PhobosCodec::new(cfg)`:
  - `wrap(&mut self, datagram: &[u8], out: &mut Vec<u8>) -> Result<Option<[u8; 28]>, WrapError>`
  - `unwrap<'a>(&mut self, buf: &'a mut [u8], from: SocketAddr) -> Unwrapped<'a>`
  - `binding_request()`, `control_interval()`, `max_message_len()`

- [x] **Step 1: Port the tests and run them**

Port all 32 awgtun tests, which include the reference conformance vectors. Run `ct --features phobos phobos::`: expect FAIL, then implement, then expect PASS.

- [x] **Step 2: Commit**

Commit with the message `phobos: client codec`.

### Task 12: Phobos transport, rebind gate, device hook

**Files:**
- Create: `gotatun/src/phobos/transport.rs`:
  - `pub struct PhobosUdpFactory<F> { .. }` with `pub fn new(inner: F, cfg: PhobosConfig) -> (Self, PhobosHandle)`.
  - It implements `UdpTransportFactory` with `Send` and `Recv` wrappers:
    - **Send:** `wrap`. Send the Binding Request first when one is returned.
    - **Receive:** `unwrap`. `Reply` is answered via the send half, and `Drop` is skipped.
    - A spawned task sends the periodic Binding Request, but only while the last handshake response seen is less than 180 s old.
  - **Rebind gate:** every `bind()` bumps a generation number. Until a `HandshakeInit` (first byte 1) has been sent successfully on the current generation, other outgoing datagrams are dropped and `PhobosHandle` raises "needs initiation".
- `pub struct PhobosHandle(Arc<..>)` with `fn take_initiation_request(&self) -> bool`.
- Modify: `gotatun/src/device/builder.rs`:
  - `#[cfg(feature="phobos")] pub fn with_phobos_handle(self, h: PhobosHandle) -> Self`, for embedders that wrap their own factory.
  - `pub fn with_phobos(self, cfg: PhobosConfig) -> Self`, which wraps the default UDP factory and registers the handle.
  - `build()` errors when both Amnezia and Phobos are configured.
- Modify: `gotatun/src/device/mod.rs` `handle_timers` (`:610-664`). When the handle reports `take_initiation_request()`, force an initiation for every peer, through the Task 9 `send_wg` path.

- [x] **Step 1: Write the tests**

Write these tests in `phobos/transport.rs` and `device/tests.rs`:
- `phobos_ping_through_reference_vectors_peer`: a test peer decodes with `PhobosCodec` server-side logic, written in the test from the spec.
- `rebind_gates_until_initiation`: an inner factory that rebinds on demand; after the rebind, the first datagram on the wire is an init and the data before it is dropped.
- `binding_request_stops_after_180s_without_handshake` (`mock_instant`)
- `amnezia_plus_phobos_build_errors`

- [x] **Step 2: Confirm fail, implement, confirm pass, commit**

Run `ct --features phobos,device,amnezia`: FAIL before, then PASS. Commit with the message `phobos: UDP transport wrapper and rebind handling`.

### Task 13: Benchmarks, docs, final gates

**Files:**
- Create: `docs/amnezia.md`. Cover:
  - the wire format by version;
  - the config keys;
  - the MTU guidance: lower the inner MTU by `transport_overhead()` (and by `Masking::overhead()` for Phobos);
  - deliberate differences from Go;
  - the two awgtun bugs fixed here.
- Modify: `README.md` (feature list), `CHANGELOG.md` (Unreleased entry).

- [x] **Step 1: Throughput benchmarks**

Run `cargo bench -p gotatun --bench throughput_benches` twice: with `--features device`, and with `--features device,amnezia` but no config. Expected: the difference is within criterion's noise, under 2%. Record both numbers in the commit message.

- [x] **Step 2: Full gates**

Run:
- `ct --features amnezia,phobos,device`
- `ct` (no features)
- clippy
- `cargo hack check --feature-powerset --depth 2`
- `typos`

Expected: all clean.

- [x] **Step 3: Live-server smoke test (done by the owner)**

Hand over a `gotatun-cli` command line and a UAPI block template based on `~/VibeCode/awgtun/.claude/skills/amnezia-dev/references/live-server-test.md`.

- [x] **Step 4: Commit**

Commit with the message `docs: AmneziaWG and Phobos`.
