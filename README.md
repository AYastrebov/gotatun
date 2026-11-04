# GotaTun

A userspace [WireGuard<sup>®</sup>](https://www.wireguard.com/) implementation, and a fork of [BoringTun](https://github.com/cloudflare/boringtun).

This repository is a fork of [Mullvad's GotaTun](https://github.com/mullvad/gotatun) that adds
AmneziaWG 2.0/3.0/3.1 and the client side of Phobos as optional features, with the upstream code
paths left unchanged when those features are off. See [Obfuscation](#obfuscation) below and
[docs/amnezia.md](docs/amnezia.md).

## License

All source code in this repository is subject to the terms of the Mozilla Public License, version 2.0 unless stated otherwise. A copy of this license can be found in the file "LICENSE" or at <https://www.mozilla.org/MPL/2.0/>.

Contributions made prior to March 5, 2026 are licensed under the old BSD 3-clause license. A copy of this license can be found in the file "LICENSE-CLOUDFLARE".

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the MPL-2.0 License, shall be licensed as above, without any additional terms or conditions.

## Building

- Library only: `cargo build --lib --no-default-features --release [--target $(TARGET_TRIPLE)]`
  (add `--features amnezia` and/or `--features phobos` for the obfuscation features; both are
  off by default in the library)
- Executable: `cargo build --bin gotatun --release [--target $(TARGET_TRIPLE)]`
  (the executable enables `amnezia` by default)

### Installation

By default the executable is placed in the `./target/release` folder. You can copy it to a desired location manually, or install it using `cargo install --bin gotatun --path .`.

### Nix

To build the executable, simply run `nix build .#gotatun`. The final binary will be located in `result/bin/gotatun`.

## Running

As per the specification, to start a tunnel use:

`gotatun [-f/--foreground] INTERFACE-NAME`

The tunnel can then be configured using [wg](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg.8), as a regular WireGuard tunnel, or any other tool.
AmneziaWG settings are set over the same socket with the amneziawg-go key names
(see [UAPI.md](./UAPI.md)), so `awg` from
[amneziawg-tools](https://github.com/amnezia-vpn/amneziawg-tools) works too;
[docs/amnezia.md](docs/amnezia.md) has a step-by-step test against a live AmneziaWG server.

It is also possible to use with [wg-quick](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg-quick.8) by setting the environment variable `WG_QUICK_USERSPACE_IMPLEMENTATION` to `gotatun`. For example:

`sudo WG_QUICK_USERSPACE_IMPLEMENTATION=gotatun WG_SUDO=1 wg-quick up CONFIGURATION`

*Please note that `wg-quick` will ignore `WG_QUICK_USERSPACE_IMPLEMENTATION` on Linux if you have the wireguard kernel module installed.*

## Testing

Testing this project has a few requirements:

- `sudo`: required to create tunnels. When you run `cargo test` you'll be prompted for your password.
- Docker: you can install it [here](https://www.docker.com/get-started). If you are on Ubuntu/Debian you can run `apt-get install docker.io`.

`.cargo/config.toml` runs every test binary under `sudo -E`. The library's unit tests, including
the AmneziaWG and Phobos device tests, use in-memory transports and do not need root; to run them
without a password prompt, override the runner for your target, for example
`CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER=env cargo test -p gotatun --lib --features amnezia,phobos,device`.

CI tests three feature sets: default, `--no-default-features --features ring`, and
`--all-features`. Because the `gotatun` executable enables `amnezia` by default, the default row
builds the library with `amnezia` compiled in; the feature-off device path is covered by the
`ring` row, and Phobos only by `--all-features`.

## Supported platforms

Target triple                 |Binary|Library|
------------------------------|:----:|------|
x86_64-unknown-linux-gnu      |  ✓   | ✓    |
aarch64-unknown-linux-gnu     |  ✓   | ✓    |
riscv64gc-unknown-linux-gnu   |  ✓   | ✓    |
aarch64-apple-darwin          |  ✓   | ✓    |
x86_64-pc-windows-msvc        |  ✓   | ✓    |
x86_64-pc-windows-gnullvm     |  ✓   | ✓    |
aarch64-pc-windows-msvc       |  ✓   | ✓    |
aarch64-pc-windows-gnullvm    |  ✓   | ✓    |
x86_64-linux-android          |      | ✓    |
aarch64-linux-android         |      | ✓    |
aarch64-apple-ios             |      | ✓    |

<sub>Other targets may work, but we only test for these</sub>

### Linux

`x86-64`, and `aarch64` architectures are supported. The behaviour should be identical to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/), with the following difference:

`gotatun` will drop privileges when started. When privileges are dropped it is not possible to set `fwmark`. If `fwmark` is required, such as when using `wg-quick`, run with `--disable-drop-privileges` or set the environment variable `WG_SUDO=1`.

You will need to give the executable the `CAP_NET_ADMIN` capability using: `sudo setcap cap_net_admin+epi gotatun`. sudo is not needed.

### macOS

The behaviour is similar to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/). Specifically the interface name must be `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select the lowest available. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

## Obfuscation

Two optional features, both off by default in the library (the `gotatun` executable enables
`amnezia`):

- `amnezia`: AmneziaWG 2.0, 3.0 and 3.1, interoperable with
  [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) and the AmneziaWG kernel module,
  in both roles. One config per device, set with `DeviceBuilder::with_amnezia`, changed at run
  time with `DeviceWrite::set_amnezia` (the sockets are kept), or over UAPI.
- `phobos` (implies `device`): the client side of
  [Phobos](https://github.com/Ground-Zerro/Phobos) UDP obfuscation, as a wrapper around any
  `UdpTransportFactory`. Plain WireGuard only; a device refuses to build with both features
  configured. Embedders whose local address can change without a rebind must keep the
  `PhobosHandle` and call `address_changed()`.

With `amnezia` compiled in but unconfigured, the `Tunn` hot path measures the same as without it
(`cargo bench -p gotatun --bench tunn_benches`). One change applies to plain WireGuard in every
build: the handshake timestamp epoch now matches kernel WireGuard (upstream's ran 27 s ahead).
See [docs/amnezia.md](docs/amnezia.md) for the wire format, config keys, MTU guidance,
the differences from amneziawg-go, known limitations, and notes for rebasing on upstream.

## UAPI extensions

See [UAPI](./UAPI.md) for extensions to the `wg` configuration protocol, including the
AmneziaWG keys (`--features amnezia`, on by default for `gotatun-cli`).

---

## Audits

Independent security audits have been conducted on the project.
See the [audit](./audits/README.md) directory.

---
<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld. GotaTun is not sponsored or endorsed by Jason A. Donenfeld.</sub></sub></sub></sub>
