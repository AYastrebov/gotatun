In addition to the standard UAPI [configuration protocol], GotaTun includes some non-standard
extensions when some features are enabled.

[configuration protocol]: https://www.wireguard.com/xplatform/#configuration-protocol

# DAITA - Defence Against AI-Guided Traffic Analysis

If GotaTun is built with `--features daita-uapi`, the following keys are available when adding or
modifying a peer:

* `daita_enable`: Set to `1` to enable or replace existing settings, or `0` to disable DAITA.
* `daita_machine`: A base64-encoded [Maybenot] machine.
* `daita_max_delayed_packets`: Maximum number of packets that may be delayed at any time.
* `daita_min_delay_capacity`: Minimum number of free slots in the delay queue to continue
  delaying packets.
* `daita_max_decoy_frac`: Maximum fraction of decoy packets in `[0, 1]`.
* `daita_max_delay_frac`: Maximum fraction of delayed packets in `[0, 1]`.

In addition to the keys above, the following ones are available when retrieving a peer (`get=1`):

* `daita_rx_padding_bytes`: Total padded bytes in received data packets from the previously added peer due to constant-size padding.
* `daita_tx_padding_bytes`: Total padded bytes in sent data packets to the previously added peer due to constant-size padding.
* `daita_rx_decoy_packet_bytes`: Total bytes of decoy packets received from the previously added peer.
* `daita_tx_decoy_packet_bytes`: Total bytes of decoy packets sent to the previously added peer.

[Maybenot]: https://docs.rs/maybenot/latest/maybenot/struct.Machine.html

# AmneziaWG

If GotaTun is built with `--features amnezia` (on by default for `gotatun-cli`), the following
keys are accepted in `set=1` and printed by `get=1`. Names and formats follow
[amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go). A `set` merges into the device's
current settings: keys that are not mentioned keep their value, and setting a key to its default
(`0`, empty) clears it. The merged result is validated first; if it is invalid nothing is
changed and `errno` is non-zero. `get` prints only settings that differ from the defaults.
Changing settings swaps them in place (sockets are not rebound) and every peer handshakes again.

Device keys (in `set`, before the first `public_key`):

* `jc`, `jmin`, `jmax`: Number of junk packets sent before a handshake, and their minimum and
  maximum size. `jmin <= jmax` is required when `jc > 0`.
* `s1`, `s2`, `s3`, `s4`: Bytes of random padding prepended to handshake initiations, responses,
  cookie replies and transport packets.
* `h1`, `h2`, `h3`, `h4`: Message-type header values for initiation, response, cookie reply and
  transport. Either a number or a range `lo-hi`. The ranges must not overlap.
* `i1` .. `i5`: Custom signature packets sent before a handshake, written as a chain of tags, e.g.
  `<b 0xc0ffee><r 24><t>`. An empty value clears the packet.
* `header_protection_key`: 32-byte key as 64 hex characters that enables header protection. When set,
  `s1` .. `s4` must each be at least 12.
* `content_padding_addition`: Range `lo-hi` of random bytes added to the content of data packets.
* `rekey_after_time`, `rekey_timeout`, `reject_after_time`, `keepalive_timeout`: Timer deadlines
  as a number or a range `lo-hi` in seconds, drawn at random from the range.
* `max_handshake_attempts`: Number or range `lo-hi` of handshake retransmits before giving up.
* `random_trailers`, `disable_cookies`: `true` or `false`.

Peer keys:

* `persistent_keepalive_interval`: Besides the usual `seconds`, accepts a range `a-b`; the
  interval is drawn again from the range each time a keepalive is sent. `0` disables. `get`
  prints the range if one is set.

The AmneziaWG 1.x keys `j1`, `j2`, `j3` and `itime` are not supported and are rejected with an
error.
