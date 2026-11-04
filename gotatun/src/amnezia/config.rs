//! AmneziaWG configuration: types, validation and UAPI key handling.
//!
//! This module performs no I/O. Validation is deliberately no stricter than
//! amneziawg-go: only overlapping H ranges, `jmin > jmax` (when junk is on),
//! padding below 12 with header protection, and AWG 1.x keys are rejected.

use std::fmt;
use std::ops::RangeInclusive;
use std::time::Duration;

use thiserror::Error;

use crate::packet::WgPacketType;

pub use super::cps::CpsChain;

/// Minimum value of `s1..s4` when header protection is enabled.
pub const HEADER_PROTECTION_MIN_PADDING: u16 = 12;

/// Size in bytes of the header protection key.
pub const HEADER_PROTECTION_KEY_SIZE: usize = 32;

/// Error returned for invalid AmneziaWG configuration.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A header range could not be parsed.
    #[error("invalid header range `{value}`: {reason}")]
    InvalidHeaderRange {
        /// The offending input.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// Two header ranges overlap.
    #[error("{first} and {second} header ranges overlap")]
    HeaderRangesOverlap {
        /// Name of the first range (`H1`..`H4`).
        first: &'static str,
        /// Name of the second range (`H1`..`H4`).
        second: &'static str,
    },
    /// `jmin` is larger than `jmax` while junk is enabled.
    #[error("junk min {min} exceeds junk max {max}")]
    JunkMinExceedsMax {
        /// `jmin`.
        min: u16,
        /// `jmax`.
        max: u16,
    },
    /// An AmneziaWG 1.x key, which is not supported.
    #[error("`{field}` is not an AmneziaWG 2.0+ field")]
    UnsupportedLegacyField {
        /// The key name.
        field: String,
    },
    /// A numeric range could not be parsed or is inverted.
    #[error("invalid range `{value}`: {reason}")]
    InvalidRange {
        /// The offending input.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A key has an unparseable value.
    #[error("invalid value for `{field}`: {reason}")]
    InvalidFieldValue {
        /// The key name.
        field: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A CPS (`i1..i5`) chain is malformed.
    #[error("invalid CPS chain: {reason}")]
    InvalidCps {
        /// Why it was rejected.
        reason: String,
    },
    /// A CPS chain uses an unknown tag.
    #[error("unsupported CPS tag `<{tag}>`")]
    UnsupportedCpsTag {
        /// The tag name.
        tag: String,
    },
    /// A CPS tag length exceeds the largest UDP datagram.
    #[error("CPS tag <{tag}> value {value} exceeds the maximum {max}")]
    CpsValueOutOfRange {
        /// The tag name.
        tag: &'static str,
        /// The offending value.
        value: usize,
        /// The maximum accepted value.
        max: usize,
    },
    /// `s1..s4` is below the minimum required for header protection.
    #[error("{field} padding {value} is below the header-protection minimum {min}")]
    HeaderProtectionPaddingTooSmall {
        /// Name of the padding (`S1`..`S4`).
        field: &'static str,
        /// The configured value.
        value: u16,
        /// The required minimum.
        min: u16,
    },
    /// AmneziaWG was configured together with Phobos, whose server forwards
    /// to plain WireGuard.
    #[cfg(feature = "phobos")]
    #[error("AmneziaWG cannot be combined with Phobos")]
    CombinedWithPhobos,
}

/// An inclusive range of message-type header values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderRange {
    /// Lowest value (inclusive).
    pub start: u32,
    /// Highest value (inclusive).
    pub end: u32,
}

impl HeaderRange {
    const fn single(value: u32) -> Self {
        HeaderRange {
            start: value,
            end: value,
        }
    }

    fn parse(input: &str) -> Result<Self, ConfigError> {
        let err = |reason| ConfigError::InvalidHeaderRange {
            value: input.to_owned(),
            reason,
        };
        let input_trimmed = input.trim();
        let mut parts = input_trimmed.split('-');
        let part = |p: Option<&str>| -> Result<u32, ConfigError> {
            p.unwrap_or_default()
                .trim()
                .parse::<u32>()
                .map_err(|_| err("expected decimal digits in u32 range"))
        };
        let start = part(parts.next())?;
        let end = match parts.next() {
            Some(p) => part(Some(p))?,
            None => start,
        };
        if parts.next().is_some() {
            return Err(err("expected `value` or `start-end`"));
        }
        if end < start {
            return Err(err("range end is smaller than start"));
        }
        Ok(HeaderRange { start, end })
    }

    fn contains(self, v: u32) -> bool {
        self.start <= v && v <= self.end
    }

    fn overlaps(self, other: Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

impl fmt::Display for HeaderRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

/// Header ranges for the four WireGuard message types (`h1..h4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderRanges {
    /// Handshake initiation (`h1`).
    pub init: HeaderRange,
    /// Handshake response (`h2`).
    pub response: HeaderRange,
    /// Cookie reply (`h3`).
    pub cookie: HeaderRange,
    /// Transport data (`h4`).
    pub transport: HeaderRange,
}

impl Default for HeaderRanges {
    fn default() -> Self {
        HeaderRanges {
            init: HeaderRange::single(1),
            response: HeaderRange::single(2),
            cookie: HeaderRange::single(3),
            transport: HeaderRange::single(4),
        }
    }
}

impl HeaderRanges {
    /// Classify a message-type header value, or `None` if it falls in no range.
    pub fn kind_of(&self, v: u32) -> Option<WgPacketType> {
        if self.init.contains(v) {
            Some(WgPacketType::HandshakeInit)
        } else if self.response.contains(v) {
            Some(WgPacketType::HandshakeResp)
        } else if self.cookie.contains(v) {
            Some(WgPacketType::CookieReply)
        } else if self.transport.contains(v) {
            Some(WgPacketType::Data)
        } else {
            None
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let entries = [
            ("H1", self.init),
            ("H2", self.response),
            ("H3", self.cookie),
            ("H4", self.transport),
        ];
        for (i, (first, a)) in entries.iter().enumerate() {
            for (second, b) in &entries[i + 1..] {
                if a.overlaps(*b) {
                    return Err(ConfigError::HeaderRangesOverlap { first, second });
                }
            }
        }
        Ok(())
    }
}

/// Handshake and transport padding sizes (`s1..s4`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Padding {
    /// Handshake initiation padding.
    pub s1: u16,
    /// Handshake response padding.
    pub s2: u16,
    /// Cookie reply padding.
    pub s3: u16,
    /// Transport packet prefix length.
    pub s4: u16,
}

/// Junk packet parameters (`jc`, `jmin`, `jmax`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Junk {
    /// Number of junk packets sent before a handshake.
    pub count: u16,
    /// Minimum junk packet size.
    pub min: u16,
    /// Maximum junk packet size.
    pub max: u16,
}

/// The five optional I-packet chains (`i1..i5`). Gaps are allowed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InitPackets(pub [Option<CpsChain>; 5]);

/// An inclusive `u32` range. A fully-zero range means "unset".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct U32Range {
    /// Lower bound (inclusive).
    pub lo: u32,
    /// Upper bound (inclusive).
    pub hi: u32,
}

impl U32Range {
    fn parse(input: &str) -> Result<Self, ConfigError> {
        let err = |reason| ConfigError::InvalidRange {
            value: input.to_owned(),
            reason,
        };
        let mut parts = input.trim().split('-');
        let part = |p: Option<&str>| -> Result<u32, ConfigError> {
            p.unwrap_or_default()
                .trim()
                .parse::<u32>()
                .map_err(|_| err("expected decimal digits"))
        };
        let lo = part(parts.next())?;
        let hi = match parts.next() {
            Some(p) => part(Some(p))?,
            None => lo,
        };
        if parts.next().is_some() {
            return Err(err("expected `value` or `start-end`"));
        }
        if hi < lo {
            return Err(err("range end is smaller than start"));
        }
        Ok(U32Range { lo, hi })
    }

    fn validate(&self, field: &str) -> Result<(), ConfigError> {
        if self.hi < self.lo {
            return Err(ConfigError::InvalidRange {
                value: format!("{field}={self}"),
                reason: "range end is smaller than start",
            });
        }
        Ok(())
    }
}

impl fmt::Display for U32Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

/// Randomized timing parameters. `None` keeps the WireGuard constant.
/// Time ranges are expressed in whole seconds on the wire (UAPI).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimingRanges {
    /// Rekey-after-time range.
    pub rekey_after_time: Option<RangeInclusive<Duration>>,
    /// Rekey-timeout range.
    pub rekey_timeout: Option<RangeInclusive<Duration>>,
    /// Reject-after-time range.
    pub reject_after_time: Option<RangeInclusive<Duration>>,
    /// Keepalive-timeout range.
    pub keepalive_timeout: Option<RangeInclusive<Duration>>,
    /// Handshake attempt count range.
    pub max_handshake_attempts: Option<RangeInclusive<u32>>,
}

fn parse_secs_range(value: &str) -> Result<Option<RangeInclusive<Duration>>, ConfigError> {
    let r = U32Range::parse(value)?;
    Ok(if r == U32Range::default() {
        None
    } else {
        Some(Duration::from_secs(r.lo.into())..=Duration::from_secs(r.hi.into()))
    })
}

fn fmt_secs_range(r: &RangeInclusive<Duration>) -> String {
    U32Range {
        lo: r.start().as_secs() as u32,
        hi: r.end().as_secs() as u32,
    }
    .to_string()
}

fn field_u16(field: &str, value: &str) -> Result<u16, ConfigError> {
    value
        .trim()
        .parse::<u16>()
        .map_err(|_| ConfigError::InvalidFieldValue {
            field: field.to_owned(),
            reason: "expected a decimal value in 0-65535",
        })
}

/// Parse a UAPI boolean: `0/1`, `t/f`, `true/false`, `on/off`, any case.
fn field_bool(field: &str, value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "t" | "true" | "on" => Ok(true),
        "0" | "f" | "false" | "off" => Ok(false),
        _ => Err(ConfigError::InvalidFieldValue {
            field: field.to_owned(),
            reason: "expected a boolean (0/1, true/false, on/off)",
        }),
    }
}

fn parse_hp_key(value: &str) -> Result<Option<[u8; HEADER_PROTECTION_KEY_SIZE]>, ConfigError> {
    let err = |reason| ConfigError::InvalidFieldValue {
        field: "header_protection_key".to_owned(),
        reason,
    };
    let v = value.trim();
    if v.len() != HEADER_PROTECTION_KEY_SIZE * 2 {
        return Err(err("expected exactly 32 bytes (64 hex characters)"));
    }
    let mut key = [0u8; HEADER_PROTECTION_KEY_SIZE];
    for (byte, pair) in key.iter_mut().zip(v.as_bytes().chunks(2)) {
        let digits = std::str::from_utf8(pair).map_err(|_| err("expected hex characters"))?;
        *byte = u8::from_str_radix(digits, 16).map_err(|_| err("expected hex characters"))?;
    }
    // An all-zero key means "disabled", as in amneziawg-go.
    Ok(if key == [0u8; HEADER_PROTECTION_KEY_SIZE] {
        None
    } else {
        Some(key)
    })
}

/// AmneziaWG configuration. The default is plain WireGuard.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AmneziaConfig {
    /// Message-type header ranges (`h1..h4`).
    pub headers: HeaderRanges,
    /// Padding sizes (`s1..s4`).
    pub padding: Padding,
    /// Junk packet parameters.
    pub junk: Junk,
    /// Signature packets (`i1..i5`).
    pub init_packets: InitPackets,
    /// Header protection key; `None` disables header protection.
    pub header_protection_key: Option<[u8; HEADER_PROTECTION_KEY_SIZE]>,
    /// Random extra content padding for transport packets.
    pub content_padding: Option<U32Range>,
    /// Randomized timing parameters.
    pub timings: TimingRanges,
    /// AmneziaWG 3.1: append random trailers to datagrams.
    pub random_trailers: bool,
    /// AmneziaWG 3.1: never emit a cookie reply.
    pub disable_cookies: bool,
}

impl AmneziaConfig {
    /// Check the configuration, enforcing only what amneziawg-go enforces.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.headers.validate()?;
        if self.junk.count > 0 && self.junk.min > self.junk.max {
            return Err(ConfigError::JunkMinExceedsMax {
                min: self.junk.min,
                max: self.junk.max,
            });
        }
        if let Some(r) = self.content_padding {
            r.validate("content_padding_addition")?;
        }
        let t = &self.timings;
        for (name, r) in [
            ("rekey_after_time", &t.rekey_after_time),
            ("rekey_timeout", &t.rekey_timeout),
            ("reject_after_time", &t.reject_after_time),
            ("keepalive_timeout", &t.keepalive_timeout),
        ] {
            if let Some(r) = r
                && r.start() > r.end()
            {
                return Err(ConfigError::InvalidRange {
                    value: name.to_owned(),
                    reason: "range end is smaller than start",
                });
            }
        }
        if let Some(r) = &t.max_handshake_attempts
            && r.start() > r.end()
        {
            return Err(ConfigError::InvalidRange {
                value: "max_handshake_attempts".to_owned(),
                reason: "range end is smaller than start",
            });
        }
        if self.header_protection_key.is_some() {
            let p = &self.padding;
            for (field, value) in [("S1", p.s1), ("S2", p.s2), ("S3", p.s3), ("S4", p.s4)] {
                if value < HEADER_PROTECTION_MIN_PADDING {
                    return Err(ConfigError::HeaderProtectionPaddingTooSmall {
                        field,
                        value,
                        min: HEADER_PROTECTION_MIN_PADDING,
                    });
                }
            }
        }
        Ok(())
    }

    /// Whether this configuration is indistinguishable from plain WireGuard.
    pub fn is_plain_wireguard(&self) -> bool {
        *self == AmneziaConfig::default()
    }

    /// Number of bytes prepended to every transport packet (`s4`).
    pub fn transport_overhead(&self) -> usize {
        self.padding.s4.into()
    }

    /// Apply one UAPI `key=value` line. Returns `Ok(false)` for an unknown key.
    ///
    /// This only parses the value; call [`Self::validate`] once all lines are
    /// applied, since some rules span several keys.
    pub fn apply_uapi_line(&mut self, key: &str, value: &str) -> Result<bool, ConfigError> {
        match key {
            "jc" => self.junk.count = field_u16(key, value)?,
            "jmin" => self.junk.min = field_u16(key, value)?,
            "jmax" => self.junk.max = field_u16(key, value)?,
            "s1" => self.padding.s1 = field_u16(key, value)?,
            "s2" => self.padding.s2 = field_u16(key, value)?,
            "s3" => self.padding.s3 = field_u16(key, value)?,
            "s4" => self.padding.s4 = field_u16(key, value)?,
            "h1" => self.headers.init = HeaderRange::parse(value)?,
            "h2" => self.headers.response = HeaderRange::parse(value)?,
            "h3" => self.headers.cookie = HeaderRange::parse(value)?,
            "h4" => self.headers.transport = HeaderRange::parse(value)?,
            "i1" | "i2" | "i3" | "i4" | "i5" => {
                let idx = usize::from(key.as_bytes()[1] - b'1');
                let v = value.trim();
                self.init_packets.0[idx] = Some(CpsChain::parse(v)?).filter(|c| !c.is_empty());
            }
            "header_protection_key" => self.header_protection_key = parse_hp_key(value)?,
            "content_padding_addition" => {
                let r = U32Range::parse(value)?;
                self.content_padding = (r != U32Range::default()).then_some(r);
            }
            "rekey_after_time" => self.timings.rekey_after_time = parse_secs_range(value)?,
            "rekey_timeout" => self.timings.rekey_timeout = parse_secs_range(value)?,
            "reject_after_time" => self.timings.reject_after_time = parse_secs_range(value)?,
            "keepalive_timeout" => self.timings.keepalive_timeout = parse_secs_range(value)?,
            "max_handshake_attempts" => {
                let r = U32Range::parse(value)?;
                self.timings.max_handshake_attempts =
                    (r != U32Range::default()).then_some(r.lo..=r.hi);
            }
            "random_trailers" => self.random_trailers = field_bool(key, value)?,
            "disable_cookies" => self.disable_cookies = field_bool(key, value)?,
            "j1" | "j2" | "j3" | "itime" => {
                return Err(ConfigError::UnsupportedLegacyField {
                    field: key.to_owned(),
                });
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Emit non-default settings as UAPI `(key, value)` lines.
    pub fn to_uapi_lines(&self) -> Vec<(String, String)> {
        let default = AmneziaConfig::default();
        let mut out: Vec<(String, String)> = Vec::new();
        let mut push = |k: &str, v: String| out.push((k.to_owned(), v));

        if self.junk != default.junk {
            push("jc", self.junk.count.to_string());
            push("jmin", self.junk.min.to_string());
            push("jmax", self.junk.max.to_string());
        }
        for (k, v) in [
            ("s1", self.padding.s1),
            ("s2", self.padding.s2),
            ("s3", self.padding.s3),
            ("s4", self.padding.s4),
        ] {
            if v != 0 {
                push(k, v.to_string());
            }
        }
        if self.headers != default.headers {
            push("h1", self.headers.init.to_string());
            push("h2", self.headers.response.to_string());
            push("h3", self.headers.cookie.to_string());
            push("h4", self.headers.transport.to_string());
        }
        for (i, chain) in self.init_packets.0.iter().enumerate() {
            if let Some(chain) = chain {
                push(&format!("i{}", i + 1), chain.to_string());
            }
        }
        if let Some(key) = self.header_protection_key {
            push(
                "header_protection_key",
                key.iter().map(|b| format!("{b:02x}")).collect(),
            );
        }
        if let Some(r) = self.content_padding {
            push("content_padding_addition", r.to_string());
        }
        for (k, r) in [
            ("rekey_after_time", &self.timings.rekey_after_time),
            ("rekey_timeout", &self.timings.rekey_timeout),
            ("reject_after_time", &self.timings.reject_after_time),
            ("keepalive_timeout", &self.timings.keepalive_timeout),
        ] {
            if let Some(r) = r {
                push(k, fmt_secs_range(r));
            }
        }
        if let Some(r) = &self.timings.max_handshake_attempts {
            push(
                "max_handshake_attempts",
                U32Range {
                    lo: *r.start(),
                    hi: *r.end(),
                }
                .to_string(),
            );
        }
        if self.random_trailers {
            push("random_trailers", "1".to_owned());
        }
        if self.disable_cookies {
            push("disable_cookies", "1".to_owned());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic, fully populated block (not a real deployment's values).
    const FULL: &str = "jc=5\n\
        jmin=70\n\
        jmax=300\n\
        s1=23\n\
        s2=91\n\
        s3=37\n\
        s4=19\n\
        h1=1000000-2000000\n\
        h2=3000000-4000000\n\
        h3=5000000-6000000\n\
        h4=7000000-8000000\n\
        i1=<b 0xdeadbeef><r 16>\n\
        i3=<t>\n\
        header_protection_key=\
        4242424242424242424242424242424242424242424242424242424242424242\n\
        content_padding_addition=1-64\n\
        rekey_after_time=100-140\n\
        rekey_timeout=3-9\n\
        reject_after_time=170-200\n\
        keepalive_timeout=8-15\n\
        max_handshake_attempts=10-20\n\
        random_trailers=1\n\
        disable_cookies=1\n";

    fn parse(block: &str) -> Result<AmneziaConfig, ConfigError> {
        let mut cfg = AmneziaConfig::default();
        for line in block.lines().filter(|l| !l.trim().is_empty()) {
            let (k, v) = line.split_once('=').unwrap();
            assert!(cfg.apply_uapi_line(k, v)?, "unknown key {k}");
        }
        cfg.validate()?;
        Ok(cfg)
    }

    fn set(pairs: &[(&str, &str)]) -> Result<AmneziaConfig, ConfigError> {
        let mut cfg = AmneziaConfig::default();
        for (k, v) in pairs {
            cfg.apply_uapi_line(k, v)?;
        }
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn h_ranges_must_not_overlap() {
        let err = set(&[("h1", "100-200"), ("h2", "150-250")]).unwrap_err();
        assert!(matches!(err, ConfigError::HeaderRangesOverlap { .. }));
        assert!(
            set(&[
                ("h1", "100-200"),
                ("h2", "201-250"),
                ("h3", "3"),
                ("h4", "4")
            ])
            .is_ok()
        );
    }

    #[test]
    fn h_values_1_to_4_allowed() {
        assert!(set(&[("h1", "1"), ("h2", "2"), ("h3", "3"), ("h4", "4")]).is_ok());
        assert!(set(&[("jc", "3"), ("jmin", "10"), ("jmax", "20")]).is_ok());
    }

    #[test]
    fn jmin_gt_jmax_rejected_only_when_jc_positive() {
        assert!(matches!(
            set(&[("jc", "1"), ("jmin", "50"), ("jmax", "10")]),
            Err(ConfigError::JunkMinExceedsMax { .. })
        ));
        assert!(set(&[("jc", "0"), ("jmin", "50"), ("jmax", "10")]).is_ok());
    }

    #[test]
    fn header_protection_requires_s_ge_12() {
        let key = "42".repeat(32);
        for bad in ["s1", "s2", "s3", "s4"] {
            let mut pairs = vec![
                ("s1", "16"),
                ("s2", "16"),
                ("s3", "16"),
                ("s4", "16"),
                ("header_protection_key", key.as_str()),
            ];
            pairs.iter_mut().find(|(k, _)| *k == bad).unwrap().1 = "11";
            assert!(matches!(
                set(&pairs),
                Err(ConfigError::HeaderProtectionPaddingTooSmall { .. })
            ));
        }
        assert!(set(&[("s1", "0"), ("header_protection_key", &"00".repeat(32))]).is_ok());
    }

    #[test]
    fn s_values_above_255_accepted() {
        let cfg = set(&[("s1", "1000")]).unwrap();
        assert_eq!(cfg.padding.s1, 1000);
    }

    #[test]
    fn awg1_keys_rejected() {
        let mut cfg = AmneziaConfig::default();
        for k in ["j1", "j2", "j3", "itime"] {
            assert!(cfg.apply_uapi_line(k, "1").is_err(), "{k}");
        }
        assert_eq!(cfg.apply_uapi_line("endpoint", "x"), Ok(false));
    }

    #[test]
    fn i_packet_gaps_allowed() {
        let cfg = set(&[("i3", "<t>")]).unwrap();
        assert!(cfg.init_packets.0[2].is_some());
        assert!(cfg.init_packets.0[0].is_none());
    }

    #[test]
    fn uapi_round_trip() {
        let cfg = parse(FULL).unwrap();
        let lines = cfg.to_uapi_lines();
        let emitted: String = lines.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
        assert_eq!(emitted, FULL);
        assert_eq!(parse(&emitted).unwrap(), cfg);
        assert_eq!(cfg.transport_overhead(), 19);
        assert!(!cfg.is_plain_wireguard());
    }

    #[test]
    fn default_emits_nothing() {
        let cfg = AmneziaConfig::default();
        assert!(cfg.to_uapi_lines().is_empty());
        assert!(cfg.is_plain_wireguard());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn zero_hp_key_means_off() {
        let cfg = set(&[("header_protection_key", &"00".repeat(32))]).unwrap();
        assert_eq!(cfg.header_protection_key, None);
        assert!(cfg.is_plain_wireguard());
    }

    #[test]
    fn full_u32_h_range_ok() {
        // The full u32 span parses without overflow. It covers every other
        // type, so it overlaps the default h1..h3 and only `validate` objects
        // (as in amneziawg-go).
        let mut cfg = AmneziaConfig::default();
        assert_eq!(cfg.apply_uapi_line("h4", "0-4294967295"), Ok(true));
        assert_eq!(
            cfg.headers.transport,
            HeaderRange {
                start: 0,
                end: u32::MAX
            }
        );
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::HeaderRangesOverlap { .. })
        ));
    }

    #[test]
    fn booleans_accept_all_spellings() {
        for t in ["1", "t", "TRUE", "On", "true"] {
            assert!(
                set(&[("random_trailers", t)]).unwrap().random_trailers,
                "{t}"
            );
        }
        for f in ["0", "f", "False", "OFF"] {
            assert!(
                !set(&[("disable_cookies", f)]).unwrap().disable_cookies,
                "{f}"
            );
        }
        assert!(set(&[("random_trailers", "maybe")]).is_err());
    }

    #[test]
    fn kind_of_classifies() {
        let cfg = set(&[("h1", "10-20"), ("h2", "30"), ("h3", "40"), ("h4", "50-60")]).unwrap();
        let h = cfg.headers;
        assert_eq!(h.kind_of(15), Some(WgPacketType::HandshakeInit));
        assert_eq!(h.kind_of(30), Some(WgPacketType::HandshakeResp));
        assert_eq!(h.kind_of(40), Some(WgPacketType::CookieReply));
        assert_eq!(h.kind_of(55), Some(WgPacketType::Data));
        assert_eq!(h.kind_of(25), None);
    }

    #[test]
    fn s_and_h_values_are_decimal_only() {
        assert!(set(&[("s1", "0x10")]).is_err());
        assert!(set(&[("h1", "5-3")]).is_err());
        assert!(set(&[("header_protection_key", "abcd")]).is_err());
    }
}
