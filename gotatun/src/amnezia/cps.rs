//! Custom protocol signature (CPS) chains for `i1..i5`.
//!
//! Tags: `<b 0xHEX> <t> <r N> <rc N> <rd N> <d> <ds> <dz N>`. I-packets carry
//! no source data, so `<d>`, `<ds>` and `<dz N>` emit nothing.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use super::config::ConfigError;
use super::rng::RandomSource;

/// Upper bound on an `<r>`/`<rc>`/`<rd>`/`<dz>` length: the largest UDP
/// datagram, which is the only bound amneziawg-go has.
pub(crate) const MAX_CPS_LEN: usize = u16::MAX as usize;

const ALPHA: &[u8; 52] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// One CPS tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CpsTag {
    Bytes(Vec<u8>),
    Timestamp,
    RandomBytes(usize),
    RandomChars(usize),
    RandomDigits(usize),
    Data,
    DataString,
    DataSize(usize),
}

/// A parsed CPS chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpsChain {
    tags: Vec<CpsTag>,
}

fn invalid(reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidCps {
        reason: reason.into(),
    }
}

impl CpsChain {
    /// Parse a chain such as `<b 0xdead><r 16><t>`.
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let mut rest = input.trim_start();
        let mut tags = Vec::new();
        while !rest.is_empty() {
            let body = rest.strip_prefix('<').ok_or_else(|| {
                invalid(format!(
                    "expected `<` at `{}`",
                    rest.chars().next().unwrap_or(' ')
                ))
            })?;
            let end = body
                .find('>')
                .ok_or_else(|| invalid("missing closing `>`"))?;
            tags.push(parse_tag(body[..end].trim())?);
            rest = body[end + 1..].trim_start();
        }
        if tags.is_empty() {
            return Err(invalid("empty chain"));
        }
        Ok(CpsChain { tags })
    }

    /// Append the chain's bytes to `out`.
    pub(crate) fn render(&self, rng: &mut dyn RandomSource, out: &mut Vec<u8>) {
        for tag in &self.tags {
            match tag {
                CpsTag::Bytes(b) => out.extend_from_slice(b),
                CpsTag::Timestamp => {
                    let ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u32;
                    out.extend_from_slice(&ts.to_be_bytes());
                }
                CpsTag::RandomBytes(n) => {
                    let start = out.len();
                    out.resize(start + n, 0);
                    rng.fill(&mut out[start..]);
                }
                CpsTag::RandomChars(n) => {
                    for _ in 0..*n {
                        out.push(ALPHA[rng.range_u32(0, 51) as usize]);
                    }
                }
                CpsTag::RandomDigits(n) => {
                    for _ in 0..*n {
                        out.push(b'0' + rng.range_u32(0, 9) as u8);
                    }
                }
                // No source data for I-packets: these emit nothing.
                CpsTag::Data | CpsTag::DataString | CpsTag::DataSize(_) => {}
            }
        }
    }
}

fn parse_tag(tag: &str) -> Result<CpsTag, ConfigError> {
    let mut parts = tag.split_whitespace();
    let name = parts.next().ok_or_else(|| invalid("empty tag"))?;
    let arg = parts.next();
    if parts.next().is_some() {
        return Err(invalid(format!("<{name}> has too many arguments")));
    }
    let no_arg = |t: CpsTag| match arg {
        Some(_) => Err(invalid(format!("<{name}> does not take an argument"))),
        None => Ok(t),
    };
    match name {
        "b" => parse_bytes(arg),
        "t" => no_arg(CpsTag::Timestamp),
        "d" => no_arg(CpsTag::Data),
        "ds" => no_arg(CpsTag::DataString),
        "r" => parse_len("r", arg).map(CpsTag::RandomBytes),
        "rc" => parse_len("rc", arg).map(CpsTag::RandomChars),
        "rd" => parse_len("rd", arg).map(CpsTag::RandomDigits),
        "dz" => parse_len("dz", arg).map(CpsTag::DataSize),
        _ => Err(ConfigError::UnsupportedCpsTag {
            tag: name.to_owned(),
        }),
    }
}

fn parse_bytes(arg: Option<&str>) -> Result<CpsTag, ConfigError> {
    let hex = arg
        .and_then(|a| a.strip_prefix("0x"))
        .ok_or_else(|| invalid("<b> requires a 0x-prefixed hex argument"))?;
    if hex.is_empty() {
        return Err(invalid("<b> hex data is empty"));
    }
    if hex.len() % 2 != 0 {
        return Err(invalid("<b> hex data must contain full bytes"));
    }
    if !hex.is_ascii() {
        return Err(invalid("<b> contains non-hex data"));
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("<b> contains non-hex data"))?;
    Ok(CpsTag::Bytes(bytes))
}

fn parse_len(tag: &'static str, arg: Option<&str>) -> Result<usize, ConfigError> {
    let arg = arg.ok_or_else(|| invalid(format!("<{tag}> requires a length argument")))?;
    let len = arg
        .parse::<usize>()
        .map_err(|_| invalid(format!("<{tag}> length must be a non-negative integer")))?;
    if len > MAX_CPS_LEN {
        return Err(ConfigError::CpsValueOutOfRange {
            tag,
            value: len,
            max: MAX_CPS_LEN,
        });
    }
    Ok(len)
}

/// Renders back to text that [`CpsChain::parse`] accepts.
impl fmt::Display for CpsChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for tag in &self.tags {
            match tag {
                CpsTag::Bytes(b) => {
                    f.write_str("<b 0x")?;
                    for byte in b {
                        write!(f, "{byte:02x}")?;
                    }
                    f.write_str(">")?;
                }
                CpsTag::Timestamp => f.write_str("<t>")?,
                CpsTag::RandomBytes(n) => write!(f, "<r {n}>")?,
                CpsTag::RandomChars(n) => write!(f, "<rc {n}>")?,
                CpsTag::RandomDigits(n) => write!(f, "<rd {n}>")?,
                CpsTag::Data => f.write_str("<d>")?,
                CpsTag::DataString => f.write_str("<ds>")?,
                CpsTag::DataSize(n) => write!(f, "<dz {n}>")?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::rng::DetRng;
    use super::*;

    fn render(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        CpsChain::parse(s)
            .unwrap()
            .render(&mut DetRng::new(3), &mut out);
        out
    }

    #[test]
    fn cps_tags_parse_and_render_lengths() {
        assert_eq!(render("<b 0xdeadbeef>"), [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(render("<t>").len(), 4);
        assert_eq!(render("<r 16>").len(), 16);
        assert_eq!(render("<rc 10>").len(), 10);
        assert_eq!(render("<rd 10>").len(), 10);
        assert!(render("<rc 50>").iter().all(u8::is_ascii_alphabetic));
        assert!(render("<rd 50>").iter().all(u8::is_ascii_digit));
        assert!(render("<d><ds><dz 4>").is_empty());
        assert_eq!(render(" <b 0xaa> <r 2><t>  <d> ").len(), 1 + 2 + 4);
        assert_eq!(render("<r 1000>").len(), 1000);

        let ts = u32::from_be_bytes(render("<t>").try_into().unwrap());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        assert!(now.abs_diff(ts) < 5);
    }

    #[test]
    fn cps_rejects_over_65535() {
        assert!(CpsChain::parse("<r 65535>").is_ok());
        assert!(matches!(
            CpsChain::parse("<r 65536>"),
            Err(ConfigError::CpsValueOutOfRange { .. })
        ));
        assert!(CpsChain::parse("<rc 65536>").is_err());
        assert!(CpsChain::parse("<rd 65536>").is_err());
        assert!(CpsChain::parse("<dz 65536>").is_err());
    }

    #[test]
    fn cps_rejects_malformed() {
        for bad in [
            "",
            "   ",
            "<r>",
            "<r x>",
            "<r -1>",
            "<t 1>",
            "<b>",
            "<b 12>",
            "<b 0x>",
            "<b 0xabc>",
            "<b 0xzz>",
            "<x 1>",
            "<r 1",
            "r 1>",
            "<r 1 2>",
            "<>",
        ] {
            assert!(CpsChain::parse(bad).is_err(), "{bad:?} should be rejected");
        }
        assert!(matches!(
            CpsChain::parse("<x 1>"),
            Err(ConfigError::UnsupportedCpsTag { .. })
        ));
    }

    #[test]
    fn cps_display_round_trips() {
        let s = "<b 0xdeadbeef><t><r 16><rc 3><rd 4><d><ds><dz 2>";
        let chain = CpsChain::parse(s).unwrap();
        assert_eq!(chain.to_string(), s);
        assert_eq!(CpsChain::parse(&chain.to_string()).unwrap(), chain);
    }
}
