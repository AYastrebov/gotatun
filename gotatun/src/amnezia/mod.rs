//! AmneziaWG 2.0/3.0/3.1 obfuscation support.

// Primitives are consumed by later tasks; only tests use some of them yet.
mod config;
#[allow(dead_code)]
pub(crate) mod cps;
#[allow(dead_code)]
pub(crate) mod header_protection;
#[allow(dead_code)]
pub(crate) mod junk;
#[allow(dead_code)]
pub(crate) mod rng;

pub use config::*;
