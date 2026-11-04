//! AmneziaWG 2.0/3.0/3.1 obfuscation support.

// Consumed by the device paths in later tasks; only tests reach these yet.
#[allow(dead_code)]
pub(crate) mod classify;
mod config;
pub(crate) mod cps;
pub(crate) mod header_protection;
pub(crate) mod junk;
#[allow(dead_code)]
pub(crate) mod rng;
#[allow(dead_code)]
pub(crate) mod seal;
// Wired into peer creation by later tasks; only tests reach it yet.
#[allow(dead_code)]
pub(crate) mod timers;
#[allow(dead_code)]
pub(crate) mod tunn_state;

pub use config::*;
