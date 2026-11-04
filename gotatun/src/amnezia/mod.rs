//! AmneziaWG 2.0/3.0/3.1 obfuscation support.

// The device is the only consumer of the wire machinery; without it, only the
// public config types are reachable.
#![cfg_attr(not(feature = "device"), allow(dead_code))]

pub(crate) mod classify;
mod config;
pub(crate) mod cps;
pub(crate) mod header_protection;
pub(crate) mod junk;
pub(crate) mod rng;
pub(crate) mod seal;
pub(crate) mod timers;
pub(crate) mod tunn_state;

pub use config::*;
