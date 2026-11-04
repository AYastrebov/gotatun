//! AWG 3.0 timing ranges mapped onto gotatun's timers.
//!
//! The device-wide [`TimingRanges`] become the default [`TimerParams`] of every
//! peer (an explicit per-peer `danger_timer_params` wins), plus a
//! [`TimerExtras`] for the ranges `TimerParams` has no field for.

use std::ops::RangeInclusive;
use std::time::Duration;

use super::config::TimingRanges;
use crate::noise::{MAX_JITTER, TimerExtras, TimerParams};

/// amneziawg-go `MaxTimerHandshakes` (`RekeyAttemptTime / RekeyTimeout`).
const MAX_TIMER_HANDSHAKES: u32 = 18;

/// The [`TimerParams`] for a peer under `cfg`. Unset ranges keep the defaults,
/// so `TimingRanges::default()` yields `TimerParams::default()`.
///
/// The retransmit jitter stays at upstream's [`MAX_JITTER`] (333 ms) rather than
/// amneziawg-go's `[0, 334)` ms.
pub(crate) fn timer_params_from(cfg: &TimingRanges) -> TimerParams {
    let defaults = TimerParams::default();
    let keepalive = cfg
        .keepalive_timeout
        .clone()
        .unwrap_or(defaults.keepalive_timeout.clone());
    let rekey = cfg.rekey_timeout.clone();

    TimerParams {
        rekey_timeout: rekey.as_ref().map_or(defaults.rekey_timeout.clone(), |r| {
            *r.start()..=*r.end() + MAX_JITTER
        }),
        // amneziawg-go `newHandshakeTimeout`: Hi(keepalive) + pick(rekey) + jitter.
        new_handshake_timeout: if cfg.keepalive_timeout.is_some() || rekey.is_some() {
            let rekey = rekey.unwrap_or(rekey_secs(&defaults));
            (*keepalive.end() + *rekey.start())..=(*keepalive.end() + *rekey.end() + MAX_JITTER)
        } else {
            defaults.new_handshake_timeout
        },
        keepalive_timeout: keepalive,
        rekey_after_time: cfg
            .rekey_after_time
            .clone()
            .unwrap_or(defaults.rekey_after_time),
    }
}

/// The [`TimerExtras`] for a peer under `cfg`. The persistent-keepalive range is
/// a peer key and is left `None` here for the caller to fill in.
///
/// amneziawg-go always bounds retries by a count, so a configured
/// `rekey_timeout` alone stretches the give-up time; that case gets the default
/// 18 attempts. Without either range the classic `REKEY_ATTEMPT_TIME` is kept.
pub(crate) fn timer_extras_from(cfg: &TimingRanges) -> TimerExtras {
    let defaults = TimerParams::default();
    let max_handshake_attempts = cfg.max_handshake_attempts.clone().or_else(|| {
        cfg.rekey_timeout
            .as_ref()
            .map(|_| MAX_TIMER_HANDSHAKES..=MAX_TIMER_HANDSHAKES)
    });

    // amneziawg-go `keyRefreshTimeoutReceiving`:
    // max(0, pick(reject) - Lo(keepalive) - Lo(rekey)).
    let rekey_after_receive = if cfg.reject_after_time.is_some()
        || cfg.keepalive_timeout.is_some()
        || cfg.rekey_timeout.is_some()
    {
        let reject = cfg
            .reject_after_time
            .clone()
            .unwrap_or(REJECT_AFTER_TIME..=REJECT_AFTER_TIME);
        let keepalive_lo = cfg
            .keepalive_timeout
            .as_ref()
            .map_or(*defaults.keepalive_timeout.start(), |r| *r.start());
        let rekey_lo = cfg
            .rekey_timeout
            .as_ref()
            .map_or(*defaults.rekey_timeout.start(), |r| *r.start());
        let offset = keepalive_lo + rekey_lo;
        Some(reject.start().saturating_sub(offset)..=reject.end().saturating_sub(offset))
    } else {
        None
    };

    TimerExtras {
        reject_after_time: cfg.reject_after_time.clone(),
        max_handshake_attempts,
        persistent_keepalive: None,
        rekey_after_receive,
    }
}

/// WireGuard `REJECT_AFTER_TIME`.
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

/// The jitter-free rekey timeout of `params` (`Lo..=Hi - MAX_JITTER`).
fn rekey_secs(params: &TimerParams) -> RangeInclusive<Duration> {
    *params.rekey_timeout.start()..=params.rekey_timeout.end().saturating_sub(MAX_JITTER)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(lo: u64, hi: u64) -> Option<RangeInclusive<Duration>> {
        Some(Duration::from_secs(lo)..=Duration::from_secs(hi))
    }

    #[test]
    fn maps_configured_ranges() {
        let cfg = TimingRanges {
            rekey_after_time: secs(100, 140),
            rekey_timeout: secs(4, 8),
            reject_after_time: secs(170, 200),
            keepalive_timeout: secs(9, 12),
            max_handshake_attempts: Some(10..=20),
        };
        let p = timer_params_from(&cfg);
        assert_eq!(
            p.rekey_timeout,
            Duration::from_secs(4)..=Duration::from_secs(8) + MAX_JITTER
        );
        assert_eq!(p.keepalive_timeout, secs(9, 12).unwrap());
        assert_eq!(
            p.new_handshake_timeout,
            Duration::from_secs(16)..=Duration::from_secs(20) + MAX_JITTER
        );
        assert_eq!(p.rekey_after_time, secs(100, 140).unwrap());

        let e = timer_extras_from(&cfg);
        assert_eq!(e.reject_after_time, secs(170, 200));
        assert_eq!(e.max_handshake_attempts, Some(10..=20));
        assert_eq!(e.persistent_keepalive, None);
        // 170 - 9 - 4 ..= 200 - 9 - 4
        assert_eq!(e.rekey_after_receive, secs(157, 187));
    }

    #[test]
    fn rekey_timeout_alone_uses_default_attempts() {
        let cfg = TimingRanges {
            rekey_timeout: secs(10, 10),
            ..TimingRanges::default()
        };
        let e = timer_extras_from(&cfg);
        assert_eq!(e.max_handshake_attempts, Some(18..=18));
        // 180 - 10 - 10
        assert_eq!(e.rekey_after_receive, secs(160, 160));
        let p = timer_params_from(&cfg);
        assert_eq!(
            p.new_handshake_timeout,
            Duration::from_secs(20)..=Duration::from_secs(20) + MAX_JITTER
        );
    }

    #[test]
    fn keepalive_alone_keeps_default_rekey() {
        let cfg = TimingRanges {
            keepalive_timeout: secs(20, 30),
            ..TimingRanges::default()
        };
        let p = timer_params_from(&cfg);
        assert_eq!(p.rekey_timeout, TimerParams::default().rekey_timeout);
        assert_eq!(
            p.new_handshake_timeout,
            Duration::from_secs(35)..=Duration::from_secs(35) + MAX_JITTER
        );
        assert_eq!(timer_extras_from(&cfg).max_handshake_attempts, None);
    }

    #[test]
    fn reject_below_offset_saturates() {
        let cfg = TimingRanges {
            reject_after_time: secs(5, 20),
            ..TimingRanges::default()
        };
        assert_eq!(timer_extras_from(&cfg).rekey_after_receive, secs(0, 5));
    }
}
