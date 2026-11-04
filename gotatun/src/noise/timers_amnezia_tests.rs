use std::sync::Arc;

#[cfg(feature = "mock_instant")]
use mock_instant::thread_local::MockClock;

use super::*;
use crate::amnezia::TimingRanges;
use crate::amnezia::timers::{timer_extras_from, timer_params_from};
#[cfg(feature = "mock_instant")]
use crate::noise::TunnResult;
use crate::noise::index_table::IndexTable;
use crate::noise::rate_limiter::RateLimiter;
use crate::x25519;

fn secs(lo: u64, hi: u64) -> RangeInclusive<Duration> {
    Duration::from_secs(lo)..=Duration::from_secs(hi)
}

fn two_tuns() -> (Tunn, Tunn) {
    let my_secret = x25519::StaticSecret::random_from_rng(rand_core::OsRng);
    let my_public = x25519::PublicKey::from(&my_secret);
    let their_secret = x25519::StaticSecret::random_from_rng(rand_core::OsRng);
    let their_public = x25519::PublicKey::from(&their_secret);
    let mine = Tunn::new(
        my_secret,
        their_public,
        None,
        None,
        IndexTable::from_os_rng(),
        Arc::new(RateLimiter::new(&my_public, 100)),
    );
    let theirs = Tunn::new(
        their_secret,
        my_public,
        None,
        None,
        IndexTable::from_os_rng(),
        Arc::new(RateLimiter::new(&their_public, 100)),
    );
    (mine, theirs)
}

#[cfg(feature = "mock_instant")]
fn handshake(mine: &mut Tunn, theirs: &mut Tunn) {
    let init = mine.format_handshake_initiation(false).expect("init");
    let TunnResult::WriteToNetwork(resp) = theirs.handle_incoming_packet(init.into()) else {
        panic!("expected a handshake response");
    };
    let TunnResult::WriteToNetwork(WgKind::Data(keepalive)) = mine.handle_incoming_packet(resp)
    else {
        panic!("expected a keepalive after the handshake");
    };
    let result = theirs.handle_incoming_packet(WgKind::Data(keepalive));
    assert!(matches!(result, TunnResult::WriteToTunnel(p) if p.is_empty()));
}

#[cfg(feature = "mock_instant")]
fn has_current_session(tun: &Tunn) -> bool {
    tun.sessions[tun.current % crate::noise::N_SESSIONS].is_some()
}

/// `max_handshake_attempts` bounds retries to `pick(rekey_timeout) * attempts`
/// instead of `REKEY_ATTEMPT_TIME` (90 s).
#[test]
#[cfg(feature = "mock_instant")]
fn max_attempts_bounds_retries() {
    let (mut mine, _theirs) = two_tuns();
    mine.dangerously_set_timer_params(TimerParams {
        rekey_timeout: secs(5, 5),
        ..TimerParams::default()
    });
    mine.set_timer_extras(TimerExtras {
        max_handshake_attempts: Some(3..=3),
        ..TimerExtras::default()
    });
    mine.format_handshake_initiation(false).expect("init");

    let mut elapsed = Duration::ZERO;
    let gave_up_at = loop {
        MockClock::advance(Duration::from_secs(1));
        elapsed += Duration::from_secs(1);
        match mine.update_timers() {
            Err(WireGuardError::ConnectionExpired) => break elapsed,
            Ok(_) => assert!(elapsed < REKEY_ATTEMPT_TIME, "never gave up"),
            Err(e) => panic!("unexpected error {e:?}"),
        }
    };
    assert_eq!(gave_up_at, Duration::from_secs(15));
}

/// Key expiry follows `Hi(reject_after_time)`, not the 180 s constant.
#[test]
#[cfg(feature = "mock_instant")]
fn reject_after_uses_hi() {
    let (mut mine, mut theirs) = two_tuns();
    mine.set_timer_extras(TimerExtras {
        reject_after_time: Some(secs(200, 300)),
        ..TimerExtras::default()
    });
    handshake(&mut mine, &mut theirs);
    assert!(has_current_session(&mine));

    MockClock::advance(Duration::from_secs(250));
    assert!(mine.update_timers().is_ok());
    assert!(has_current_session(&mine), "expired before Hi(reject)");

    MockClock::advance(Duration::from_secs(51));
    assert!(mine.update_timers().is_ok());
    assert!(!has_current_session(&mine), "kept past Hi(reject)");

    // Key material is zeroed after Hi(reject) * 3, not REJECT_AFTER_TIME * 3.
    assert_eq!(
        mine.timers.reject_after_time() * 3,
        Duration::from_secs(900)
    );
}

/// The persistent-keepalive interval is re-drawn from its range on every fire.
#[test]
#[cfg(feature = "mock_instant")]
fn persistent_keepalive_range_redrawn() {
    let (mut mine, mut theirs) = two_tuns();
    handshake(&mut mine, &mut theirs);
    mine.set_timer_extras(TimerExtras {
        persistent_keepalive: Some(secs(2, 9)),
        ..TimerExtras::default()
    });

    let mut intervals = Vec::new();
    let mut since_last = Duration::ZERO;
    let mut fired = 0;
    for _ in 0..200 {
        MockClock::advance(Duration::from_secs(1));
        since_last += Duration::from_secs(1);
        let interval = mine.timers.persistent_keepalive.expect("enabled");
        assert!(secs(2, 9).contains(&interval), "{interval:?} out of range");
        if let Ok(Some(WgKind::Data(_))) = mine.update_timers() {
            // The first keepalive is due immediately; later ones wait their interval.
            if fired > 0 {
                assert_eq!(since_last, interval);
            }
            fired += 1;
            since_last = Duration::ZERO;
            intervals.push(mine.timers.persistent_keepalive.expect("enabled"));
        }
    }
    assert!(fired > 20, "only {fired} keepalives");
    intervals.sort();
    intervals.dedup();
    assert!(
        intervals.len() > 1,
        "interval never re-drawn: {intervals:?}"
    );
}

/// A fixed interval set afterwards replaces the range: no more re-draws.
#[test]
fn fixed_keepalive_replaces_range() {
    let (mut mine, _theirs) = two_tuns();
    mine.set_timer_extras(TimerExtras {
        persistent_keepalive: Some(secs(2, 9)),
        ..TimerExtras::default()
    });
    assert!(mine.timers.persistent_keepalive.is_some());
    mine.set_persistent_keepalive(Some(25));
    assert_eq!(mine.timers.extras.persistent_keepalive, None);
    mine.amnezia_persistent_keepalive_fired();
    assert_eq!(mine.persistent_keepalive(), Some(25));

    // Removing a range that was set disables persistent keepalive.
    mine.set_timer_extras(TimerExtras {
        persistent_keepalive: Some(secs(2, 9)),
        ..TimerExtras::default()
    });
    mine.set_timer_extras(TimerExtras::default());
    assert_eq!(mine.persistent_keepalive(), None);
}

/// Unset AWG ranges change nothing: the mapped params are the defaults and the
/// derived thresholds are the WireGuard constants.
#[test]
fn unset_ranges_equal_upstream_defaults() {
    let unset = TimingRanges::default();
    assert_eq!(timer_params_from(&unset), TimerParams::default());
    assert_eq!(timer_extras_from(&unset), TimerExtras::default());

    let (mut mine, _theirs) = two_tuns();
    mine.set_timer_extras(timer_extras_from(&unset));
    mine.format_handshake_initiation(false).expect("init");
    assert_eq!(mine.timers.reject_after_time(), REJECT_AFTER_TIME);
    assert_eq!(mine.timers.rekey_attempt_time(), REKEY_ATTEMPT_TIME);
    assert_eq!(
        mine.timers.rekey_after_receive(),
        REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
    );
    assert_eq!(mine.timers.persistent_keepalive, None);
}
