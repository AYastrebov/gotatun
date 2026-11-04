use std::time::SystemTime;

use super::TimeStamper;

/// Kernel WireGuard and wireguard-go/amneziawg-go stamp handshakes with
/// TAI64N base `2^62 + 10` (Unix seconds + 10). A larger base makes the
/// next handshake from a kernel/Go peer using the same key look like a
/// replay until the clocks catch up.
#[test]
fn timestamp_epoch_matches_kernel() {
    const KERNEL_TAI64_BASE: u64 = 0x4000_0000_0000_000a;
    let unix_before = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let stamp = TimeStamper::new().stamp();
    let unix_after = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let secs = u64::from_be_bytes(stamp[..8].try_into().unwrap());
    let unix = secs.wrapping_sub(KERNEL_TAI64_BASE);
    assert!(
        (unix_before..=unix_after).contains(&unix),
        "stamp {secs:#x} decodes to Unix {unix}, expected {unix_before}..={unix_after}"
    );
}
