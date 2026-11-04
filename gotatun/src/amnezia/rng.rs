//! Injectable randomness for AmneziaWG packet generation.

use std::cell::RefCell;
#[cfg(unix)]
use std::sync::Once;
use std::sync::atomic::{AtomicUsize, Ordering};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::TryRngCore;
use rand::rngs::OsRng;

/// A source of random bytes and bounded integers.
pub(crate) trait RandomSource {
    /// Fill `buf` with random bytes.
    fn fill(&mut self, buf: &mut [u8]);

    /// A uniform value in `[lo, hi_inclusive]`. An inverted range yields `lo`.
    fn range_u32(&mut self, lo: u32, hi_inclusive: u32) -> u32 {
        if lo >= hi_inclusive {
            return lo;
        }
        let mut buf = [0u8; 4];
        self.fill(&mut buf);
        let raw = u32::from_le_bytes(buf);
        match (hi_inclusive - lo).checked_add(1) {
            Some(span) => lo + raw % span,
            // Full `u32` span: every value is in range.
            None => raw,
        }
    }
}

/// Random source backed by the OS CSPRNG (one syscall per draw).
#[derive(Debug, Clone, Copy)]
pub(crate) struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, buf: &mut [u8]) {
        OsRng.try_fill_bytes(buf).expect("OS RNG failure");
    }
}

/// Buffered per-thread ChaCha20 keystream seeded from the OS.
///
/// Far cheaper per draw than [`OsRandom`]. Use it for wire filler (padding,
/// junk, CPS random tags, header values); keep [`OsRandom`] for long-lived
/// secrets. A `fork` copies the buffer, so each thread discards its state when
/// a `pthread_atfork` child handler bumps [`FORK_GENERATION`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct FastRandom;

/// Incremented in the child after `fork`; only touches an atomic, so it is
/// async-signal-safe.
static FORK_GENERATION: AtomicUsize = AtomicUsize::new(0);

#[cfg(unix)]
extern "C" fn note_fork() {
    FORK_GENERATION.fetch_add(1, Ordering::Relaxed);
}

const FAST_RNG_BUFFER_SIZE: usize = 256;
/// Reseed from the OS after this many bytes (hygiene, not necessity).
const FAST_RNG_RESEED_INTERVAL: usize = 1 << 20;

struct FastRngState {
    key: [u8; 32],
    block: u64,
    buffer: [u8; FAST_RNG_BUFFER_SIZE],
    used: usize,
    since_reseed: usize,
    generation: usize,
}

impl FastRngState {
    fn new() -> Self {
        #[cfg(unix)]
        {
            static REGISTER: Once = Once::new();
            REGISTER.call_once(|| {
                // SAFETY: `note_fork` only does a relaxed atomic increment,
                // which is async-signal-safe as required of child handlers.
                unsafe {
                    libc::pthread_atfork(None, None, Some(note_fork));
                }
            });
        }

        let mut state = FastRngState {
            key: [0u8; 32],
            block: 0,
            buffer: [0u8; FAST_RNG_BUFFER_SIZE],
            used: FAST_RNG_BUFFER_SIZE,
            since_reseed: FAST_RNG_RESEED_INTERVAL,
            generation: 0,
        };
        state.reseed();
        state
    }

    fn reseed(&mut self) {
        OsRng.try_fill_bytes(&mut self.key).expect("OS RNG failure");
        self.block = 0;
        self.since_reseed = 0;
        self.generation = FORK_GENERATION.load(Ordering::Relaxed);
        self.used = FAST_RNG_BUFFER_SIZE;
    }

    fn refill(&mut self) {
        if self.since_reseed >= FAST_RNG_RESEED_INTERVAL {
            self.reseed();
        }
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.block.to_le_bytes());
        self.block += 1;

        self.buffer = [0u8; FAST_RNG_BUFFER_SIZE];
        let mut cipher = ChaCha20::new((&self.key).into(), (&nonce).into());
        cipher.apply_keystream(&mut self.buffer);
        self.used = 0;
        self.since_reseed += FAST_RNG_BUFFER_SIZE;
    }

    fn fill(&mut self, out: &mut [u8]) {
        // Checked per draw: a forked child still holds unconsumed parent bytes.
        if self.generation != FORK_GENERATION.load(Ordering::Relaxed) {
            self.reseed();
        }
        let mut written = 0;
        while written < out.len() {
            if self.used == FAST_RNG_BUFFER_SIZE {
                self.refill();
            }
            let take = (out.len() - written).min(FAST_RNG_BUFFER_SIZE - self.used);
            out[written..written + take].copy_from_slice(&self.buffer[self.used..self.used + take]);
            self.used += take;
            written += take;
        }
    }
}

thread_local! {
    static FAST_RNG: RefCell<FastRngState> = RefCell::new(FastRngState::new());
}

impl RandomSource for FastRandom {
    fn fill(&mut self, buf: &mut [u8]) {
        FAST_RNG.with(|state| state.borrow_mut().fill(buf));
    }
}

/// Deterministic source for tests.
#[cfg(test)]
pub(crate) struct DetRng(rand_chacha::ChaCha8Rng);

#[cfg(test)]
impl DetRng {
    pub(crate) fn new(seed: u8) -> Self {
        use rand::SeedableRng;
        DetRng(rand_chacha::ChaCha8Rng::from_seed([seed; 32]))
    }
}

#[cfg(test)]
impl RandomSource for DetRng {
    fn fill(&mut self, buf: &mut [u8]) {
        use rand::RngCore;
        self.0.fill_bytes(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_random_does_not_repeat_within_a_thread() {
        let mut a = vec![0u8; FAST_RNG_BUFFER_SIZE * 3];
        let mut b = vec![0u8; FAST_RNG_BUFFER_SIZE * 3];
        FastRandom.fill(&mut a);
        FastRandom.fill(&mut b);
        assert_ne!(a, b);
        let block = &a[..FAST_RNG_BUFFER_SIZE];
        assert_ne!(block, &a[FAST_RNG_BUFFER_SIZE..FAST_RNG_BUFFER_SIZE * 2]);
        assert_ne!(block, &a[FAST_RNG_BUFFER_SIZE * 2..]);
    }

    #[test]
    fn range_u32_is_inclusive_and_handles_full_span() {
        let mut rng = DetRng::new(1);
        let mut seen = [false; 3];
        for _ in 0..200 {
            seen[rng.range_u32(5, 7) as usize - 5] = true;
        }
        assert_eq!(seen, [true; 3]);
        assert_eq!(rng.range_u32(9, 9), 9);
        assert_eq!(rng.range_u32(9, 3), 9);
        let _ = rng.range_u32(0, u32::MAX);
    }

    #[test]
    fn os_random_fills() {
        let mut a = [0u8; 32];
        OsRandom.fill(&mut a);
        assert_ne!(a, [0u8; 32]);
    }

    /// `fork` copies the buffer; the child must not replay the parent's bytes.
    #[cfg(unix)]
    #[test]
    fn fast_random_regenerates_after_fork() {
        const N: usize = 64;
        let mut primer = [0u8; 16];
        FastRandom.fill(&mut primer);

        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (read_fd, write_fd) = (fds[0], fds[1]);

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let mut child = [0u8; N];
            FastRandom.fill(&mut child);
            unsafe {
                libc::write(write_fd, child.as_ptr().cast(), N);
                libc::_exit(0);
            }
        }

        let mut parent = [0u8; N];
        FastRandom.fill(&mut parent);

        unsafe { libc::close(write_fd) };
        let mut child = [0u8; N];
        let mut total = 0;
        while total < N {
            let n = unsafe { libc::read(read_fd, child.as_mut_ptr().add(total).cast(), N - total) };
            assert!(n > 0, "short read from child");
            total += n as usize;
        }
        unsafe {
            libc::close(read_fd);
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
        }
        assert_ne!(
            parent, child,
            "parent and child emitted identical bytes after fork"
        );
    }
}
