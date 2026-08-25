//! What the user last asked for.
//!
//! This is the most important file in the project, and it is deliberately
//! the dullest. Two shipped bugs came from the daemon *inferring* intent
//! instead of reading it, so the whole design is: intent is a word in a
//! file, written only when a human asks for something, and every component
//! reads it through this one implementation.
//!
//! Absent means "never said", which is treated as "leave me alone" rather
//! than as a default of up or down. A daemon that assumes on a missing file
//! is a daemon that acts on a fresh install before you have asked it for
//! anything.

use std::time::{Duration, SystemTime};

use crate::paths;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum Intent {
    Up,
    Down,
    /// No file, or a file we cannot make sense of.
    Unset,
}

impl Intent {
    pub fn as_str(self) -> &'static str {
        match self {
            Intent::Up => "up",
            Intent::Down => "down",
            Intent::Unset => "unset",
        }
    }
}

/// Read intent. Anything unrecognised is `Unset`, never a guess.
pub fn read() -> Intent {
    match std::fs::read_to_string(paths::intent_file()) {
        Ok(s) => match s.trim() {
            "up" => Intent::Up,
            "down" => Intent::Down,
            _ => Intent::Unset,
        },
        Err(_) => Intent::Unset,
    }
}

/// Record intent.
///
/// `Unset` is not writable on purpose: "the user never said" is a state you
/// arrive at by having no file, not one any component may put the system
/// into. Being able to write it would give a caller a way to erase an
/// instruction, which is exactly what must not be possible here.
pub fn write(i: Intent) -> std::io::Result<()> {
    let word = match i {
        Intent::Up => "up",
        Intent::Down => "down",
        Intent::Unset => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to write Intent::Unset: absence is not an instruction",
            ))
        }
    };
    paths::write_atomic(&paths::intent_file(), &format!("{word}\n"))
}

/// How long `pvpn`'s busy marker is honoured before it is treated as stale.
///
/// Two minutes: comfortably longer than the slowest measured connect (41s)
/// and far shorter than "until you reboot". A crashed `pvpn` must not
/// silence the daemon permanently.
const BUSY_TTL: Duration = Duration::from_secs(120);

/// Is `pvpn` itself mid-operation right now?
///
/// During a connect there is a real window where NetworkManager shows no
/// VPN at all: the old tunnel is gone and the new one has not arrived. Read
/// naively that is indistinguishable from the user switching the VPN off,
/// and the daemon would stand down halfway through the user's own
/// `pvpn up`. `pvpn` drops a marker for the length of any operation that
/// touches the tunnel, and NM is not judged while it is there.
///
/// NOTE: this closes the window *during* an operation only. It cannot close
/// the window *after* one, because the marker is cleared when `pvpn` exits
/// and NetworkManager finishes its teardown after that. Relying on it for
/// the after case is precisely the bug that made `pvpn down` bounce back.
/// The signal path handles that, not this.
pub fn pvpn_is_busy() -> bool {
    let path = paths::busy_file();
    let Ok(meta) = std::fs::metadata(&path) else {
        return false;
    };
    match meta.modified().ok().and_then(|t| t.elapsed().ok()) {
        Some(age) => age < BUSY_TTL,
        // A modification time in the future (clock skew, or a resumed
        // laptop) yields an Err from elapsed(). Treat that as busy: the
        // marker exists, and honouring it briefly is safer than ignoring a
        // real one.
        None => true,
    }
}

/// Claim the busy marker for the duration of an operation.
///
/// Returns a guard that clears it on drop, including on panic and on an
/// early `?` return - which is the point. Every path that took the marker
/// by hand had to remember to release it on every exit, and that is the
/// kind of thing that is right until it is not.
#[must_use = "the marker is released as soon as this guard is dropped"]
pub struct BusyGuard(());

impl BusyGuard {
    pub fn acquire() -> Self {
        let path = paths::busy_file();
        let stamp = format!("{}\n", std::process::id());
        let _ = paths::write_atomic(&path, &stamp);
        BusyGuard(())
    }

    /// Refresh the marker, for an operation legitimately longer than
    /// `BUSY_TTL`.
    pub fn touch(&self) {
        let path = paths::busy_file();
        let stamp = format!("{}\n", std::process::id());
        let _ = paths::write_atomic(&path, &stamp);
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(paths::busy_file());
    }
}

/// Seconds since the epoch, saturating rather than panicking on a clock
/// before 1970.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Absence must not be writable. If a component could write "unset" it
    /// could erase an instruction the user gave, which is the failure mode
    /// this whole module exists to prevent.
    #[test]
    fn unset_cannot_be_written() {
        let err = write(Intent::Unset).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn intent_words_are_stable() {
        // These strings are a wire format shared with the shell front-end
        // and the GUI. Changing one silently desynchronises them.
        assert_eq!(Intent::Up.as_str(), "up");
        assert_eq!(Intent::Down.as_str(), "down");
        assert_eq!(Intent::Unset.as_str(), "unset");
    }

    #[test]
    fn busy_guard_releases_on_drop() {
        let dir = std::env::temp_dir().join(format!("pvpn-busy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &dir);

        assert!(!pvpn_is_busy());
        {
            let _g = BusyGuard::acquire();
            assert!(pvpn_is_busy(), "marker must be visible while held");
        }
        assert!(!pvpn_is_busy(), "marker must be gone once the guard drops");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
