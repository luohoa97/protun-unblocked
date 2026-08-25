//! Where everything lives.
//!
//! Every path the CLI and the daemon share is defined here exactly once.
//! When these were duplicated between a bash script and a Rust daemon,
//! "the daemon reads a different file than the CLI writes" was a bug
//! waiting to happen rather than a hypothetical.

use std::path::PathBuf;

/// `$HOME`, or `/tmp` if the environment is too broken to have one.
///
/// Falling back rather than panicking is deliberate: a daemon that dies on
/// a missing env var during early boot is worse than one that operates on
/// a useless path and says so.
pub fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
}

/// `$XDG_RUNTIME_DIR`, or `/tmp`.
///
/// Anything here is ephemeral BY DESIGN. A state file that survived a
/// reboot claiming a tunnel was up, or a busy marker that outlived the
/// process that made it, would silence the daemon at exactly the wrong
/// moment.
pub fn runtime_dir() -> PathBuf {
    PathBuf::from(std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into()))
}

/// `~/.config/pvpn` - user settings and intent. Survives reboots.
pub fn config_dir() -> PathBuf {
    home().join(".config/pvpn")
}

/// `~/.local/share/pvpn` - things learned about networks. Survives reboots.
pub fn data_dir() -> PathBuf {
    home().join(".local/share/pvpn")
}

/// `KEY=value` settings, shared verbatim with the shell front-end.
pub fn config_file() -> PathBuf {
    config_dir().join("config")
}

/// What the user last asked for: the single word `up` or `down`.
pub fn intent_file() -> PathBuf {
    config_dir().join("intent")
}

/// The daemon's view of the world, as JSON, for the GUI and `pvpn status`.
pub fn state_file() -> PathBuf {
    runtime_dir().join("pvpnd.state")
}

/// Dropped by `pvpn` for the length of any operation that touches the
/// tunnel. While it exists, the daemon does not judge what NM is doing.
pub fn busy_file() -> PathBuf {
    runtime_dir().join("pvpn.busy")
}

/// Prefer a user-local `pvpn` over one on `$PATH`, so a development build
/// in `~/.local/bin` wins over whatever the image shipped.
pub fn pvpn_bin() -> String {
    let local = home().join(".local/bin/pvpn");
    if local.is_file() {
        local.to_string_lossy().into_owned()
    } else {
        "pvpn".into()
    }
}

/// Write a file so that no reader can ever see it half-written.
///
/// Temp-then-rename, because `rename(2)` within a filesystem is atomic.
/// Both files this is used for are read by another process on a timer, so
/// a torn read is not a theoretical concern: an empty `intent` parses as
/// "never said", which the daemon correctly treats as "leave me alone" -
/// meaning a torn write would silently disarm it.
pub fn write_atomic(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_paths_are_under_the_runtime_dir() {
        // Not a tautology: putting either of these under $HOME would mean a
        // stale marker survived a reboot, which is a real bug we avoid by
        // construction rather than by remembering.
        let rt = runtime_dir();
        assert!(state_file().starts_with(&rt));
        assert!(busy_file().starts_with(&rt));
    }

    #[test]
    fn config_paths_survive_reboots() {
        let cfg = config_dir();
        assert!(intent_file().starts_with(&cfg));
        assert!(config_file().starts_with(&cfg));
    }

    #[test]
    fn write_atomic_leaves_no_temp_behind() {
        let dir = std::env::temp_dir().join(format!("pvpn-core-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let target = dir.join("intent");
        write_atomic(&target, "up\n").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "up\n");
        assert!(!target.with_extension("tmp").exists());
        // Overwriting must also be clean.
        write_atomic(&target, "down\n").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "down\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
