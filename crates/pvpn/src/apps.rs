//! `pvpn apps` — Flatpak apps that quietly skip the tunnel.
//!
//! The problem, and it is a nasty one because nothing else shows it: a
//! Flatpak override can set `http_proxy` (or friends) for one app. That app
//! then sends its traffic to the proxy instead of down the default route,
//! so it leaves the machine outside the tunnel while `pvpn status` — which
//! looks at routing — correctly reports a healthy VPN. The VPN *is*
//! healthy. The app simply is not using it.
//!
//! Overrides survive app updates and reboots, and nothing surfaces them, so
//! one experiment with a proxy a year ago is still leaking today.
//!
//! The idea of checking for this comes from
//! dixonSolutions/protun-unblocked (MIT). See NOTICE.md.
//!
//! WHAT THIS DELIBERATELY DOES NOT DO
//!
//! It does not start your applications to check where they exit. That is
//! the only way to be *certain*, and it is far too invasive for a command
//! people will run casually — launching a browser and a chat client to
//! answer a diagnostic question is not a reasonable trade. Reading the
//! overrides is enough to find the cause, which is what you actually need.

use std::process::Command;

use anyhow::Result;

/// Environment variables that take an app off the default route.
///
/// `no_proxy` is deliberately absent: it *narrows* proxying, so its
/// presence is not a leak.
const PROXY_VARS: &[&str] = &[
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "ftp_proxy",
    "socks_proxy",
];

#[derive(Debug, Clone)]
pub struct Offender {
    pub app: String,
    /// `(variable, value)` pairs that route the app elsewhere.
    pub vars: Vec<(String, String)>,
}

pub fn cmd_apps(fix: bool, json: bool) -> Result<u8> {
    if which("flatpak").is_none() {
        if json {
            println!("{}", serde_json::json!({"flatpak": false, "offenders": []}));
        } else {
            println!("flatpak is not installed - nothing to check.");
        }
        return Ok(0);
    }

    let apps = installed_apps();
    let mut offenders = Vec::new();
    for app in &apps {
        let overrides = show_overrides(app);
        let vars = proxy_vars_in(&overrides);
        if !vars.is_empty() {
            offenders.push(Offender {
                app: app.clone(),
                vars,
            });
        }
    }

    if json {
        let out = serde_json::json!({
            "flatpak": true,
            "checked": apps.len(),
            "offenders": offenders.iter().map(|o| serde_json::json!({
                "app": o.app,
                "vars": o.vars.iter().map(|(k, v)| serde_json::json!({"name": k, "value": v}))
                          .collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        if fix {
            for o in &offenders {
                unset_all(o);
            }
        }
        return Ok(if offenders.is_empty() { 0 } else { 2 });
    }

    if offenders.is_empty() {
        println!("All {} Flatpak apps are on the tunnel.", apps.len());
        return Ok(0);
    }

    println!(
        "{} of {} Flatpak apps route around the tunnel:\n",
        offenders.len(),
        apps.len()
    );
    for o in &offenders {
        println!("  {}", o.app);
        for (k, v) in &o.vars {
            println!("      {k}={v}");
        }
    }

    if !fix {
        println!();
        println!("These send traffic to a proxy instead of down the VPN route.");
        println!("`pvpn status` cannot see this: the tunnel is fine, the app is not using it.");
        println!();
        println!("Fix with:  pvpn apps --fix");
        return Ok(2);
    }

    println!();
    for o in &offenders {
        match unset_all(o) {
            true => println!("  fixed  {}", o.app),
            false => println!("  FAILED {} - try: flatpak override --user --reset {}", o.app, o.app),
        }
    }
    println!();
    println!("Restart those apps for the change to take effect.");
    Ok(0)
}

fn unset_all(o: &Offender) -> bool {
    let mut all_ok = true;
    for (k, _) in &o.vars {
        let ok = Command::new("flatpak")
            .args([
                "override",
                "--user",
                &format!("--unset-env={k}"),
                &o.app,
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        all_ok &= ok;
    }
    all_ok
}

fn installed_apps() -> Vec<String> {
    let Ok(out) = Command::new("flatpak")
        .args(["list", "--app", "--columns=application"])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && l.contains('.'))
        .map(|s| s.to_string())
        .collect()
}

fn show_overrides(app: &str) -> String {
    Command::new("flatpak")
        .args(["override", "--user", "--show", app])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Pull proxy assignments out of `flatpak override --show` output.
///
/// The format is INI-ish:
///
///     [Environment]
///     http_proxy=http://10.0.0.1:8080
///
/// Parsed by splitting on the first `=` inside the `[Environment]` section
/// rather than by scanning the whole file, so a *context* key that merely
/// mentions a proxy name is not mistaken for one being set.
pub fn proxy_vars_in(overrides: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut in_env = false;
    for line in overrides.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_env = line.eq_ignore_ascii_case("[Environment]");
            continue;
        }
        if !in_env || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        // An empty value is an override that *unsets* the variable, which
        // is the fix, not the problem.
        if v.is_empty() {
            continue;
        }
        if PROXY_VARS.contains(&k) {
            found.push((k.to_string(), v.to_string()));
        }
    }
    found
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_proxy_variables_in_the_environment_section() {
        let text = "[Context]\nsockets=wayland\n\n[Environment]\nhttp_proxy=http://10.0.0.1:8080\nLANG=en_AU\n";
        let found = proxy_vars_in(text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "http_proxy");
        assert_eq!(found[0].1, "http://10.0.0.1:8080");
    }

    /// A key outside [Environment] that merely mentions a proxy must not be
    /// reported — a false positive here sends someone hunting a leak that
    /// does not exist.
    #[test]
    fn ignores_proxy_looking_keys_outside_the_environment_section() {
        let text = "[Context]\nhttp_proxy=something\n";
        assert!(proxy_vars_in(text).is_empty());
    }

    /// An empty value is an override that UNSETS the variable. That is the
    /// fix, so reporting it as the problem would make `--fix` look broken
    /// by leaving its own work behind as a finding.
    #[test]
    fn an_empty_value_is_a_fix_not_a_leak() {
        let text = "[Environment]\nhttp_proxy=\n";
        assert!(proxy_vars_in(text).is_empty());
    }

    /// no_proxy narrows proxying rather than causing it.
    #[test]
    fn no_proxy_is_not_a_leak() {
        let text = "[Environment]\nno_proxy=localhost\n";
        assert!(proxy_vars_in(text).is_empty());
    }

    #[test]
    fn catches_both_cases_and_socks() {
        let text = "[Environment]\nHTTPS_PROXY=http://x\nall_proxy=socks5://y\n";
        let found = proxy_vars_in(text);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn empty_or_malformed_input_yields_nothing() {
        assert!(proxy_vars_in("").is_empty());
        assert!(proxy_vars_in("garbage without sections").is_empty());
        assert!(proxy_vars_in("[Environment]\nno equals sign here\n").is_empty());
    }
}
