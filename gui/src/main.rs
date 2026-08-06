// Copyright (C) 2026 Neil Luo
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program. If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! libadwaita front-end for pvpn.
//!
//! Deliberately a thin shell over the `pvpn` CLI rather than a
//! reimplementation. All the hard-won behaviour - restoring routing when a
//! connect fails, waiting out slow tunnels, steering server choice through
//! the client's cache - lives in one place, and both front-ends inherit it.
//!
//! Every command runs on a worker thread and reports back over an async
//! channel, because a connect can take tens of seconds and blocking the
//! main loop would freeze the window.

use std::process::Command;
use std::time::Duration;

use adw::prelude::*;
use gtk::glib;

const APP_ID: &str = "dev.pvpn.Gui";

/// Where setup.sh puts the CLI.
fn pvpn_bin() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    let local = format!("{home}/.local/bin/pvpn");
    if std::path::Path::new(&local).is_file() {
        local
    } else {
        "pvpn".to_string()
    }
}

fn scanner() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{home}/.local/share/pvpn/pvpn-scan.py")
}

#[derive(Debug, Clone, Default)]
struct Status {
    connected: bool,
    server: String,
    protocol: String,
}

fn read_status() -> Status {
    let mut st = Status::default();
    let Ok(out) = Command::new(pvpn_bin()).arg("status").output() else {
        return st;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("Status:") {
            // Must not match "Disconnected", which contains "connected".
            st.connected = v.trim().eq_ignore_ascii_case("connected");
        } else if let Some(v) = line.strip_prefix("Server:") {
            st.server = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Protocol:") {
            st.protocol = v.trim().to_string();
        }
    }
    st
}

#[derive(Debug, Clone)]
struct ServerRow {
    name: String,
    city: String,
    load: i64,
    ms: f64,
}

/// Ask the shared Python scanner for ranked results. Probing is the only
/// part of this that can be parallel; connecting cannot be.
fn scan(filter: &str) -> Result<Vec<ServerRow>, String> {
    let mut cmd = Command::new("/usr/bin/python3");
    cmd.arg(scanner());
    if !filter.trim().is_empty() {
        cmd.arg(filter.trim());
    }
    cmd.arg("--json");
    let out = cmd.output().map_err(|e| format!("cannot run scanner: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| format!("bad scanner output: {e}"))?;
    let arr = parsed.as_array().ok_or("scanner did not return a list")?;
    Ok(arr
        .iter()
        .map(|v| ServerRow {
            name: v["name"].as_str().unwrap_or("?").to_string(),
            city: v["city"].as_str().unwrap_or("?").to_string(),
            load: v["load"].as_i64().unwrap_or(-1),
            ms: v["ms"].as_f64().unwrap_or(0.0),
        })
        .collect())
}

fn run_pvpn(args: &[&str]) -> Result<String, String> {
    let out = Command::new(pvpn_bin())
        .args(args)
        .output()
        .map_err(|e| format!("cannot run pvpn: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if out.status.success() {
        Ok(stdout)
    } else {
        let msg = stderr.trim().to_string();
        Err(if msg.is_empty() {
            stdout.lines().last().unwrap_or("failed").to_string()
        } else {
            msg
        })
    }
}

/// What a worker thread sends back to the UI.
enum Msg {
    Status(Status),
    Scanned(Result<Vec<ServerRow>, String>),
    Done(Result<String, String>),
}

fn main() -> glib::ExitCode {
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    app.run()
}

fn build_ui(app: &adw::Application) {
    let (tx, rx) = async_channel::unbounded::<Msg>();

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("pvpn")
        .default_width(480)
        .default_height(700)
        .build();

    let header = adw::HeaderBar::new();
    let refresh = gtk::Button::from_icon_name("view-refresh-symbolic");
    refresh.set_tooltip_text(Some("Refresh status"));
    header.pack_start(&refresh);

    // --- status -------------------------------------------------------
    // NOT AdwStatusPage. That widget is designed to fill an empty page and
    // renders an enormous icon, which ate the top half of the window and
    // pushed the server name off-screen entirely. A single ActionRow says
    // the same thing in one line and leaves room for the list.
    let status_icon = gtk::Image::from_icon_name("network-vpn-disabled-symbolic");
    status_icon.set_pixel_size(32);

    let status_row = adw::ActionRow::new();
    status_row.set_title("Disconnected");
    status_row.set_subtitle("Not connected to Proton VPN");
    status_row.add_prefix(&status_icon);

    let status_group = adw::PreferencesGroup::new();
    status_group.add(&status_row);

    let connect_btn = gtk::Button::with_label("Connect");
    connect_btn.add_css_class("suggested-action");
    connect_btn.add_css_class("pill");

    // `pvpn up` ranks and picks the best server by itself, so this is
    // "connect to the fastest", with --rescan to ignore the cached ranking.
    let fastest_btn = gtk::Button::with_label("Fastest");
    fastest_btn.add_css_class("pill");
    fastest_btn.set_tooltip_text(Some(
        "Re-measure servers now and connect to the fastest one",
    ));

    let hop_btn = gtk::Button::with_label("Hop");
    hop_btn.add_css_class("pill");
    hop_btn.set_tooltip_text(Some("Switch to a different server"));

    let btn_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    btn_row.set_halign(gtk::Align::Center);
    btn_row.append(&connect_btn);
    btn_row.append(&fastest_btn);
    btn_row.append(&hop_btn);

    let spinner = gtk::Spinner::new();
    spinner.set_halign(gtk::Align::Center);

    let busy_label = gtk::Label::new(None);
    busy_label.add_css_class("dim-label");
    busy_label.set_halign(gtk::Align::Center);
    busy_label.set_justify(gtk::Justification::Center);
    busy_label.set_wrap(true);

    // --- server picker -------------------------------------------------
    let filter_row = adw::EntryRow::builder()
        .title("Filter - japan, tokyo, JP,SG, or a server name")
        .build();

    let scan_btn = gtk::Button::with_label("Scan");
    scan_btn.set_valign(gtk::Align::Center);
    scan_btn.set_tooltip_text(Some(
        "Probe servers in parallel and rank them by measured latency",
    ));
    filter_row.add_suffix(&scan_btn);

    let filter_group = adw::PreferencesGroup::new();
    filter_group.set_title("Servers");
    filter_group.set_description(Some(
        "Latency is a TLS handshake - comparable between servers, not a ping",
    ));
    filter_group.add(&filter_row);

    let results = gtk::ListBox::new();
    results.set_selection_mode(gtk::SelectionMode::None);
    results.add_css_class("boxed-list");

    let results_group = adw::PreferencesGroup::new();
    results_group.add(&results);

    // Only the server list scrolls. Previously the whole page was inside
    // the ScrolledWindow, so Connect/Fastest/Hop scrolled away as soon as a
    // scan returned more than a few servers - you had to scroll back up to
    // disconnect.
    let fixed_top = gtk::Box::new(gtk::Orientation::Vertical, 12);
    fixed_top.set_margin_top(12);
    fixed_top.set_margin_start(18);
    fixed_top.set_margin_end(18);
    fixed_top.append(&status_group);
    fixed_top.append(&btn_row);
    fixed_top.append(&spinner);
    fixed_top.append(&busy_label);
    fixed_top.append(&filter_group);

    let list_holder = gtk::Box::new(gtk::Orientation::Vertical, 0);
    list_holder.set_margin_top(12);
    list_holder.set_margin_bottom(18);
    list_holder.set_margin_start(18);
    list_holder.set_margin_end(18);
    list_holder.append(&results_group);

    let scroller = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&list_holder)
        .build();

    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    content.append(&fixed_top);
    content.append(&scroller);

    let toasts = adw::ToastOverlay::new();
    toasts.set_child(Some(&content));

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&toasts));
    window.set_content(Some(&toolbar));

    // --- behaviour ------------------------------------------------------
    // Controls are disabled while a command runs: a second connect while one
    // is in flight would fight over the same routing table.
    let set_busy = {
        let spinner = spinner.clone();
        let busy_label = busy_label.clone();
        let connect_btn = connect_btn.clone();
        let fastest_btn = fastest_btn.clone();
        let hop_btn = hop_btn.clone();
        let scan_btn = scan_btn.clone();
        move |busy: bool, what: &str| {
            spinner.set_spinning(busy);
            spinner.set_visible(busy);
            busy_label.set_visible(busy);
            busy_label.set_text(what);
            connect_btn.set_sensitive(!busy);
            fastest_btn.set_sensitive(!busy);
            hop_btn.set_sensitive(!busy);
            scan_btn.set_sensitive(!busy);
        }
    };
    set_busy(false, "");

    // Connect / Disconnect
    {
        let tx = tx.clone();
        let set_busy = set_busy.clone();
        let btn = connect_btn.clone();
        let filter_row_c = filter_row.clone();
        connect_btn.connect_clicked(move |_| {
            let disconnecting = btn.label().map(|l| l == "Disconnect").unwrap_or(false);
            let filter = filter_row_c.text().to_string();
            set_busy(
                true,
                if disconnecting {
                    "Disconnecting..."
                } else {
                    "Connecting - traffic moves into the tunnel before it is up,\nso this may stall briefly"
                },
            );
            let tx = tx.clone();
            std::thread::spawn(move || {
                let f = filter.trim().to_string();
                let r = if disconnecting {
                    run_pvpn(&["down"])
                } else if f.is_empty() {
                    run_pvpn(&["up"])
                } else {
                    run_pvpn(&["up", &f])
                };
                let _ = tx.send_blocking(Msg::Done(r));
            });
        });
    }

    // Fastest: force a fresh ranking, then connect to the winner.
    {
        let tx = tx.clone();
        let set_busy = set_busy.clone();
        let filter_row = filter_row.clone();
        fastest_btn.connect_clicked(move |_| {
            let filter = filter_row.text().to_string();
            set_busy(true, "Measuring servers, then connecting to the fastest...");
            let tx = tx.clone();
            std::thread::spawn(move || {
                let f = filter.trim().to_string();
                let r = if f.is_empty() {
                    run_pvpn(&["up", "--rescan"])
                } else {
                    run_pvpn(&["up", &f, "--rescan"])
                };
                let _ = tx.send_blocking(Msg::Done(r));
            });
        });
    }

    // Hop, honouring the filter box if it has anything in it
    {
        let tx = tx.clone();
        let set_busy = set_busy.clone();
        let filter_row = filter_row.clone();
        hop_btn.connect_clicked(move |_| {
            let filter = filter_row.text().to_string();
            set_busy(true, "Switching server...");
            let tx = tx.clone();
            std::thread::spawn(move || {
                let f = filter.trim().to_string();
                let r = if f.is_empty() {
                    run_pvpn(&["hop"])
                } else {
                    run_pvpn(&["hop", &f])
                };
                let _ = tx.send_blocking(Msg::Done(r));
            });
        });
    }

    // Scan
    {
        let tx = tx.clone();
        let set_busy = set_busy.clone();
        let filter_row = filter_row.clone();
        scan_btn.connect_clicked(move |_| {
            let filter = filter_row.text().to_string();
            set_busy(true, "Probing servers in parallel...");
            let tx = tx.clone();
            std::thread::spawn(move || {
                let _ = tx.send_blocking(Msg::Scanned(scan(&filter)));
            });
        });
    }

    // Refresh
    {
        let tx = tx.clone();
        refresh.connect_clicked(move |_| {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let _ = tx.send_blocking(Msg::Status(read_status()));
            });
        });
    }

    // --- message pump ----------------------------------------------------
    {
        let status_row = status_row.clone();
        let status_icon = status_icon.clone();
        let connect_btn = connect_btn.clone();
        let hop_btn = hop_btn.clone();
        let fastest_btn = fastest_btn.clone();
        let results = results.clone();
        let toasts = toasts.clone();
        let set_busy = set_busy.clone();
        let tx_inner = tx.clone();

        glib::spawn_future_local(async move {
            while let Ok(msg) = rx.recv().await {
                match msg {
                    Msg::Status(st) => {
                        if st.connected {
                            status_icon.set_icon_name(Some("network-vpn-symbolic"));
                            status_row.set_title("Connected");
                            // One line, not two: the server and protocol on
                            // a single subtitle keeps the row compact.
                            let sub = if st.protocol.is_empty() {
                                st.server.clone()
                            } else {
                                format!("{}  •  {}", st.server, st.protocol)
                            };
                            status_row.set_subtitle(&sub);
                            connect_btn.set_label("Disconnect");
                            connect_btn.remove_css_class("suggested-action");
                            connect_btn.add_css_class("destructive-action");
                            hop_btn.set_sensitive(true);
                            fastest_btn.set_sensitive(true);
                        } else {
                            status_icon.set_icon_name(Some("network-vpn-disabled-symbolic"));
                            status_row.set_title("Disconnected");
                            status_row.set_subtitle("Not connected to Proton VPN");
                            connect_btn.set_label("Connect");
                            connect_btn.remove_css_class("destructive-action");
                            connect_btn.add_css_class("suggested-action");
                            // Hop is meaningless with no tunnel to hop from.
                            hop_btn.set_sensitive(false);
                        }
                        set_busy(false, "");
                    }

                    Msg::Done(res) => {
                        match res {
                            Ok(out) => {
                                let last = out
                                    .lines()
                                    .rev()
                                    .find(|l| !l.trim().is_empty())
                                    .unwrap_or("Done");
                                toasts.add_toast(adw::Toast::new(last.trim()));
                            }
                            Err(e) => {
                                let t = adw::Toast::new(&format!("Failed: {e}"));
                                t.set_timeout(6);
                                toasts.add_toast(t);
                            }
                        }
                        // Whatever happened, re-read the truth rather than
                        // assuming the command did what it claimed.
                        let tx2 = tx_inner.clone();
                        std::thread::spawn(move || {
                            let _ = tx2.send_blocking(Msg::Status(read_status()));
                        });
                    }

                    Msg::Scanned(res) => {
                        while let Some(child) = results.first_child() {
                            results.remove(&child);
                        }
                        match res {
                            Ok(rows) if !rows.is_empty() => {
                                for r in rows.iter().take(15) {
                                    let row = adw::ActionRow::new();
                                    row.set_title(&r.name);
                                    let load = if r.load >= 0 {
                                        format!("{}% load", r.load)
                                    } else {
                                        "load ?".to_string()
                                    };
                                    row.set_subtitle(&format!(
                                        "{} - {:.0} ms - {}",
                                        r.city, r.ms, load
                                    ));

                                    let go = gtk::Button::with_label("Connect");
                                    go.set_valign(gtk::Align::Center);
                                    let name = r.name.clone();
                                    let set_busy2 = set_busy.clone();
                                    let tx2 = tx_inner.clone();
                                    go.connect_clicked(move |_| {
                                        set_busy2(true, &format!("Connecting to {name}..."));
                                        let name = name.clone();
                                        let tx2 = tx2.clone();
                                        std::thread::spawn(move || {
                                            let r = run_pvpn(&["hop", &name]);
                                            let _ = tx2.send_blocking(Msg::Done(r));
                                        });
                                    });
                                    row.add_suffix(&go);
                                    results.append(&row);
                                }
                            }
                            Ok(_) => {
                                toasts.add_toast(adw::Toast::new("No servers matched"));
                            }
                            Err(e) => {
                                let t = adw::Toast::new(&format!("Scan failed: {e}"));
                                t.set_timeout(6);
                                toasts.add_toast(t);
                            }
                        }
                        set_busy(false, "");
                    }
                }
            }
        });
    }

    // Poll, so the window also reflects changes made from the CLI.
    {
        let tx = tx.clone();
        glib::timeout_add_local(Duration::from_secs(10), move || {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let _ = tx.send_blocking(Msg::Status(read_status()));
            });
            glib::ControlFlow::Continue
        });
    }

    // Initial read.
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send_blocking(Msg::Status(read_status()));
        });
    }

    window.present();
}
