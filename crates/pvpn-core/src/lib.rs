//! Shared ground between `pvpn` (the CLI) and `pvpnd` (the daemon).
//!
//! WHY THIS CRATE EXISTS
//!
//! The two front-ends have to agree about four things: where files live,
//! what the config says, what the user last asked for, and what
//! NetworkManager is currently doing. Every serious bug this project has
//! shipped came from them disagreeing about one of those.
//!
//! Twice now:
//!
//!   1. The daemon sampled NM's connection list to decide what the user
//!      wanted, landed in the gap between `pvpn down` writing intent and
//!      NM finishing the teardown, and put the tunnel back up.
//!
//!   2. The daemon subscribed to the right D-Bus signal but not the right
//!      SENDER, so the wifi re-activating after a teardown looked exactly
//!      like the user switching the VPN on, and it put the tunnel back up
//!      again.
//!
//! Both were one component guessing at another's state. So the rule here
//! is that intent is WRITTEN, never inferred, and there is exactly one
//! implementation of reading and writing it - this one.

pub mod config;
pub mod dbus;
pub mod intent;
pub mod learn;
pub mod net;
pub mod nm;
pub mod paths;
pub mod probe;
pub mod proton;
pub mod state;
pub mod tls;

pub use intent::Intent;
pub use nm::{Ev, Sig};
pub use learn::{NetworkMemory, ServerRecord};
pub use state::DaemonState;
