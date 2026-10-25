//! omakeepickd: the helper daemon of the OmaKeePick Omarchy shell plugin.
//! See `docs/PROTOCOL.md` for the protocol spoken over its socket.

pub mod autotype;
pub mod client;
pub mod clipboard;
pub mod config;
pub mod daemon;
pub mod harden;
pub mod locker;
pub mod paths;
pub mod portal;
pub mod protocol;
pub mod quickunlock;
pub mod search;
pub mod server;
pub mod state;
pub mod totp;
pub mod vault;
pub mod watch;
