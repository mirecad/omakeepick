//! omakeepickd: the helper daemon of the OmaKeePick Omarchy shell plugin.
//! See `docs/PROTOCOL.md` for the protocol spoken over its socket.

pub mod autotype;
pub mod client;
pub mod clipboard;
pub mod config;
pub mod daemon;
pub mod harden;
pub mod inflight;
pub mod locker;
pub mod memory;
pub mod opener;
pub mod paths;
pub mod portal;
pub mod protocol;
pub mod quickunlock;
pub mod search;
pub mod server;
pub mod state;
pub mod tool;
pub mod totp;
pub mod vault;
pub mod watch;

/// See `memory`: the system allocator, except in a helper that ran into its limit.
#[global_allocator]
static ALLOCATOR: memory::Limited = memory::Limited;
