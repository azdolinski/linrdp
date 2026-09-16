//! Multi-session support: per-user desktops with Windows RDP semantics.
//!
//! See `docs/superpowers/specs/2026-09-16-multi-session-design.md`.

pub(crate) mod display_alloc;
pub(crate) mod pam_session;
pub(crate) mod privilege;
pub(crate) mod runtime_dir;
