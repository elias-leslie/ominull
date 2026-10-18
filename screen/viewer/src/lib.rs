//! OmniNull remote screen viewer (REMOTE_SCREEN.md §9): the window, the
//! headless `ctl` commands, and the console link launcher.

pub mod ctl;
pub mod draw;
pub mod geometry;
pub mod grab;
pub mod handshake;
pub mod input;
pub mod keymap;
pub mod launch;
pub mod net;
pub mod session;
pub mod ui;
