//! The capture + input seam (`REMOTE_SCREEN.md` §6.0). The session loop, the
//! wire protocol, and the framing know nothing about Win32: they talk to this
//! trait. The Windows DXGI/GDI backend implements it now; the Linux primary path
//! (root DRM/KMS capture + uinput injection, §10) implements the same trait
//! later without touching the loop, the protocol, or the framing.
//!
//! This file is pure (no Win32), so the session loop is unit-tested on the host
//! against a mock backend.

use screen_wire::input::InputEvent;

/// 256x256 tile grid (§4.3). Dirty rects snap to this grid.
pub const TILE_SIZE: u32 = 256;

/// A connected display, in pre-rotation desktop pixels (§4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Monitor {
    pub id: u32,
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
    pub primary: bool,
}

/// One encoded tile: monitor-relative pixel rect plus the JPEG bytes (§4.1).
#[derive(Clone, Debug)]
pub struct Tile {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
    pub keyframe: bool,
    pub jpeg: Vec<u8>,
}

/// A cursor shape read from `GetFramePointerShape` (§4.1). The cursor is never
/// baked into the image; the viewer composites it.
#[derive(Clone, Debug)]
pub struct CursorShape {
    pub w: u16,
    pub h: u16,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    /// `wire::CURSOR_FORMAT_*`.
    pub format: u8,
    pub pixels: Vec<u8>,
}

/// Cursor position/visibility, monitor-relative pixels (§4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorPos {
    pub x: i32,
    pub y: i32,
    pub visible: bool,
}

/// Which input desktop capture is on (§4.1). `name` is "user" | "lock" |
/// "secure"; `signed_in` from the WTS session state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesktopState {
    pub name: String,
    pub signed_in: bool,
}

/// What one `capture()` produced. Any field may be empty: a timeout yields
/// nothing; a cursor-only update (`AccumulatedFrames == 0`) yields only cursor
/// fields; a desktop/mode change yields `geometry_change`.
#[derive(Clone, Debug, Default)]
pub struct CaptureFrame {
    pub tiles: Vec<Tile>,
    pub cursor_shape: Option<CursorShape>,
    pub cursor_pos: Option<CursorPos>,
    pub geometry_change: Option<Vec<Monitor>>,
    /// Set when the input desktop changed since the last capture (§4.1); the
    /// session emits a `desktop` frame and re-asserts the banner.
    pub desktop_change: Option<DesktopState>,
}

/// Result of the local "ask the person first" consent prompt (§7). Shown on the
/// endpoint before the session goes active when the per-machine `ask_first`
/// setting is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consent {
    Allowed,
    Denied,
}

/// Capture + input, behind one trait so protocol/loop/framing stay OS-agnostic.
pub trait ScreenBackend {
    /// The current monitor list.
    fn monitors(&self) -> Vec<Monitor>;

    /// Switch the captured monitor. Returns false for an out-of-range index.
    /// The next `capture()` must return a keyframe of the new monitor.
    fn set_active_monitor(&mut self, index: u32) -> bool;

    /// Clamp and apply the JPEG quality (§4.3: 30..=85).
    fn set_quality(&mut self, jpeg_q: u8);

    /// Force the next `capture()` to be a full keyframe of the active monitor.
    fn request_keyframe(&mut self);

    /// Capture once: dirty (or full) tiles, plus any cursor/geometry updates.
    /// Non-blocking-ish: it waits only briefly for a frame and returns an empty
    /// `CaptureFrame` on timeout, so the loop stays responsive to input.
    fn capture(&mut self) -> CaptureFrame;

    /// Inject one validated input event (control mode, live session only).
    fn inject(&mut self, ev: &InputEvent);

    /// Release every key the backend believes is held (pause/detach/end, §4.2).
    fn release_all_keys(&mut self);

    /// Re-attach the capture/input thread to the current input desktop if it
    /// changed (UAC/secure desktop/lock, §6.1). Owns no window, per §6.1.
    fn follow_input_desktop(&mut self);

    /// Show the local consent prompt (§7, `ask_first`) and block until the person
    /// answers or it times out (60 s = denied). `control` selects the
    /// "see and control" vs "see" wording; `operator` is untrusted display text.
    /// Runs on the banner UI thread. Ctrl+Alt+Del itself is handled by the agent
    /// service, not here (§6.4): the session emits a service-request frame.
    fn request_consent(&mut self, control: bool, operator: Option<&str>) -> Consent;

    /// The current input desktop + sign-in state (§4.1), for the `desktop` frame
    /// the session sends right after `hello`.
    fn desktop_state(&mut self) -> DesktopState;
}
