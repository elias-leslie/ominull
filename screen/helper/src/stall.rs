//! DXGI stall detection (`REMOTE_SCREEN.md` §6.2).
//!
//! On some virtual GPUs (QEMU's "Microsoft Basic Render Driver", headless hosts)
//! `IDXGIOutputDuplication::DuplicateOutput` *succeeds* but `AcquireNextFrame`
//! never delivers a frame — so the GDI fallback (which only triggers when
//! duplication fails to initialize) is never reached, and the viewer gets the
//! monitor list but no image at all.
//!
//! This is the pure decision logic that notices that case and bridges/switches
//! to GDI, with no Win32 in it so it is unit-tested on the host. Time is passed
//! in as a millisecond count (monotonic since the current duplication
//! generation started), so tests feed it directly.
//!
//! Lifecycle per duplication generation (session start, or a reinit after a
//! desktop switch / mode change / `ACCESS_LOST`):
//!   * `t < bridge_ms`           : try DXGI; it may still wake up.
//!   * `bridge_ms <= t < switch_ms`: still try DXGI, but serve the keyframe via
//!     GDI so the viewer gets an initial image at ~1 s (`GdiBridge`).
//!   * `t >= switch_ms`          : DXGI has produced nothing; switch to GDI for
//!     this output and stop probing DXGI until the next reinit (`Gdi`).
//! Once DXGI delivers any frame in a generation, it owns the generation
//! (`Dxgi`) — later `WAIT_TIMEOUT`s on a static desktop are normal and never
//! re-trigger a bridge or switch.

/// Which path `capture()` should take this tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapturePath {
    /// Use DXGI duplication (it is working, or we are still giving it a chance).
    Dxgi,
    /// Still probe DXGI, but if it yields no frame, serve this frame via GDI so
    /// the viewer is not left blank while DXGI is stalled at session start.
    GdiBridge,
    /// DXGI delivered nothing within the switch window (or failed structurally):
    /// use GDI for this output and stop probing DXGI until a reinit.
    Gdi,
}

/// Why the path switched to GDI, for the diagnostics log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchReason {
    /// `DuplicateOutput`/device creation failed structurally (hybrid-GPU, etc.).
    InitFailed,
    /// Duplication initialized but produced no frame within the switch window.
    NoFrames,
}

/// Default bridge/switch thresholds (ms) — ~1 s to a first image, ~2.5 s before
/// giving up on DXGI for the generation.
pub const DEFAULT_BRIDGE_MS: u64 = 1_000;
pub const DEFAULT_SWITCH_MS: u64 = 2_500;

#[derive(Debug)]
pub struct DxgiStall {
    bridge_ms: u64,
    switch_ms: u64,
    /// Start of the current duplication generation.
    init_ms: u64,
    /// DXGI delivered at least one frame this generation.
    got_frame: bool,
    /// Switched to GDI for this generation.
    switched: bool,
    /// Set when `switched` flips, cleared by `take_switch_reason`.
    pending_switch_reason: Option<SwitchReason>,
}

impl DxgiStall {
    pub fn new(bridge_ms: u64, switch_ms: u64) -> Self {
        DxgiStall {
            bridge_ms,
            switch_ms,
            init_ms: 0,
            got_frame: false,
            switched: false,
            pending_switch_reason: None,
        }
    }

    /// Start a fresh duplication generation at `now_ms` (session start, desktop
    /// switch, monitor change, or `ACCESS_LOST`). DXGI gets a clean chance again.
    pub fn reinit(&mut self, now_ms: u64) {
        self.init_ms = now_ms;
        self.got_frame = false;
        self.switched = false;
        // A pending reason not yet logged is dropped on reinit; the new
        // generation will raise its own if it stalls again.
        self.pending_switch_reason = None;
    }

    /// DXGI delivered a frame this generation; it now owns the generation.
    pub fn on_frame(&mut self) {
        self.got_frame = true;
    }

    /// Force GDI for this generation because duplication failed to initialize.
    pub fn force_gdi(&mut self) {
        if !self.switched {
            self.switched = true;
            self.pending_switch_reason = Some(SwitchReason::InitFailed);
        }
    }

    /// Decide the path for this tick and advance the sticky switch state.
    pub fn decide(&mut self, now_ms: u64) -> CapturePath {
        if self.got_frame {
            return CapturePath::Dxgi;
        }
        if self.switched {
            return CapturePath::Gdi;
        }
        let elapsed = now_ms.saturating_sub(self.init_ms);
        if elapsed >= self.switch_ms {
            self.switched = true;
            self.pending_switch_reason = Some(SwitchReason::NoFrames);
            return CapturePath::Gdi;
        }
        if elapsed >= self.bridge_ms {
            return CapturePath::GdiBridge;
        }
        CapturePath::Dxgi
    }

    /// Take the one-shot reason the path switched to GDI, for logging.
    pub fn take_switch_reason(&mut self) -> Option<SwitchReason> {
        self.pending_switch_reason.take()
    }

    #[cfg(test)]
    fn switched(&self) -> bool {
        self.switched
    }
}

impl Default for DxgiStall {
    fn default() -> Self {
        DxgiStall::new(DEFAULT_BRIDGE_MS, DEFAULT_SWITCH_MS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> DxgiStall {
        let mut s = DxgiStall::new(1_000, 2_500);
        s.reinit(0);
        s
    }

    #[test]
    fn dxgi_used_before_bridge_window() {
        let mut s = fresh();
        assert_eq!(s.decide(0), CapturePath::Dxgi);
        assert_eq!(s.decide(999), CapturePath::Dxgi);
    }

    #[test]
    fn bridges_then_switches_when_dxgi_never_delivers() {
        let mut s = fresh();
        assert_eq!(s.decide(1_000), CapturePath::GdiBridge);
        assert_eq!(s.decide(2_499), CapturePath::GdiBridge);
        assert_eq!(s.take_switch_reason(), None, "no switch yet while only bridging");
        assert_eq!(s.decide(2_500), CapturePath::Gdi);
        assert_eq!(s.take_switch_reason(), Some(SwitchReason::NoFrames));
        assert_eq!(s.take_switch_reason(), None, "reason is one-shot");
        // Sticky: stays GDI thereafter until a reinit.
        assert_eq!(s.decide(10_000), CapturePath::Gdi);
        assert!(s.switched());
    }

    #[test]
    fn first_dxgi_frame_owns_the_generation() {
        let mut s = fresh();
        // A frame arrives during the bridge window.
        assert_eq!(s.decide(1_200), CapturePath::GdiBridge);
        s.on_frame();
        // Even well past the switch window, a static desktop (timeouts) stays DXGI.
        assert_eq!(s.decide(9_000), CapturePath::Dxgi);
        assert_eq!(s.take_switch_reason(), None);
        assert!(!s.switched());
    }

    #[test]
    fn reinit_gives_dxgi_a_fresh_chance() {
        let mut s = fresh();
        assert_eq!(s.decide(3_000), CapturePath::Gdi); // switched
        assert!(s.switched());
        s.take_switch_reason();
        // A desktop switch / mode change at t=5000 restarts the generation.
        s.reinit(5_000);
        assert!(!s.switched());
        assert_eq!(s.decide(5_000), CapturePath::Dxgi);
        assert_eq!(s.decide(5_999), CapturePath::Dxgi);
        assert_eq!(s.decide(6_000), CapturePath::GdiBridge);
    }

    #[test]
    fn force_gdi_switches_with_init_reason() {
        let mut s = fresh();
        s.force_gdi();
        assert_eq!(s.decide(0), CapturePath::Gdi);
        assert_eq!(s.take_switch_reason(), Some(SwitchReason::InitFailed));
        // Idempotent: a second force does not re-raise.
        s.force_gdi();
        assert_eq!(s.take_switch_reason(), None);
    }

    #[test]
    fn reinit_clears_unlogged_switch_reason() {
        let mut s = fresh();
        assert_eq!(s.decide(3_000), CapturePath::Gdi);
        s.reinit(4_000); // reason never taken
        assert_eq!(s.take_switch_reason(), None);
    }
}
