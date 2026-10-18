//! The session loop (`REMOTE_SCREEN.md` §4), generic over [`ScreenBackend`] so
//! it is pure and host-testable with a mock backend. It owns the protocol state
//! machine — mode, active monitor, quality, pause, the frame_end/ack flow-control
//! window — and knows nothing about Win32.
//!
//! One-way dependency: wire schema + backend trait in, frames out. The real
//! capture pacing (the 10 fps timer) lives in `main.rs`, which calls
//! [`Session::tick`] when a frame is due; the loop here stays timer-free so the
//! tests are deterministic.

use std::io::{self, Write};

use screen_wire::framing::{write_frame, FrameKind, SERVICE_OP_SAS};
use screen_wire::input::{validate, InputEvent};
use screen_wire::proto::{encode_cursor_shape, encode_tile_message, InMsg, MonitorInfo, OutMsg};

use crate::backend::{Consent, DesktopState, Monitor, ScreenBackend};

/// Frames the agent may have outstanding without an `ack` before it stops
/// sending new ones (§4.3, v1 = 2). Bounds latency on a slow viewer.
pub const MAX_UNACKED: u64 = 2;

/// fps / quality caps (§4.3).
pub const FPS_CAP: u32 = 10;
pub const JPEG_Q_MIN: u8 = 30;
pub const JPEG_Q_MAX: u8 = 85;
pub const JPEG_Q_DEFAULT: u8 = 60;

/// Grant mode (§3). View drops all input even if one slips through the hub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Control,
    View,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "control" => Some(Mode::Control),
            "view" => Some(Mode::View),
            _ => None,
        }
    }
}

/// What the loop should do after handling a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Stop,
}

pub struct Session<B: ScreenBackend> {
    backend: B,
    mode: Mode,
    monitors: Vec<Monitor>,
    active: u32,
    fps: u32,
    jpeg_q: u8,
    paused: bool,
    /// next tile sequence number (§4.1 tile header `seq`).
    seq: u32,
    /// next frame number (§4.1 `frame_end.frame`, what `ack` references).
    frame_no: u64,
    /// frames sent but not yet acked (flow control, §4.3).
    unacked: u64,
}

impl<B: ScreenBackend> Session<B> {
    pub fn new(mut backend: B, mode: Mode) -> Self {
        let monitors = backend.monitors();
        backend.set_quality(JPEG_Q_DEFAULT);
        Session {
            backend,
            mode,
            monitors,
            active: 0,
            fps: FPS_CAP,
            jpeg_q: JPEG_Q_DEFAULT,
            paused: false,
            seq: 0,
            frame_no: 0,
            unacked: 0,
        }
    }

    pub fn fps(&self) -> u32 {
        self.fps.clamp(1, FPS_CAP)
    }

    fn monitor_count(&self) -> u32 {
        self.monitors.len() as u32
    }

    fn monitor_infos(&self) -> Vec<MonitorInfo> {
        self.monitors
            .iter()
            .map(|m| MonitorInfo { id: m.id, w: m.w, h: m.h, x: m.x, y: m.y, primary: m.primary })
            .collect()
    }

    /// First messages (§4.1): `hello`, then the current `desktop` state.
    pub fn send_hello<W: Write>(&mut self, out: &mut W) -> io::Result<()> {
        let hello = OutMsg::Hello { monitors: self.monitor_infos(), active: self.active };
        send_json(out, &hello)?;
        let DesktopState { name, signed_in } = self.backend.desktop_state();
        send_json(out, &OutMsg::Desktop { name, signed_in })
    }

    /// Decide whether the session may go active (§7, "ask the person first").
    /// With `ask_first` off, always yes (the banner still shows). With it on: if
    /// nobody is signed in or the screen is locked there is nobody to ask, so the
    /// session is declined with `bye`/`nobody_signed_in` unless the owner's
    /// approval was unattended; otherwise a local consent prompt is shown (60 s
    /// with no answer = denied). Returns false after writing the `bye` when the
    /// session must not proceed — the caller then shuts down without capturing.
    pub fn authorize<W: Write>(
        &mut self,
        out: &mut W,
        ask_first: bool,
        unattended: bool,
        operator: Option<&str>,
    ) -> io::Result<bool> {
        if !ask_first {
            return Ok(true);
        }
        let ds = self.backend.desktop_state();
        let present = ds.signed_in && ds.name == "user";
        if !present {
            if unattended {
                // The owner approved an unattended session; there is nobody to ask.
                return Ok(true);
            }
            self.backend.release_all_keys();
            send_json(out, &OutMsg::Bye { reason: "nobody_signed_in".into() })?;
            return Ok(false);
        }
        match self.backend.request_consent(self.mode == Mode::Control, operator) {
            Consent::Allowed => Ok(true),
            Consent::Denied => {
                self.backend.release_all_keys();
                send_json(out, &OutMsg::Bye { reason: "consent_declined".into() })?;
                Ok(false)
            }
        }
    }

    /// Handle one decoded operator/hub message. Returns whether the loop goes on.
    ///
    /// `close` means a real session end: the hub relays `close` to the agent
    /// only on a true end, and a detach arrives as `pause` (§4.1 note,
    /// 2026-10-17). So the helper stops on `close` and merely pauses on `pause`.
    pub fn on_message<W: Write>(&mut self, msg: InMsg, out: &mut W) -> io::Result<Flow> {
        match msg {
            InMsg::Close => return Ok(Flow::Stop),
            InMsg::Pause => {
                // Stop capture and release every key so none is left stuck down
                // on the endpoint while detached (§4.2, §4.3).
                self.paused = true;
                self.backend.release_all_keys();
            }
            InMsg::Resume => {
                // A fresh keyframe of the active monitor promptly, so an
                // attach/detach burst (ominullctl screen shot/click) repaints at
                // once (§4.1 note).
                self.paused = false;
                self.backend.request_keyframe();
            }
            InMsg::Ack { frame, .. } => {
                // Clear the window up to the acked frame.
                if frame >= self.frame_no.saturating_sub(self.unacked) {
                    self.unacked = self.unacked.saturating_sub(1);
                }
            }
            InMsg::SetMonitor { monitor } => {
                if self.backend.set_active_monitor(monitor) {
                    self.active = monitor;
                    self.backend.request_keyframe();
                }
            }
            InMsg::Quality { fps, jpeg_q } => {
                if let Some(f) = fps {
                    self.fps = f.clamp(1, FPS_CAP);
                }
                if let Some(q) = jpeg_q {
                    self.jpeg_q = (q as u8).clamp(JPEG_Q_MIN, JPEG_Q_MAX);
                    self.backend.set_quality(self.jpeg_q);
                }
            }
            InMsg::Input(raw) => {
                // View mode never injects; the grant says view (§7). Paused
                // sessions never inject either (input only while live, §7).
                if self.mode == Mode::Control && !self.paused {
                    if let Some(ev) = validate(&raw, self.monitor_count()) {
                        if let InputEvent::Sas = ev {
                            // SAS can only be issued by the agent service (§6.4).
                            // Ask it with a service-request frame; the service
                            // reads the policy and calls SendSAS, or sends
                            // sas_unavailable toward the operator itself. The
                            // helper never calls SendSAS and never reads the policy.
                            write_frame(out, FrameKind::Service, &[SERVICE_OP_SAS])?;
                        } else {
                            self.backend.inject(&ev);
                        }
                    }
                    // A malformed/out-of-bounds event is simply dropped.
                }
            }
            InMsg::Unknown => {}
        }
        Ok(Flow::Continue)
    }

    /// Produce one captured frame's worth of output, if allowed. Called by the
    /// real loop at the fps cadence. Honors pause and the ack window.
    pub fn tick<W: Write>(&mut self, out: &mut W) -> io::Result<()> {
        self.backend.follow_input_desktop();
        if self.paused {
            return Ok(());
        }
        // Flow control: do not outrun the viewer (§4.3).
        if self.unacked >= MAX_UNACKED {
            // Still surface a desktop switch even while flow-control-stalled, so
            // the viewer/banner state is never stale.
            let cap = self.backend.capture();
            self.emit_side_channel(out, &cap)?;
            return Ok(());
        }

        let cap = self.backend.capture();
        self.emit_side_channel(out, &cap)?;

        if cap.tiles.is_empty() {
            return Ok(());
        }
        let frame = self.frame_no;
        let mut count = 0u32;
        for t in &cap.tiles {
            let seq = self.seq;
            self.seq = self.seq.wrapping_add(1);
            let msg = encode_tile_message(self.active as u8, t.keyframe, t.x, t.y, t.w, t.h, seq, &t.jpeg);
            write_frame(out, FrameKind::Binary, &msg)?;
            count += 1;
        }
        send_json(out, &OutMsg::FrameEnd { monitor: self.active, frame, tiles: count })?;
        self.frame_no += 1;
        self.unacked += 1;
        Ok(())
    }

    /// Emit the non-tile parts of a capture: geometry change, desktop switch,
    /// cursor shape, cursor position.
    fn emit_side_channel<W: Write>(&mut self, out: &mut W, cap: &crate::backend::CaptureFrame) -> io::Result<()> {
        if let Some(mons) = &cap.geometry_change {
            self.monitors = mons.clone();
            if self.active >= self.monitor_count() {
                self.active = 0;
            }
            send_json(out, &OutMsg::Resized { monitors: self.monitor_infos(), active: self.active })?;
        }
        if let Some(ds) = &cap.desktop_change {
            send_json(out, &OutMsg::Desktop { name: ds.name.clone(), signed_in: ds.signed_in })?;
        }
        if let Some(cs) = &cap.cursor_shape {
            let msg = encode_cursor_shape(cs.w, cs.h, cs.hotspot_x, cs.hotspot_y, cs.format, &cs.pixels);
            write_frame(out, FrameKind::Binary, &msg)?;
        }
        if let Some(cp) = &cap.cursor_pos {
            send_json(out, &OutMsg::CursorPos { x: cp.x, y: cp.y, visible: cp.visible })?;
        }
        Ok(())
    }

    /// Release keys and say goodbye (§4.2 release-all-keys, §4.1 bye).
    pub fn shutdown<W: Write>(&mut self, out: &mut W, reason: &str) -> io::Result<()> {
        self.backend.release_all_keys();
        send_json(out, &OutMsg::Bye { reason: reason.into() })
    }
}

fn send_json<W: Write>(out: &mut W, msg: &OutMsg) -> io::Result<()> {
    write_frame(out, FrameKind::Text, msg.to_json().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{
        CaptureFrame, Consent, CursorPos, Monitor, ScreenBackend, Tile,
    };
    use screen_wire::framing::{read_frame, FrameKind, SERVICE_OP_SAS};
    use screen_wire::input::InputEvent;
    use screen_wire::proto::{decode_tile_message, parse_out, OutMsg};
    use std::io::Cursor as IoCursor;

    #[derive(Default)]
    struct MockBackend {
        injects: Vec<InputEvent>,
        released: u32,
        keyframe_requests: u32,
        active: u32,
        quality: u8,
        next_capture: CaptureFrame,
        /// What `request_consent` returns (default Allowed) and how often it ran.
        consent: Option<Consent>,
        consent_calls: u32,
        /// Overrides for `desktop_state` (default "user" / signed in).
        ds_name: Option<String>,
        ds_signed_in: Option<bool>,
    }

    fn two_monitors() -> Vec<Monitor> {
        vec![
            Monitor { id: 0, x: 0, y: 0, w: 1920, h: 1080, primary: true },
            Monitor { id: 1, x: 1920, y: 0, w: 1280, h: 1024, primary: false },
        ]
    }

    impl ScreenBackend for MockBackend {
        fn monitors(&self) -> Vec<Monitor> {
            two_monitors()
        }
        fn set_active_monitor(&mut self, index: u32) -> bool {
            if index < 2 {
                self.active = index;
                true
            } else {
                false
            }
        }
        fn set_quality(&mut self, jpeg_q: u8) {
            self.quality = jpeg_q;
        }
        fn request_keyframe(&mut self) {
            self.keyframe_requests += 1;
        }
        fn capture(&mut self) -> CaptureFrame {
            std::mem::take(&mut self.next_capture)
        }
        fn inject(&mut self, ev: &InputEvent) {
            self.injects.push(ev.clone());
        }
        fn release_all_keys(&mut self) {
            self.released += 1;
        }
        fn follow_input_desktop(&mut self) {}
        fn request_consent(&mut self, _control: bool, _operator: Option<&str>) -> Consent {
            self.consent_calls += 1;
            self.consent.unwrap_or(Consent::Allowed)
        }
        fn desktop_state(&mut self) -> DesktopState {
            DesktopState {
                name: self.ds_name.clone().unwrap_or_else(|| "user".into()),
                signed_in: self.ds_signed_in.unwrap_or(true),
            }
        }
    }

    fn read_all(buf: Vec<u8>) -> Vec<(FrameKind, Vec<u8>)> {
        let mut c = IoCursor::new(buf);
        let mut out = Vec::new();
        while let Some(f) = read_frame(&mut c).unwrap() {
            out.push(f);
        }
        out
    }

    fn input(json: &str) -> InMsg {
        screen_wire::proto::parse_in(json.as_bytes()).unwrap()
    }

    #[test]
    fn hello_then_desktop() {
        let mut s = Session::new(MockBackend::default(), Mode::Control);
        let mut out = Vec::new();
        s.send_hello(&mut out).unwrap();
        let frames = read_all(out);
        assert_eq!(frames.len(), 2);
        assert_eq!(parse_out(&frames[0].1).unwrap(), OutMsg::Hello { monitors: s.monitor_infos(), active: 0 });
        assert!(matches!(parse_out(&frames[1].1).unwrap(), OutMsg::Desktop { .. }));
    }

    #[test]
    fn control_injects_valid_input() {
        let mut s = Session::new(MockBackend::default(), Mode::Control);
        let mut out = Vec::new();
        s.on_message(input(r#"{"type":"input","ev":"mouse","x":100,"y":100,"monitor":0}"#), &mut out).unwrap();
        assert_eq!(s.backend.injects.len(), 1);
    }

    #[test]
    fn view_mode_never_injects() {
        let mut s = Session::new(MockBackend::default(), Mode::View);
        let mut out = Vec::new();
        s.on_message(input(r#"{"type":"input","ev":"mouse","x":100,"y":100,"monitor":0}"#), &mut out).unwrap();
        assert_eq!(s.backend.injects.len(), 0, "view-mode input is dropped at the agent too");
    }

    #[test]
    fn paused_never_injects_and_releases_keys() {
        let mut s = Session::new(MockBackend::default(), Mode::Control);
        let mut out = Vec::new();
        s.on_message(InMsg::Pause, &mut out).unwrap();
        assert_eq!(s.backend.released, 1);
        s.on_message(input(r#"{"type":"input","ev":"mouse","x":1,"y":1,"monitor":0}"#), &mut out).unwrap();
        assert_eq!(s.backend.injects.len(), 0);
    }

    #[test]
    fn malformed_input_dropped_not_fatal() {
        let mut s = Session::new(MockBackend::default(), Mode::Control);
        let mut out = Vec::new();
        let flow = s
            .on_message(input(r#"{"type":"input","ev":"mouse","x":999999,"y":1,"monitor":0}"#), &mut out)
            .unwrap();
        assert_eq!(flow, Flow::Continue);
        assert_eq!(s.backend.injects.len(), 0);
    }

    #[test]
    fn close_stops_pause_does_not() {
        let mut s = Session::new(MockBackend::default(), Mode::Control);
        let mut out = Vec::new();
        assert_eq!(s.on_message(InMsg::Pause, &mut out).unwrap(), Flow::Continue);
        assert_eq!(s.on_message(InMsg::Close, &mut out).unwrap(), Flow::Stop);
    }

    #[test]
    fn resume_requests_keyframe() {
        let mut s = Session::new(MockBackend::default(), Mode::Control);
        let mut out = Vec::new();
        s.on_message(InMsg::Pause, &mut out).unwrap();
        let before = s.backend.keyframe_requests;
        s.on_message(InMsg::Resume, &mut out).unwrap();
        assert_eq!(s.backend.keyframe_requests, before + 1);
        assert!(!s.paused);
    }

    #[test]
    fn set_monitor_switches_and_keyframes() {
        let mut s = Session::new(MockBackend::default(), Mode::Control);
        let mut out = Vec::new();
        s.on_message(InMsg::SetMonitor { monitor: 1 }, &mut out).unwrap();
        assert_eq!(s.active, 1);
        assert_eq!(s.backend.keyframe_requests, 1);
        // Out-of-range index is ignored.
        s.on_message(InMsg::SetMonitor { monitor: 9 }, &mut out).unwrap();
        assert_eq!(s.active, 1);
    }

    #[test]
    fn quality_clamped_to_caps() {
        let mut s = Session::new(MockBackend::default(), Mode::Control);
        let mut out = Vec::new();
        s.on_message(InMsg::Quality { fps: Some(999), jpeg_q: Some(200) }, &mut out).unwrap();
        assert_eq!(s.fps(), FPS_CAP);
        assert_eq!(s.jpeg_q, JPEG_Q_MAX);
        assert_eq!(s.backend.quality, JPEG_Q_MAX);
        s.on_message(InMsg::Quality { fps: Some(0), jpeg_q: Some(1) }, &mut out).unwrap();
        assert_eq!(s.fps(), 1);
        assert_eq!(s.jpeg_q, JPEG_Q_MIN);
    }

    #[test]
    fn tick_emits_tiles_then_frame_end_and_tracks_unacked() {
        let mut s = Session::new(MockBackend::default(), Mode::Control);
        s.backend.next_capture = CaptureFrame {
            tiles: vec![
                Tile { x: 0, y: 0, w: 256, h: 256, keyframe: true, jpeg: vec![1, 2, 3] },
                Tile { x: 256, y: 0, w: 256, h: 256, keyframe: true, jpeg: vec![4, 5] },
            ],
            cursor_pos: Some(CursorPos { x: 10, y: 20, visible: true }),
            ..Default::default()
        };
        let mut out = Vec::new();
        s.tick(&mut out).unwrap();
        let frames = read_all(out);
        // cursor_pos (text) + 2 tiles (binary) + frame_end (text)
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[1].0, FrameKind::Binary);
        let (hdr, body) = decode_tile_message(&frames[1].1).unwrap();
        assert!(hdr.keyframe && hdr.w == 256 && body == [1, 2, 3]);
        assert!(matches!(parse_out(&frames[3].1).unwrap(), OutMsg::FrameEnd { tiles: 2, frame: 0, .. }));
        assert_eq!(s.unacked, 1);
    }

    #[test]
    fn flow_control_stops_after_max_unacked() {
        let mut s = Session::new(MockBackend::default(), Mode::Control);
        let one_tile = || CaptureFrame {
            tiles: vec![Tile { x: 0, y: 0, w: 256, h: 256, keyframe: false, jpeg: vec![9] }],
            ..Default::default()
        };
        for _ in 0..(MAX_UNACKED + 3) {
            s.backend.next_capture = one_tile();
            let mut out = Vec::new();
            s.tick(&mut out).unwrap();
        }
        assert_eq!(s.unacked, MAX_UNACKED, "never sends more than the window without an ack");
        // An ack frees the window again.
        let mut out = Vec::new();
        s.on_message(InMsg::Ack { monitor: 0, frame: 0 }, &mut out).unwrap();
        assert_eq!(s.unacked, MAX_UNACKED - 1);
    }

    #[test]
    fn sas_emits_service_request_frame() {
        // The helper never calls SendSAS; it asks the agent service with a
        // kind=service / op=SAS frame (§6.4).
        let mut s = Session::new(MockBackend::default(), Mode::Control);
        let mut out = Vec::new();
        s.on_message(input(r#"{"type":"input","ev":"sas"}"#), &mut out).unwrap();
        let frames = read_all(out);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, FrameKind::Service);
        assert_eq!(frames[0].1, vec![SERVICE_OP_SAS]);
        assert!(s.backend.injects.is_empty());
    }

    #[test]
    fn view_mode_drops_sas() {
        let mut s = Session::new(MockBackend::default(), Mode::View);
        let mut out = Vec::new();
        s.on_message(input(r#"{"type":"input","ev":"sas"}"#), &mut out).unwrap();
        assert!(read_all(out).is_empty(), "view mode never issues SAS");
    }

    #[test]
    fn authorize_off_is_always_allowed_without_prompt() {
        let mut s = Session::new(MockBackend::default(), Mode::Control);
        let mut out = Vec::new();
        assert!(s.authorize(&mut out, false, false, None).unwrap());
        assert_eq!(s.backend.consent_calls, 0);
        assert!(read_all(out).is_empty());
    }

    #[test]
    fn authorize_prompts_and_allows() {
        let mut s = Session::new(MockBackend::default(), Mode::Control);
        let mut out = Vec::new();
        assert!(s.authorize(&mut out, true, false, Some("admin")).unwrap());
        assert_eq!(s.backend.consent_calls, 1);
    }

    #[test]
    fn authorize_denied_sends_bye() {
        let mut b = MockBackend::default();
        b.consent = Some(Consent::Denied);
        let mut s = Session::new(b, Mode::Control);
        let mut out = Vec::new();
        assert!(!s.authorize(&mut out, true, false, None).unwrap());
        let frames = read_all(out);
        assert!(matches!(parse_out(&frames[0].1).unwrap(), OutMsg::Bye { .. }));
    }

    #[test]
    fn authorize_nobody_signed_in_declines_unless_unattended() {
        // ask_first on, nobody signed in, not unattended -> bye nobody_signed_in.
        let mut b = MockBackend::default();
        b.ds_signed_in = Some(false);
        let mut s = Session::new(b, Mode::Control);
        let mut out = Vec::new();
        assert!(!s.authorize(&mut out, true, false, None).unwrap());
        assert_eq!(s.backend.consent_calls, 0, "nobody to ask");
        let frames = read_all(out);
        match parse_out(&frames[0].1).unwrap() {
            OutMsg::Bye { reason } => assert_eq!(reason, "nobody_signed_in"),
            _ => panic!("expected bye"),
        }

        // unattended -> proceeds without a prompt (owner approved it).
        let mut b2 = MockBackend::default();
        b2.ds_signed_in = Some(false);
        let mut s2 = Session::new(b2, Mode::Control);
        let mut out2 = Vec::new();
        assert!(s2.authorize(&mut out2, true, true, None).unwrap());
        assert_eq!(s2.backend.consent_calls, 0);
    }
}
